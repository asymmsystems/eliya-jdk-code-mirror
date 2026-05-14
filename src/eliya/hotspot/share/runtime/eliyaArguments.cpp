/*
 * Copyright (c) 2026, Asymm Systems (Pvt) Ltd. All rights reserved.
 *
 * Eliya — see asymm.systems/product/eliya
 *   ADR-00001: flag taxonomy
 *   ADR-00006: adaptive three-or-two-level diagnostic path layout
 *              with the replica-suppression rule
 *   ADR-00009: source file layout
 *   ADR-00010: data-driven design (Status table + activator pointers)
 *
 * Data-driven design throughout:
 *   - Path-component resolution: single generic resolve_chain() helper
 *     drives base / service / replica via a uniform env → sysprop →
 *     HOSTNAME → fallback chain.
 *   - Path building: single build_path() over a Category enum + name
 *     table; replica suppression handled via empty-segment trick (no
 *     double-branched format strings).
 *   - Profile activation: function pointers live on EliyaFlags::Entry
 *     rows in eliyaFlags.cpp; this file defines the activator bodies
 *     (e.g. apply_production_profile).
 */

#include "runtime/eliyaArguments.hpp"

#include "runtime/arguments.hpp"   // Arguments::PropertyList_get_value, system_properties
#include "runtime/globals.hpp"     // EliyaProfile, EliyaConflictCheck, FLAG_SET_ERGO, etc.
#include "memory/allocation.hpp"   // NEW_C_HEAP_ARRAY
#include "utilities/ostream.hpp"   // jio_snprintf

#include <cstring>
#include <cstdlib>

// ============================================================
// Diagnostic-path component resolution (ADR-00006)
// ============================================================

// Read an env var and treat empty string as not-set.
static const char* try_env(const char* var) {
  const char* v = ::getenv(var);
  return (v != nullptr && *v != '\0') ? v : nullptr;
}

// Read a system property and treat empty string as not-set.
static const char* try_sysprop(const char* key) {
  const char* v = Arguments::PropertyList_get_value(
      Arguments::system_properties(), key);
  return (v != nullptr && *v != '\0') ? v : nullptr;
}

// Per ADR-00006: chain env → sysprop → HOSTNAME → fallback, returning
// the first non-empty value. include_hostname is false for the base
// path (which doesn't fall back to HOSTNAME) and true for service and
// replica.
//
// Three resolvers (base, service, replica) collapse to one-liner calls
// against this generic helper after the ADR-00006 §2.2 amendment adds
// sysprop support to the base path (Commit 3 of ISSUE-00001 lands the
// sysprop step there; today the helper is invoked with the upstream
// sysprop key already filled in but the base-path call passes an
// empty key, falling through to the platform default).
static const char* resolve_chain(const char* env_var,
                                  const char* sysprop_key,
                                  bool include_hostname,
                                  const char* fallback) {
  const char* v;
  if ((v = try_env(env_var))) return v;
  if (sysprop_key != nullptr && (v = try_sysprop(sysprop_key))) return v;
  if (include_hostname && (v = try_env("HOSTNAME"))) return v;
  return fallback;
}

// Platform default base path. Separate function so the resolve_chain
// fallback parameter can be a simple string while the platform
// branching stays here.
static const char* platform_default_base_path() {
#if defined(__APPLE__)
  return "/usr/local/var/eliya";
#elif defined(__FreeBSD__) || defined(LINUX) || defined(__linux__)
  return "/var/log/eliya";
#else
  return "/var/log/eliya";
#endif
}

// Resolve the diagnostic base path.
// Per ADR-00006 §2.2 (amended): env → sysprop → platform default.
// Three steps in symmetry with service and replica resolution.
static const char* resolve_eliya_base_path() {
  return resolve_chain("ELIYA_DIAGNOSTIC_PATH",
                       "eliya.diagnostic.path",
                       /* include_hostname */ false,
                       platform_default_base_path());
}

// Resolve the service name. Order: env → sysprop → HOSTNAME → "default".
static const char* resolve_eliya_service_name() {
  return resolve_chain("ELIYA_SERVICE_NAME",
                       "eliya.service.name",
                       /* include_hostname */ true,
                       /* fallback */ "default");
}

// Resolve the replica name. Order: env → sysprop → HOSTNAME → nullptr.
// build_path()'s replica-suppression rule handles nullptr (and the
// service==replica byte-equality case).
static const char* resolve_eliya_replica_name() {
  return resolve_chain("ELIYA_REPLICA_NAME",
                       "eliya.replica.name",
                       /* include_hostname */ true,
                       /* fallback */ nullptr);
}

// ============================================================
// Diagnostic-path builder (ADR-00006 §2.1)
// ============================================================

namespace {

// Diagnostic categories. Adding a new category (Phase 1.5+ e.g.
// "profiling" for async-profiler integration) means appending a row
// here and an entry to CATEGORY_NAMES; no function bodies change.
enum class Category : size_t {
  HEAP_DUMPS = 0,
  GC,
  CRASH,
  NMT,
  JFR,
  _COUNT
};

// Indexed by Category enum; static_assert below guards against drift.
constexpr const char* CATEGORY_NAMES[] = {
  "heap-dumps",  // HEAP_DUMPS
  "gc",          // GC
  "crash",       // CRASH
  "nmt",         // NMT
  "jfr",         // JFR
};
static_assert(sizeof(CATEGORY_NAMES) / sizeof(CATEGORY_NAMES[0])
                  == static_cast<size_t>(Category::_COUNT),
              "CATEGORY_NAMES must have one entry per Category enum value");

inline const char* name_of(Category c) {
  return CATEGORY_NAMES[static_cast<size_t>(c)];
}

} // anonymous namespace

// Unified path builder. Per ADR-00006 §2.1, produces either a
// directory path (filename=nullptr) ending in trailing slash, or a
// file path with the given filename appended (no trailing slash).
//
// Replica suppression (ADR-00006 §2.3): when the resolved replica is
// nullptr or byte-equal to the service, the replica segment collapses
// to empty via the r_sep/r_val empty-segment trick — single snprintf
// produces either three-level or two-level path with no double slashes.
//
// Returned buffer is allocated from the C heap (mtArguments = NMT
// memory-tracking tag for argument-parsing memory; see memTag.hpp).
// Retained for the lifetime of the JVM via the flag's internal storage.
static char* build_path(Category cat, const char* filename = nullptr) {
  const char* base     = resolve_eliya_base_path();
  const char* service  = resolve_eliya_service_name();
  const char* replica  = resolve_eliya_replica_name();
  const char* category = name_of(cat);

  const bool include_replica =
      (replica != nullptr && strcmp(replica, service) != 0);
  const char* r_sep = include_replica ? "/"     : "";
  const char* r_val = include_replica ? replica : "";

  const char* file_suffix = (filename != nullptr) ? filename : "";
  const char* file_sep    = (filename != nullptr) ? ""       : "/";
  // file form: "base/service[/replica]/category/<filename>"  (no trailing slash)
  // dir form:  "base/service[/replica]/category/"             (trailing slash)

  // Size calculation: all segments + 3 separators ('/' before service,
  // before category, between category and filename-or-slash) + 1 byte
  // for '\0'. The replica separator (r_sep) and content (r_val) are
  // counted by their own strlen so the empty-suppression case produces
  // no extra bytes.
  const size_t needed = strlen(base) + 1                  // base + '/'
                      + strlen(service)
                      + strlen(r_sep) + strlen(r_val)     // /<replica> or ""
                      + 1                                  // '/' before category
                      + strlen(category)
                      + strlen(file_sep)                  // '/' for dir form, "" for file form
                      + strlen(file_suffix)
                      + 1;                                 // '\0' terminator

  char* path = NEW_C_HEAP_ARRAY(char, needed, mtArguments);
  jio_snprintf(path, needed, "%s/%s%s%s/%s%s%s",
               base, service, r_sep, r_val, category, file_sep, file_suffix);
  return path;
}

// ============================================================
// Production-profile activator
// ============================================================

// Phase 1 activator. Sets the production-readiness defaults when
// -XX:EliyaProfile=Production was specified, respecting existing user
// command-line settings (FLAG_IS_CMDLINE silent-override per ADR-00001
// §2.5 tier 1).
//
// Two capabilities cannot use FLAG_SET_ERGO and are deferred to Phase 1.5:
//   - StartFlightRecording is parsed by JfrOptionSet, not as a product flag.
//   - -Xlog:gc* unified logging is configured via LogConfiguration.
// Both require dedicated integration hooks; tracked as TODO(Phase1.5)
// markers below.
void EliyaArguments::apply_production_profile() {
  // JFR continuous recording — TODO(Phase1.5) JfrOptionSet hook.
  // Intended spec when the integration lands:
  //   disk=true,maxage=24h,maxsize=250m,settings=default,dumponexit=true,
  //   filename=${build_path(JFR)}/recording.jfr

  if (!FLAG_IS_CMDLINE(HeapDumpOnOutOfMemoryError)) {
    FLAG_SET_ERGO(HeapDumpOnOutOfMemoryError, true);
  }
  if (!FLAG_IS_CMDLINE(HeapDumpPath)) {
    FLAG_SET_ERGO(HeapDumpPath, build_path(Category::HEAP_DUMPS));
  }

  if (!FLAG_IS_CMDLINE(NativeMemoryTracking)) {
    FLAG_SET_ERGO(NativeMemoryTracking, "summary");
  }

  // GC logging — TODO(Phase1.5) LogConfiguration hook.
  // Intended spec when the integration lands:
  //   gc*:file=${build_path(GC)}gc-%t-%p.log:time,uptime,level,tags:
  //       filecount=5,filesize=20m

  if (!FLAG_IS_CMDLINE(ErrorFile)) {
    FLAG_SET_ERGO(ErrorFile, build_path(Category::CRASH, "hs_err_pid%p.log"));
  }

  // UseContainerSupport defaults to true upstream; reinforced here for
  // auditability (no-op when already true).
  if (!FLAG_IS_CMDLINE(UseContainerSupport) && !UseContainerSupport) {
    FLAG_SET_ERGO(UseContainerSupport, true);
  }

  if (!FLAG_IS_CMDLINE(UnlockDiagnosticVMOptions)) {
    FLAG_SET_ERGO(UnlockDiagnosticVMOptions, true);
  }
}

// ============================================================
// Three-tier conflict detection (ADR-00001 §2.5)
// ============================================================

// Tier 1 (silent override) is realised structurally via the
// FLAG_IS_CMDLINE guards in apply_production_profile(). Tiers 2
// (warning) and 3 (fatal) wire in alongside Phase 2 capability flags;
// today this function is the established integration point.
void EliyaArguments::check_flag_consistency() {
  if (EliyaProfile == nullptr || strcmp(EliyaProfile, "None") == 0) {
    return;
  }
  // Phase 2+ tiers wire in here.
}

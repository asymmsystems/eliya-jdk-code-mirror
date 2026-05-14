/*
 * Copyright (c) 2026, Asymm Systems (Pvt) Ltd. All rights reserved.
 *
 * Eliya — see asymm.systems/product/eliya
 *   ADR-00001: flag taxonomy (EliyaProfile + EliyaConflictCheck)
 *   ADR-00006: adaptive three-or-two-level diagnostic path layout
 *              with the replica-suppression rule
 *   ADR-00009: source file layout (this file is the Eliya counterpart
 *              to src/hotspot/share/runtime/arguments.cpp)
 */

#include "runtime/eliyaArguments.hpp"

#include "runtime/arguments.hpp"   // Arguments::PropertyList_get_value, system_properties
#include "runtime/globals.hpp"     // EliyaProfile, EliyaConflictCheck, FLAG_SET_ERGO, etc.
#include "memory/allocation.hpp"   // NEW_C_HEAP_ARRAY
#include "utilities/ostream.hpp"   // jio_snprintf

#include <cstring>
#include <cstdlib>

// ============================================================
// Path-component resolvers
// (Currently free file-static helpers — Commit 2 of ISSUE-00001
//  collapses these to a single generic resolve_chain per
//  ADR-00006 §2.2 after the sysprop step is added in Commit 3.)
// ============================================================

// Resolve the diagnostic base path.
// Order: ELIYA_DIAGNOSTIC_PATH env var -> platform default.
static const char* resolve_eliya_base_path() {
  const char* val = ::getenv("ELIYA_DIAGNOSTIC_PATH");
  if (val != nullptr && *val != '\0') {
    return val;
  }
#if defined(__APPLE__)
  return "/usr/local/var/eliya";
#elif defined(__FreeBSD__) || defined(LINUX) || defined(__linux__)
  return "/var/log/eliya";
#else
  return "/var/log/eliya";
#endif
}

// Resolve the service name for diagnostic path construction.
// Order: ELIYA_SERVICE_NAME -> -Deliya.service.name -> HOSTNAME -> "default".
// Framework config files (application.yml etc.) are intentionally NOT consulted;
// operators using Spring Boot / Quarkus / etc. set the env var or sysprop from
// the same shell variable that drives their framework app name.
static const char* resolve_eliya_service_name() {
  const char* val = ::getenv("ELIYA_SERVICE_NAME");
  if (val != nullptr && *val != '\0') {
    return val;
  }
  val = Arguments::PropertyList_get_value(
      Arguments::system_properties(), "eliya.service.name");
  if (val != nullptr && *val != '\0') {
    return val;
  }
  val = ::getenv("HOSTNAME");
  if (val != nullptr && *val != '\0') {
    return val;
  }
  return "default";
}

// Resolve the replica name. Order: ELIYA_REPLICA_NAME ->
// -Deliya.replica.name -> HOSTNAME -> nullptr (suppress level).
// build_eliya_path() collapses the replica level to a two-level path
// whenever replica == service (covers the bare-metal single-JVM case
// where service itself falls through to HOSTNAME).
static const char* resolve_eliya_replica_name() {
  const char* val = ::getenv("ELIYA_REPLICA_NAME");
  if (val != nullptr && *val != '\0') {
    return val;
  }
  val = Arguments::PropertyList_get_value(
      Arguments::system_properties(), "eliya.replica.name");
  if (val != nullptr && *val != '\0') {
    return val;
  }
  val = ::getenv("HOSTNAME");
  if (val != nullptr && *val != '\0') {
    return val;
  }
  return nullptr;
}

// ============================================================
// Path builders
// (Currently two near-identical functions — Commit 2 of ISSUE-00001
//  unifies them into a single builder over a Category enum + table.)
// ============================================================

// Construct an Eliya diagnostic directory path for the given category.
// Three-level:  ${base}/${service}/${replica}/${category}/
// Two-level:    ${base}/${service}/${category}/        (when replica null or == service)
// Returned buffer is allocated from the C heap (mtArguments = NMT
// memory-tracking tag for argument-parsing memory; see memTag.hpp) and
// retained for the lifetime of the JVM via the flag's internal storage.
static char* build_eliya_path(const char* category) {
  const char* base    = resolve_eliya_base_path();
  const char* service = resolve_eliya_service_name();
  const char* replica = resolve_eliya_replica_name();
  bool include_replica = (replica != nullptr && strcmp(replica, service) != 0);

  size_t needed;
  char*  path;
  if (include_replica) {
    needed = strlen(base) + strlen(service) + strlen(replica) +
             strlen(category) + 5;
    path = NEW_C_HEAP_ARRAY(char, needed, mtArguments);
    jio_snprintf(path, needed, "%s/%s/%s/%s/",
                 base, service, replica, category);
  } else {
    needed = strlen(base) + strlen(service) + strlen(category) + 4;
    path = NEW_C_HEAP_ARRAY(char, needed, mtArguments);
    jio_snprintf(path, needed, "%s/%s/%s/",
                 base, service, category);
  }
  return path;
}

// Construct the ErrorFile path. Same three-/two-level logic but produces
// a file template (with %p for PID) rather than a directory.
static char* build_eliya_error_file_path() {
  const char* base     = resolve_eliya_base_path();
  const char* service  = resolve_eliya_service_name();
  const char* replica  = resolve_eliya_replica_name();
  const char* filename = "hs_err_pid%p.log";
  bool include_replica = (replica != nullptr && strcmp(replica, service) != 0);

  size_t needed;
  char*  path;
  if (include_replica) {
    needed = strlen(base) + strlen(service) + strlen(replica) +
             strlen("crash") + strlen(filename) + 6;
    path = NEW_C_HEAP_ARRAY(char, needed, mtArguments);
    jio_snprintf(path, needed, "%s/%s/%s/crash/%s",
                 base, service, replica, filename);
  } else {
    needed = strlen(base) + strlen(service) +
             strlen("crash") + strlen(filename) + 5;
    path = NEW_C_HEAP_ARRAY(char, needed, mtArguments);
    jio_snprintf(path, needed, "%s/%s/crash/%s",
                 base, service, filename);
  }
  return path;
}

// ============================================================
// Profile activation
// ============================================================

// Phase 1 activator. Sets the production-readiness defaults when
// -XX:EliyaProfile=Production was specified, respecting existing user
// command-line settings (FLAG_IS_CMDLINE silent-override per ADR-00001
// §2.5 tier 1).
//
// Two capabilities cannot use FLAG_SET_ERGO and are deferred:
//   - StartFlightRecording is parsed by JfrOptionSet, not as a product flag.
//   - -Xlog:gc* unified logging is configured via LogConfiguration, not via
//     ordinary product flags.
// Both require dedicated integration hooks (jfrOptionSet.cpp and
// LogConfiguration::parse_log_arguments() respectively); they are marked
// as TODO(Phase1.5) below so the current patch lands without modifying JFR
// or unified-logging subsystem internals.
void EliyaArguments::apply_production_profile() {
  // --- JFR continuous recording (TODO Phase1.5 — JfrOptionSet hook) ------
  // Intended spec, once the JFR integration point lands:
  //   disk=true,maxage=24h,maxsize=250m,settings=default,dumponexit=true,
  //   filename=${base}/${service}/${replica?}/jfr/recording.jfr
  // See src/hotspot/share/jfr/recorder/service/jfrOptionSet.cpp.

  // --- Heap dump on OOM --------------------------------------------------
  if (!FLAG_IS_CMDLINE(HeapDumpOnOutOfMemoryError)) {
    FLAG_SET_ERGO(HeapDumpOnOutOfMemoryError, true);
  }
  if (!FLAG_IS_CMDLINE(HeapDumpPath)) {
    char* heap_dump_path = build_eliya_path("heap-dumps");
    FLAG_SET_ERGO(HeapDumpPath, heap_dump_path);
  }

  // --- Native Memory Tracking — summary mode -----------------------------
  if (!FLAG_IS_CMDLINE(NativeMemoryTracking)) {
    FLAG_SET_ERGO(NativeMemoryTracking, "summary");
  }

  // --- GC logging (TODO Phase1.5 — LogConfiguration hook) ----------------
  // Intended spec, once the unified-logging integration point lands:
  //   gc*:file=${gc_path}gc-%t-%p.log:time,uptime,level,tags:
  //       filecount=5,filesize=20m
  // See logging/logConfiguration.hpp parse_log_arguments().

  // --- Crash log path ----------------------------------------------------
  if (!FLAG_IS_CMDLINE(ErrorFile)) {
    char* error_file_path = build_eliya_error_file_path();
    FLAG_SET_ERGO(ErrorFile, error_file_path);
  }

  // --- Container awareness reinforcement ---------------------------------
  // UseContainerSupport defaults to true upstream; reinforced here for
  // auditability (no-op when already true).
  if (!FLAG_IS_CMDLINE(UseContainerSupport) && !UseContainerSupport) {
    FLAG_SET_ERGO(UseContainerSupport, true);
  }

  // --- Diagnostic VM options unlocked ------------------------------------
  if (!FLAG_IS_CMDLINE(UnlockDiagnosticVMOptions)) {
    FLAG_SET_ERGO(UnlockDiagnosticVMOptions, true);
  }
}

// ============================================================
// Conflict detection
// ============================================================

// Three-tier conflict detection per ADR-00001 §2.5.
//
//   Tier 1 (silent override): a user explicit command-line flag wins over a
//     profile-set ergonomic default. This tier is realised structurally via
//     the FLAG_IS_CMDLINE guards in apply_production_profile() above and
//     needs no code here.
//
//   Tier 2 (warning): a user explicit flag duplicates what the profile
//     already activates (e.g. -XX:+UseEliyaObservability under
//     EliyaProfile=Production once Phase 2 carves out capability flags).
//
//   Tier 3 (fatal): a user explicit negation breaks a capability the profile
//     requires (e.g. -XX:-UseEliyaSecurityStrict under EliyaProfile=PCIDSS
//     in Phase 4).
//
// Phase 1 has no carved-out capability flags yet (ADR-00001 §6.1 reserves
// the Layer 1 namespace for Phase 2), so Tiers 2 and 3 currently have no
// flag pairs to check. This function is the established integration point —
// Phase 2 / Phase 4 patches extend the body without changing
// Eliya::apply()'s dispatch.
void EliyaArguments::check_flag_consistency() {
  if (EliyaProfile == nullptr || strcmp(EliyaProfile, "None") == 0) {
    return;
  }
  // Phase 2+ tiers wire in here.
}

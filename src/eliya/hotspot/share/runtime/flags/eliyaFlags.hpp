/*
 * Copyright (c) 2026, Asymm Systems (Pvt) Ltd. All rights reserved.
 *
 * Eliya — see asymm.systems/product/eliya
 *   ADR-00001 §7.2: Phase 4 reserved profile-value namespace
 *   ADR-00009: source file layout (Eliya counterpart to
 *              src/hotspot/share/runtime/flags/jvmFlagConstraintsRuntime.cpp)
 *   ADR-00010: constraint function location + data-driven Status table
 */

#ifndef ELIYA_SHARE_RUNTIME_FLAGS_ELIYAFLAGS_HPP
#define ELIYA_SHARE_RUNTIME_FLAGS_ELIYAFLAGS_HPP

#include "memory/allStatic.hpp"
#include "runtime/flags/jvmFlag.hpp"

// Eliya-side semantic logic for EliyaProfile constraint validation and
// profile-activation dispatch, organised data-driven per ADR-00010.
//
// Adding a new profile (Phase 4 activation, Phase 5+ additions, etc.)
// touches only the data table KNOWN_PROFILES[]. No function body in
// this file or its .cpp ever changes when profiles change.
class EliyaFlags : public AllStatic {
public:
  // Outcome of a profile-value lookup. Carries the constraint return
  // code AND the operator-facing error message template together so
  // the data table is the single source of truth.
  struct Status {
    JVMFlag::Error code;     // SUCCESS or VIOLATES_CONSTRAINT
    const char*    message;  // nullptr (no message) or printf-format with %s
  };

  // Activator function for a profile. Called from activate_profile() at
  // apply_ergo()-time once the constraint function has accepted the
  // value. nullptr for non-activator entries (None, Phase 4 reserved,
  // unrecognised). When Phase 4 activates PCIDSS, the activator field
  // of its entry switches from nullptr to apply_pcidss_profile.
  typedef void (*Activator)();

  // One row of the profile registry.
  struct Entry {
    const char*   name;
    const Status& status;
    Activator     activator;  // nullptr if no activator
  };

  // Three shared Status singletons. Entries reference these by const&.
  static const Status ACCEPTED;
  static const Status RESERVED_PHASE_4;
  static const Status UNRECOGNIZED;

  // The data table. THE one thing that changes when profiles
  // activate / deprecate / are added.
  static const Entry KNOWN_PROFILES[];
  static const size_t KNOWN_PROFILES_COUNT;

  // Returns the entry for the given profile name, or nullptr if not in
  // the table. Treats nullptr input as nullptr output (no entry).
  static const Entry* find(const char* value);

  // Returns the status of a value: ACCEPTED, RESERVED_PHASE_4, or
  // UNRECOGNIZED (the fallback for values not in the table).
  static const Status& status_of(const char* value);

  // Validate at parse time (called from EliyaProfileConstraintFunc).
  // Reads the data table; never changes when profiles change.
  static JVMFlag::Error validate_profile(ccstr value, bool verbose);

  // Activate at apply_ergo() time (called from Eliya::apply()).
  // Looks up the entry's activator and invokes it if non-null.
  // The function body never changes when profiles change.
  static void activate_profile(const char* value);
};

// Free-function declaration matching the RUNTIME_CONSTRAINTS macro
// expansion in jvmFlagConstraintsRuntime.hpp. Definition lives in
// eliyaFlags.cpp; linker resolves the macro-generated declaration
// to that definition.
JVMFlag::Error EliyaProfileConstraintFunc(ccstr value, bool verbose);

#endif // ELIYA_SHARE_RUNTIME_FLAGS_ELIYAFLAGS_HPP

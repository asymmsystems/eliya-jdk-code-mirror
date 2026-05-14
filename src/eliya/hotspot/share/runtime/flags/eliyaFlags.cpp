/*
 * Copyright (c) 2026, Asymm Systems (Pvt) Ltd. All rights reserved.
 *
 * Eliya - see asymm.systems/product/eliya
 *   ADR-00001 sec.7.2: Phase 4 reserved profile-value namespace
 *   ADR-00009: source file layout
 *   ADR-00010: constraint function location + data-driven Status table
 *
 * Data-driven design: validate_profile() and activate_profile() are
 * three-line bodies that look up a value in KNOWN_PROFILES[] and act on
 * the entry's metadata. Adding a new profile = adding a row. Activating
 * a profile = changing its Status reference (RESERVED_PHASE_4 -> ACCEPTED)
 * and setting its activator field. The function bodies never change.
 */

#include "runtime/flags/eliyaFlags.hpp"
#include "runtime/eliyaArguments.hpp"   // for EliyaArguments::apply_production_profile

#include <cstring>

// ============================================================
// Shared Status singletons
// ============================================================
const EliyaFlags::Status EliyaFlags::ACCEPTED = {
    JVMFlag::SUCCESS,
    nullptr   // no error message - value accepted
};

const EliyaFlags::Status EliyaFlags::RESERVED_PHASE_4 = {
    JVMFlag::VIOLATES_CONSTRAINT,
    "EliyaProfile=%s is reserved for Phase 4. "
    "Currently available: None, Production.\n"
};

const EliyaFlags::Status EliyaFlags::UNRECOGNIZED = {
    JVMFlag::VIOLATES_CONSTRAINT,
    "Unrecognized value %s for EliyaProfile. "
    "Must be one of: None, Production.\n"
};

// ============================================================
// The profile registry - THE one place that changes when profiles
// activate / deprecate / are added. Per ADR-00001 sec.7.2 the Phase 4
// reserved namespace is the seven single-framework profiles plus the
// three combined profiles.
//
// Adding a Phase 5+ profile: append a row.
// Activating PCIDSS in Phase 4: change its row to { "PCIDSS", ACCEPTED,
//   &EliyaArguments::apply_pcidss_profile } (the activator definition
//   lands in eliyaArguments.cpp).
// ============================================================
const EliyaFlags::Entry EliyaFlags::KNOWN_PROFILES[] = {
    { "None",               ACCEPTED,         nullptr },
    { "Production",         ACCEPTED,         &EliyaArguments::apply_production_profile },
    // Phase 4 single-framework reserved namespace (ADR-00001 sec.7.2):
    { "PCIDSS",             RESERVED_PHASE_4, nullptr },
    { "HIPAA",              RESERVED_PHASE_4, nullptr },
    { "SOX",                RESERVED_PHASE_4, nullptr },
    { "FedRAMP",            RESERVED_PHASE_4, nullptr },
    { "GDPR",               RESERVED_PHASE_4, nullptr },
    { "ISO27001",           RESERVED_PHASE_4, nullptr },
    { "SOC2",               RESERVED_PHASE_4, nullptr },
    // Phase 4 combined-framework reserved namespace (ADR-00001 sec.7.2):
    { "Healthcare-Payment", RESERVED_PHASE_4, nullptr },
    { "Financial-SaaS",     RESERVED_PHASE_4, nullptr },
    { "Federal-Defense",    RESERVED_PHASE_4, nullptr },
};

const size_t EliyaFlags::KNOWN_PROFILES_COUNT =
    sizeof(KNOWN_PROFILES) / sizeof(KNOWN_PROFILES[0]);

// ============================================================
// Lookups
// ============================================================
const EliyaFlags::Entry* EliyaFlags::find(const char* value) {
  if (value == nullptr) return nullptr;
  for (size_t i = 0; i < KNOWN_PROFILES_COUNT; i++) {
    if (strcmp(value, KNOWN_PROFILES[i].name) == 0) {
      return &KNOWN_PROFILES[i];
    }
  }
  return nullptr;
}

const EliyaFlags::Status& EliyaFlags::status_of(const char* value) {
  const Entry* entry = find(value);
  return (entry != nullptr) ? entry->status : UNRECOGNIZED;
}

// ============================================================
// Validation (parse-time, called from EliyaProfileConstraintFunc)
//
// Three-line body. Never changes when profiles change.
// ============================================================
JVMFlag::Error EliyaFlags::validate_profile(ccstr value, bool verbose) {
  const Status& s = status_of(value);
  if (s.message != nullptr) JVMFlag::printError(verbose, s.message, value);
  return s.code;
}

// ============================================================
// Activation (apply_ergo-time, called from Eliya::apply())
//
// Three-line body. Never changes when profiles change. Activates
// whichever profile the operator chose by invoking the entry's
// function pointer.
// ============================================================
void EliyaFlags::activate_profile(const char* value) {
  const Entry* entry = find(value);
  if (entry != nullptr && entry->activator != nullptr) {
    entry->activator();
  }
}

// ============================================================
// Free-function definition that fulfills the RUNTIME_CONSTRAINTS
// macro-generated declaration. Linker resolves the declaration in
// jvmFlagConstraintsRuntime.hpp to this body.
// ============================================================
JVMFlag::Error EliyaProfileConstraintFunc(ccstr value, bool verbose) {
  return EliyaFlags::validate_profile(value, verbose);
}

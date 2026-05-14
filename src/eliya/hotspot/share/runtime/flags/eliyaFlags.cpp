/*
 * Copyright (c) 2026, Asymm Systems (Pvt) Ltd. All rights reserved.
 *
 * Eliya — see asymm.systems/product/eliya
 *   ADR-00001 §7.2: Phase 4 reserved profile-value namespace
 *   ADR-00009: source file layout (Eliya counterpart to
 *              src/hotspot/share/runtime/flags/jvmFlagConstraintsRuntime.cpp)
 *   ADR-00010: constraint function location
 *
 * COMMIT 1 NOTE: This file currently hosts the same strcmp-chain validation
 * body that TASK-00001 placed in jvmFlagConstraintsRuntime.cpp. The body is
 * pure code motion (same behavior) — Commit 2 of ISSUE-00001 refactors to
 * the data-driven Status + KNOWN_PROFILES[] design per ADR-00010 §2.1.
 */

#include "runtime/flags/eliyaFlags.hpp"
#include "runtime/flags/jvmFlag.hpp"

#include <cstring>

// EliyaFlags::validate_profile — currently the moved-from-upstream
// strcmp-chain body. Refactored to data-driven design in Commit 2.
JVMFlag::Error EliyaFlags::validate_profile(ccstr value, bool verbose) {
  if (value == nullptr) {
    JVMFlag::printError(verbose, "EliyaProfile cannot be empty\n");
    return JVMFlag::VIOLATES_CONSTRAINT;
  }
  if (strcmp(value, "None") == 0 || strcmp(value, "Production") == 0) {
    return JVMFlag::SUCCESS;
  }
  // Phase 4 reserved single-framework names (per ADR-00001 §7.2):
  if (strcmp(value, "PCIDSS")   == 0 ||
      strcmp(value, "HIPAA")    == 0 ||
      strcmp(value, "SOX")      == 0 ||
      strcmp(value, "FedRAMP")  == 0 ||
      strcmp(value, "GDPR")     == 0 ||
      strcmp(value, "ISO27001") == 0 ||
      strcmp(value, "SOC2")     == 0) {
    JVMFlag::printError(verbose,
                        "EliyaProfile=%s is reserved for Phase 4. "
                        "Currently available: None, Production.\n",
                        value);
    return JVMFlag::VIOLATES_CONSTRAINT;
  }
  // Phase 4 reserved combined-framework names (per ADR-00001 §7.2):
  if (strcmp(value, "Healthcare-Payment") == 0 ||
      strcmp(value, "Financial-SaaS")     == 0 ||
      strcmp(value, "Federal-Defense")    == 0) {
    JVMFlag::printError(verbose,
                        "EliyaProfile=%s is reserved for Phase 4. "
                        "Currently available: None, Production.\n",
                        value);
    return JVMFlag::VIOLATES_CONSTRAINT;
  }
  JVMFlag::printError(verbose,
                      "Unrecognized value %s for EliyaProfile. "
                      "Must be one of: None, Production.\n",
                      value);
  return JVMFlag::VIOLATES_CONSTRAINT;
}

// Free-function definition matching the RUNTIME_CONSTRAINTS macro
// expansion. The flag parser invokes this via the function pointer
// registered by globals.hpp's constraint() directive. Three-line stub
// that delegates to the EliyaFlags helper for testability and to keep
// the function body itself immutable across profile additions.
JVMFlag::Error EliyaProfileConstraintFunc(ccstr value, bool verbose) {
  return EliyaFlags::validate_profile(value, verbose);
}

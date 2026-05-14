/*
 * Copyright (c) 2026, Asymm Systems (Pvt) Ltd. All rights reserved.
 *
 * Eliya — see asymm.systems/product/eliya
 *   ADR-00001 §7.2: Phase 4 reserved profile-value namespace
 *   ADR-00009: source file layout (Eliya counterpart to
 *              src/hotspot/share/runtime/flags/jvmFlagConstraintsRuntime.cpp)
 *   ADR-00010: constraint function location (function body lives in
 *              this file; upstream jvmFlagConstraintsRuntime.cpp carries
 *              ZERO Eliya code post-ISSUE-00001)
 */

#ifndef ELIYA_SHARE_RUNTIME_FLAGS_ELIYAFLAGS_HPP
#define ELIYA_SHARE_RUNTIME_FLAGS_ELIYAFLAGS_HPP

#include "memory/allStatic.hpp"
#include "runtime/flags/jvmFlag.hpp"           // for JVMFlag::Error
#include "runtime/flags/jvmFlagConstraintList.hpp"  // for ccstr (via jvmFlagAccess includes)

// Eliya-side semantic logic for EliyaProfile constraint validation.
//
// Per ADR-00010, the function body for EliyaProfileConstraintFunc
// lives in eliyaFlags.cpp, not in upstream jvmFlagConstraintsRuntime.cpp.
// The RUNTIME_CONSTRAINTS macro in jvmFlagConstraintsRuntime.hpp
// generates the declaration; the linker resolves it to the definition
// in eliyaFlags.cpp.
//
// Phase 4 profile additions/activations touch only the data table in
// eliyaFlags.cpp (KNOWN_PROFILES[]). The function body itself never
// changes once written.
class EliyaFlags : public AllStatic {
public:
  // Validate an EliyaProfile=<value> setting at parse time. Returns
  // JVMFlag::SUCCESS for valid values (None, Production today; Phase 4
  // profiles when they activate); JVMFlag::VIOLATES_CONSTRAINT for
  // reserved or unrecognised values, after calling JVMFlag::printError
  // with a context-appropriate message.
  //
  // Currently Commit 1 of ISSUE-00001 (pure code motion) implements this
  // as a strcmp chain — same as TASK-00001's original body. Commit 2
  // refactors to the data-driven Status struct + KNOWN_PROFILES[] table
  // per ADR-00010 §2.1–§2.2.
  static JVMFlag::Error validate_profile(ccstr value, bool verbose);
};

// Free-function declaration matching the RUNTIME_CONSTRAINTS macro
// expansion in jvmFlagConstraintsRuntime.hpp. The definition lives in
// eliyaFlags.cpp; the linker resolves the macro-generated declaration
// to that definition.
JVMFlag::Error EliyaProfileConstraintFunc(ccstr value, bool verbose);

#endif // ELIYA_SHARE_RUNTIME_FLAGS_ELIYAFLAGS_HPP

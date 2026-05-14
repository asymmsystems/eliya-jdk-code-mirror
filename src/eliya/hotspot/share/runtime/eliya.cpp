/*
 * Copyright (c) 2026, Asymm Systems (Pvt) Ltd. All rights reserved.
 *
 * Eliya — see asymm.systems/product/eliya
 *
 * Top-level Eliya facade. Single dispatcher invoked from
 * Arguments::apply_ergo() in upstream arguments.cpp. Routes to
 * profile-specific activators and the conflict checker.
 *
 * Per ADR-00009: this file is part of the Eliya source mirror at
 * src/eliya/hotspot/share/runtime/eliya.cpp.
 */

#include "runtime/eliya.hpp"
#include "runtime/eliyaArguments.hpp"
#include "runtime/globals.hpp"  // EliyaProfile, EliyaConflictCheck

#include <cstring>

// Single dispatcher. Reads the current EliyaProfile + EliyaConflictCheck
// values and routes to the appropriate Eliya-side handlers.
//
// COMMIT 1 NOTE: This commit's body uses the same direct strcmp branch
// TASK-00001 had in apply_ergo() — pure code motion. Commit 2 of
// ISSUE-00001 refactors to a data-driven dispatch so Phase 4 profile
// additions never touch this function body (per ADR-00010's "untouchable
// after refactor" principle, extended to apply() as well).
void Eliya::apply() {
  // Applied LAST (in apply_ergo's call order), so this observes the
  // final state of other ergonomic decisions. Explicit user
  // command-line flags still win because EliyaArguments uses
  // FLAG_IS_CMDLINE guards (ADR-00001 §2.5 tier 1).
  //
  // Per ADR-00001 §6.1, dispatch on the EliyaProfile enum value. The
  // EliyaProfileConstraintFunc (registered in globals.hpp) has
  // already rejected unrecognised and Phase-4-reserved values at
  // parse time, so here only the currently-valid Phase 1 cases need
  // handling.
  if (EliyaProfile != nullptr && strcmp(EliyaProfile, "Production") == 0) {
    EliyaArguments::apply_production_profile();
  }

  // Three-tier conflict detection, gated by -XX:+EliyaConflictCheck
  // (default true; -XX:-EliyaConflictCheck disables).
  if (EliyaConflictCheck) {
    EliyaArguments::check_flag_consistency();
  }
}

/*
 * Copyright (c) 2026, Asymm Systems (Pvt) Ltd. All rights reserved.
 *
 * Eliya — see asymm.systems/product/eliya
 *   ADR-00009: source file layout (Eliya facade)
 *   ADR-00010: data-driven profile dispatch (EliyaFlags::activate_profile)
 *
 * Top-level facade. Single dispatcher invoked from
 * Arguments::apply_ergo() in upstream arguments.cpp.
 *
 * This function body NEVER changes when profiles activate / deprecate /
 * are added. All per-profile dispatch happens through
 * EliyaFlags::activate_profile() reading the KNOWN_PROFILES[] table.
 */

#include "runtime/eliya.hpp"
#include "runtime/eliyaArguments.hpp"
#include "runtime/flags/eliyaFlags.hpp"
#include "runtime/globals.hpp"  // EliyaProfile, EliyaConflictCheck

// Single dispatcher. Reads EliyaProfile + EliyaConflictCheck and
// delegates to the data-driven activator + conflict checker. Phase 4
// profile activations change rows in EliyaFlags::KNOWN_PROFILES[]
// (in eliyaFlags.cpp); this function body never changes.
void Eliya::apply() {
  // Applied LAST in apply_ergo's call order, so it observes the final
  // state of other ergonomic decisions. Explicit user command-line
  // flags still win because EliyaArguments::apply_production_profile
  // (and future activators) use FLAG_IS_CMDLINE guards (ADR-00001
  // §2.5 tier 1).
  //
  // Per ADR-00010 §2: dispatch is data-driven. The constraint function
  // already rejected unrecognised and Phase-4-reserved values at parse
  // time, so by the time we get here, EliyaProfile is either "None"
  // (no activator), "Production" (Phase 1 activator), or a Phase 4+
  // value whose activator's row in KNOWN_PROFILES[] has been wired
  // when that phase activates.
  EliyaFlags::activate_profile(EliyaProfile);

  // Three-tier conflict detection, gated by -XX:+EliyaConflictCheck
  // (default true; -XX:-EliyaConflictCheck disables).
  if (EliyaConflictCheck) {
    EliyaArguments::check_flag_consistency();
  }
}

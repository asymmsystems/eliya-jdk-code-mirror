/*
 * Copyright (c) 2026, Asymm Systems (Pvt) Ltd. All rights reserved.
 *
 * Eliya - see asymm.systems/product/eliya
 *   ADR-00001: flag taxonomy (EliyaProfile + EliyaConflictCheck)
 *   ADR-00006: adaptive three-or-two-level diagnostic path layout
 *              with the replica-suppression rule
 *   ADR-00009: source file layout (this file lives in the
 *              src/eliya/hotspot/share/... mirror tree)
 */

#ifndef ELIYA_SHARE_RUNTIME_ELIYAARGUMENTS_HPP
#define ELIYA_SHARE_RUNTIME_ELIYAARGUMENTS_HPP

#include "memory/allStatic.hpp"

// Counterpart to src/hotspot/share/runtime/arguments.cpp's Eliya block,
// moved here per ADR-00009. Owns:
//   - Diagnostic-path component resolution (base, service, replica)
//   - Path builders (directory and crash-file forms)
//   - Production-profile activator (the eight observability defaults)
//   - Three-tier conflict-detection integration point
class EliyaArguments : public AllStatic {
public:
  // Phase 1: activates the Production profile defaults (observability,
  // diagnostics, operational) when EliyaProfile == "Production". Respects
  // FLAG_IS_CMDLINE (user-explicit-wins per ADR-00001 sec.2.5 tier 1).
  static void apply_production_profile();

  // Three-tier conflict detection per ADR-00001 sec.2.5. Gated by
  // -XX:+EliyaConflictCheck (default true). Phase 1 has no carved-out
  // capability flags yet - this is the integration point Phase 2+
  // extends without changing the dispatch.
  static void check_flag_consistency();
};

#endif // ELIYA_SHARE_RUNTIME_ELIYAARGUMENTS_HPP

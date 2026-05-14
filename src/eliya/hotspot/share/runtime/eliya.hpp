/*
 * Copyright (c) 2026, Asymm Systems (Pvt) Ltd. All rights reserved.
 *
 * Eliya — see asymm.systems/product/eliya
 *
 * Top-level Eliya facade. Single entry point invoked from upstream
 * arguments.cpp at the end of Arguments::apply_ergo(). All Eliya
 * behaviour dispatches from here.
 *
 * Per ADR-00009 §2.1, this file lives at the root of the Eliya source
 * mirror tree. The upstream-file delegation is one line:
 *     Eliya::apply();
 * in arguments.cpp's apply_ergo().
 */

#ifndef ELIYA_SHARE_RUNTIME_ELIYA_HPP
#define ELIYA_SHARE_RUNTIME_ELIYA_HPP

#include "memory/allStatic.hpp"

class Eliya : public AllStatic {
public:
  // Single dispatcher invoked from Arguments::apply_ergo(). Reads the
  // current value of EliyaProfile + EliyaConflictCheck and routes to
  // the appropriate Eliya-side handlers. Future profile activations
  // (Phase 4) and capability-flag-based conflict tiers (Phase 2)
  // extend the dispatchee functions (in eliyaArguments.cpp) — this
  // facade method is never touched again.
  static void apply();
};

#endif // ELIYA_SHARE_RUNTIME_ELIYA_HPP

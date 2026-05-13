/*
 * Copyright (c) 2015, 2025, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 *
 */

#include "runtime/flags/jvmFlag.hpp"
#include "runtime/flags/jvmFlagLimit.hpp"
#include "runtime/flags/jvmFlagConstraintsRuntime.hpp"
#include "runtime/globals.hpp"
#include "runtime/os.hpp"
#include "runtime/safepointMechanism.hpp"
#include "runtime/task.hpp"
#include "utilities/powerOfTwo.hpp"

JVMFlag::Error AOTCacheConstraintFunc(ccstr value, bool verbose) {
  if (value == nullptr) {
    JVMFlag::printError(verbose, "AOTCache cannot be empty\n");
    return JVMFlag::VIOLATES_CONSTRAINT;
  }
  return JVMFlag::SUCCESS;
}

JVMFlag::Error AOTCacheOutputConstraintFunc(ccstr value, bool verbose) {
  if (value == nullptr) {
    JVMFlag::printError(verbose, "AOTCacheOutput cannot be empty\n");
    return JVMFlag::VIOLATES_CONSTRAINT;
  }
  return JVMFlag::SUCCESS;
}

JVMFlag::Error AOTConfigurationConstraintFunc(ccstr value, bool verbose) {
  if (value == nullptr) {
    JVMFlag::printError(verbose, "AOTConfiguration cannot be empty\n");
    return JVMFlag::VIOLATES_CONSTRAINT;
  }
  return JVMFlag::SUCCESS;
}

JVMFlag::Error AOTModeConstraintFunc(ccstr value, bool verbose) {
  if (value == nullptr) {
    JVMFlag::printError(verbose, "AOTMode cannot be empty\n");
    return JVMFlag::VIOLATES_CONSTRAINT;
  }
  if (strcmp(value, "off") != 0 &&
      strcmp(value, "record") != 0 &&
      strcmp(value, "create") != 0 &&
      strcmp(value, "auto") != 0 &&
      strcmp(value, "on") != 0) {
    JVMFlag::printError(verbose,
                        "Unrecognized value %s for AOTMode. Must be one of the following: "
                        "off, record, create, auto, on\n",
                        value);
    return JVMFlag::VIOLATES_CONSTRAINT;
  }
  return JVMFlag::SUCCESS;
}

JVMFlag::Error ObjectAlignmentInBytesConstraintFunc(int value, bool verbose) {
  if (!is_power_of_2(value)) {
    JVMFlag::printError(verbose,
                        "ObjectAlignmentInBytes (%d) must be "
                        "power of 2\n",
                        value);
    return JVMFlag::VIOLATES_CONSTRAINT;
  }
  // In case page size is very small.
  if (value >= (intx)os::vm_page_size()) {
    JVMFlag::printError(verbose,
                        "ObjectAlignmentInBytes (%d) must be "
                        "less than page size (%zu)\n",
                        value, os::vm_page_size());
    return JVMFlag::VIOLATES_CONSTRAINT;
  }
  return JVMFlag::SUCCESS;
}

// Need to enforce the padding not to break the existing field alignments.
// It is sufficient to check against the largest type size.
JVMFlag::Error ContendedPaddingWidthConstraintFunc(int value, bool verbose) {
  if ((value % BytesPerLong) != 0) {
    JVMFlag::printError(verbose,
                        "ContendedPaddingWidth (%d) must be "
                        "a multiple of %d\n",
                        value, BytesPerLong);
    return JVMFlag::VIOLATES_CONSTRAINT;
  } else {
    return JVMFlag::SUCCESS;
  }
}

JVMFlag::Error PerfDataSamplingIntervalFunc(int value, bool verbose) {
  if ((value % PeriodicTask::interval_gran != 0)) {
    JVMFlag::printError(verbose,
                        "PerfDataSamplingInterval (%d) must be "
                        "evenly divisible by PeriodicTask::interval_gran (%d)\n",
                        value, PeriodicTask::interval_gran);
    return JVMFlag::VIOLATES_CONSTRAINT;
  } else {
    return JVMFlag::SUCCESS;
  }
}

JVMFlag::Error VMPageSizeConstraintFunc(uintx value, bool verbose) {
  uintx min = (uintx)os::vm_page_size();
  if (value < min) {
    JVMFlag::printError(verbose,
                        "%s %s=%zu is outside the allowed range [ %zu"
                        " ... %zu ]\n",
                        JVMFlagLimit::last_checked_flag()->type_string(),
                        JVMFlagLimit::last_checked_flag()->name(),
                        value, min, max_uintx);
    return JVMFlag::VIOLATES_CONSTRAINT;
  }

  return JVMFlag::SUCCESS;
}

JVMFlag::Error NUMAInterleaveGranularityConstraintFunc(size_t value, bool verbose) {
  size_t min = os::vm_allocation_granularity();
  size_t max = NOT_LP64(2*G) LP64_ONLY(8192*G);

  if (value < min || value > max) {
    JVMFlag::printError(verbose,
                        "size_t NUMAInterleaveGranularity=%zu is outside the allowed range [ %zu"
                        " ... %zu ]\n", value, min, max);
    return JVMFlag::VIOLATES_CONSTRAINT;
  }

  return JVMFlag::SUCCESS;
}

JVMFlag::Error LargePageSizeInBytesConstraintFunc(size_t value, bool verbose) {
  if (!is_power_of_2(value)) {
    JVMFlag::printError(verbose, "LargePageSizeInBytes ( %zu ) must be "
                        "a power of 2\n",
                        value);
    return JVMFlag::VIOLATES_CONSTRAINT;
  }
  return JVMFlag::SUCCESS;
}


// ============================================================
// Eliya — see asymm.systems/product/eliya  (ADR-00001 §2)
//
// Phase 1 valid values: None, Production.
// Phase 4 reserved values — seven single-framework profiles
// (PCIDSS, HIPAA, SOX, FedRAMP, GDPR, ISO27001, SOC2) plus three
// combined-framework profiles (Healthcare-Payment, Financial-SaaS,
// Federal-Defense) — are rejected with a "reserved" message so
// operators discovering them in documentation get a clear error
// rather than silent acceptance.
// ============================================================
JVMFlag::Error EliyaProfileConstraintFunc(ccstr value, bool verbose) {
  if (value == nullptr) {
    JVMFlag::printError(verbose, "EliyaProfile cannot be empty\n");
    return JVMFlag::VIOLATES_CONSTRAINT;
  }
  if (strcmp(value, "None") == 0 || strcmp(value, "Production") == 0) {
    return JVMFlag::SUCCESS;
  }
  if (strcmp(value, "PCIDSS")             == 0 ||
      strcmp(value, "HIPAA")              == 0 ||
      strcmp(value, "SOX")                == 0 ||
      strcmp(value, "FedRAMP")            == 0 ||
      strcmp(value, "GDPR")               == 0 ||
      strcmp(value, "ISO27001")           == 0 ||
      strcmp(value, "SOC2")               == 0 ||
      strcmp(value, "Healthcare-Payment") == 0 ||
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

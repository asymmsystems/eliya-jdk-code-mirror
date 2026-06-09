/*
 * Copyright (c) 2026, Asymm Systems (Pvt) Ltd. All rights reserved.
 * @author Fahim Farook
 */

/*
 * @test
 * @summary Validate EliyaProfile constraint function:
 *          - accepts None and Production
 *          - rejects all 10 Phase 4 reserved names (7 single-framework +
 *            3 combined) with "reserved for Phase 4" message
 *          - rejects unknown values with the generic "Unrecognized value"
 *            message
 *          See ADR-00001 sec.7.2 (Phase 4 reserved namespace) and
 *          ADR-00010 (constraint function location).
 * @library /test/lib
 * @run main EliyaProfileValidation
 */

import jdk.test.lib.process.ProcessTools;
import jdk.test.lib.process.OutputAnalyzer;

public class EliyaProfileValidation {

    private static final String[] ACCEPTED = {
        "None", "Production"
    };

    private static final String[] PHASE_4_RESERVED = {
        // 7 single-framework names
        "PCIDSS", "HIPAA", "SOX", "FedRAMP", "GDPR", "ISO27001", "SOC2",
        // 3 combined-framework names
        "Healthcare-Payment", "Financial-SaaS", "Federal-Defense"
    };

    public static void main(String[] args) throws Exception {
        // 1. Accepted values produce a successful version banner.
        for (String accepted : ACCEPTED) {
            OutputAnalyzer out = ProcessTools.executeTestJava(
                "-XX:EliyaProfile=" + accepted, "-version");
            out.shouldHaveExitValue(0);
        }

        // 2. All 10 Phase 4 reserved names rejected with "reserved for Phase 4".
        for (String reserved : PHASE_4_RESERVED) {
            OutputAnalyzer out = ProcessTools.executeTestJava(
                "-XX:EliyaProfile=" + reserved, "-version");
            out.shouldNotHaveExitValue(0);
            out.shouldContain("reserved for Phase 4");
            // Confirm the message names the specific profile attempted.
            out.shouldContain("EliyaProfile=" + reserved);
        }

        // 3. Unrecognized value produces the generic rejection.
        OutputAnalyzer out = ProcessTools.executeTestJava(
            "-XX:EliyaProfile=Foobar", "-version");
        out.shouldNotHaveExitValue(0);
        out.shouldContain("Unrecognized value Foobar");

        // 4. No EliyaProfile flag specified: JVM starts successfully AND the
        //    Production-profile defaults are NOT activated. The discriminator
        //    is the {ergonomic} marker, not the raw value: when None, the
        //    apply_production_profile() activator never runs, so none of the
        //    flags it would FLAG_SET_ERGO carry {ergonomic}.
        //
        //    Note: UnlockDiagnosticVMOptions is itself a {diagnostic} flag,
        //    so -XX:+PrintFlagsFinal does NOT list it at all unless it is
        //    already unlocked. Asserting "= false" can therefore never match
        //    in the default case (the line is absent, not false). The correct
        //    negative check is "not ergonomically activated".
        out = ProcessTools.executeTestJava("-XX:+PrintFlagsFinal", "-version");
        out.shouldHaveExitValue(0);
        // EliyaProfile flag itself is present with default value "None".
        out.shouldMatch("ccstr\\s+EliyaProfile\\s*=\\s*None");
        // NativeMemoryTracking should be off (upstream default), not "summary"
        // which is what the Production activator would set ergonomically.
        out.shouldMatch("ccstr\\s+NativeMemoryTracking\\s*=\\s*off");
        // Production would FLAG_SET_ERGO UnlockDiagnosticVMOptions=true; with
        // None it must not appear ergonomically activated.
        out.shouldNotMatch("UnlockDiagnosticVMOptions.*\\{ergonomic\\}");
        out.shouldNotMatch("HeapDumpOnOutOfMemoryError.*\\{ergonomic\\}");

        // 5. Explicit EliyaProfile=None: identical to omitting the flag.
        out = ProcessTools.executeTestJava(
            "-XX:EliyaProfile=None", "-XX:+PrintFlagsFinal", "-version");
        out.shouldHaveExitValue(0);
        out.shouldMatch("ccstr\\s+NativeMemoryTracking\\s*=\\s*off");
        out.shouldNotMatch("UnlockDiagnosticVMOptions.*\\{ergonomic\\}");
        out.shouldNotMatch("HeapDumpOnOutOfMemoryError.*\\{ergonomic\\}");

        System.out.println("EliyaProfileValidation: all assertions passed.");
    }
}

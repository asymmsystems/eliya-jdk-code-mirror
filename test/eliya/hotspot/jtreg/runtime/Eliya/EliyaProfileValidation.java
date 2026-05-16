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
            OutputAnalyzer out = ProcessTools.executeTestJvm(
                "-XX:EliyaProfile=" + accepted, "-version");
            out.shouldHaveExitValue(0);
        }

        // 2. All 10 Phase 4 reserved names rejected with "reserved for Phase 4".
        for (String reserved : PHASE_4_RESERVED) {
            OutputAnalyzer out = ProcessTools.executeTestJvm(
                "-XX:EliyaProfile=" + reserved, "-version");
            out.shouldNotHaveExitValue(0);
            out.shouldContain("reserved for Phase 4");
            // Confirm the message names the specific profile attempted.
            out.shouldContain("EliyaProfile=" + reserved);
        }

        // 3. Unrecognized value produces the generic rejection.
        OutputAnalyzer out = ProcessTools.executeTestJvm(
            "-XX:EliyaProfile=Foobar", "-version");
        out.shouldNotHaveExitValue(0);
        out.shouldContain("Unrecognized value Foobar");

        // 4. No EliyaProfile flag specified: JVM starts successfully AND the
        //    Production-profile defaults are NOT activated. Specifically,
        //    NativeMemoryTracking and UnlockDiagnosticVMOptions stay at
        //    their upstream defaults (off/false) rather than the
        //    {ergonomic} values the Production activator would set.
        out = ProcessTools.executeTestJvm("-XX:+PrintFlagsFinal", "-version");
        out.shouldHaveExitValue(0);
        // EliyaProfile flag itself is present with default value "None".
        out.shouldMatch("ccstr\\s+EliyaProfile\\s*=\\s*None");
        // NativeMemoryTracking should be off (upstream default), not "summary"
        // which is what the Production activator would set ergonomically.
        out.shouldMatch("ccstr\\s+NativeMemoryTracking\\s*=\\s*off");
        // UnlockDiagnosticVMOptions should be false (upstream default).
        out.shouldMatch("bool\\s+UnlockDiagnosticVMOptions\\s*=\\s*false");

        // 5. Explicit EliyaProfile=None: identical to omitting the flag.
        out = ProcessTools.executeTestJvm(
            "-XX:EliyaProfile=None", "-XX:+PrintFlagsFinal", "-version");
        out.shouldHaveExitValue(0);
        out.shouldMatch("ccstr\\s+NativeMemoryTracking\\s*=\\s*off");
        out.shouldMatch("bool\\s+UnlockDiagnosticVMOptions\\s*=\\s*false");

        System.out.println("EliyaProfileValidation: all assertions passed.");
    }
}

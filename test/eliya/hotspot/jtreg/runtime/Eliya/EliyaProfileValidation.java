/*
 * Copyright (c) 2026, Asymm Systems (Pvt) Ltd. All rights reserved.
 */

/*
 * @test
 * @summary Validate EliyaProfile constraint function:
 *          - accepts None and Production
 *          - rejects all 10 Phase 4 reserved names (7 single-framework +
 *            3 combined) with "reserved for Phase 4" message
 *          - rejects unknown values with the generic "Unrecognized value"
 *            message
 *          See ADR-00001 §7.2 (Phase 4 reserved namespace) and
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

        // 4. Default (no flag specified) — succeeds with EliyaProfile=None.
        out = ProcessTools.executeTestJvm("-version");
        out.shouldHaveExitValue(0);

        System.out.println("EliyaProfileValidation: all assertions passed.");
    }
}

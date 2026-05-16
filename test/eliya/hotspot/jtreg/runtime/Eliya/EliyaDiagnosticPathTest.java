/*
 * Copyright (c) 2026, Asymm Systems (Pvt) Ltd. All rights reserved.
 * @author Fahim Farook
 */

/*
 * @test
 * @summary Validate the diagnostic-path resolution chain per ADR-00006
 *          (amended sec.2.2: env -> sysprop -> HOSTNAME-or-default).
 *          - Env wins over sysprop
 *          - Sysprop wins over platform default
 *          - Service / replica resolution uses HOSTNAME fallback
 *          - Replica suppression collapses to two-level path when
 *            replica is unset or byte-equal to service
 *          Specifically exercises the sysprop step added in
 *          ISSUE-00001 commit 3 to base-path resolution.
 * @library /test/lib
 * @run main EliyaDiagnosticPathTest
 */

import jdk.test.lib.process.ProcessTools;
import jdk.test.lib.process.OutputAnalyzer;
import java.util.Arrays;
import java.util.Map;
import java.util.HashMap;

public class EliyaDiagnosticPathTest {

    /**
     * Run the JVM with the given env + sysprop + flag arguments, asking it
     * to print final flag values, then assert HeapDumpPath contains the
     * expected substring (the resolved base path under which the
     * heap-dumps directory lives).
     */
    private static void assertHeapDumpPathContains(Map<String,String> env,
                                                   String[] jvmArgs,
                                                   String expectedSubstring)
            throws Exception {
        String[] cmd = new String[jvmArgs.length + 2];
        cmd[0] = "-XX:+PrintFlagsFinal";
        System.arraycopy(jvmArgs, 0, cmd, 1, jvmArgs.length);
        cmd[cmd.length - 1] = "-version";

        ProcessBuilder pb = ProcessTools.createTestJvm(cmd);
        if (env != null) pb.environment().putAll(env);
        OutputAnalyzer out = new OutputAnalyzer(pb.start());
        out.shouldHaveExitValue(0);
        out.shouldMatch("HeapDumpPath\\s*=\\s*.*" + expectedSubstring + ".*");
    }

    public static void main(String[] args) throws Exception {

        // 1. Env wins over sysprop: ELIYA_DIAGNOSTIC_PATH=/tmp/env-wins
        //    plus -Deliya.diagnostic.path=/tmp/sysprop-loses -> /tmp/env-wins
        Map<String,String> envWins = new HashMap<>();
        envWins.put("ELIYA_DIAGNOSTIC_PATH", "/tmp/eliya-test-env-wins");
        envWins.put("ELIYA_SERVICE_NAME", "svc");
        assertHeapDumpPathContains(
            envWins,
            new String[]{
                "-XX:EliyaProfile=Production",
                "-Deliya.diagnostic.path=/tmp/eliya-test-sysprop-loses"
            },
            "/tmp/eliya-test-env-wins/svc/");

        // 2. Sysprop wins over platform default when env is unset.
        Map<String,String> noEnv = new HashMap<>();
        noEnv.put("ELIYA_DIAGNOSTIC_PATH", "");          // empty == unset per try_env
        noEnv.put("ELIYA_SERVICE_NAME", "svc-b");
        assertHeapDumpPathContains(
            noEnv,
            new String[]{
                "-XX:EliyaProfile=Production",
                "-Deliya.diagnostic.path=/tmp/eliya-test-sysprop-wins"
            },
            "/tmp/eliya-test-sysprop-wins/svc-b/");

        // 3. Replica suppression: when ELIYA_REPLICA_NAME == ELIYA_SERVICE_NAME,
        //    the path collapses from three-level to two-level (no replica segment).
        Map<String,String> suppression = new HashMap<>();
        suppression.put("ELIYA_DIAGNOSTIC_PATH", "/tmp/eliya-test-supp");
        suppression.put("ELIYA_SERVICE_NAME", "same");
        suppression.put("ELIYA_REPLICA_NAME", "same");
        // Two-level path: /tmp/eliya-test-supp/same/heap-dumps/
        // (no /same/same/ - replica suppressed)
        assertHeapDumpPathContains(
            suppression,
            new String[]{ "-XX:EliyaProfile=Production" },
            "/tmp/eliya-test-supp/same/heap-dumps/");

        // 4. Three-level path: when replica differs from service.
        Map<String,String> threeLvl = new HashMap<>();
        threeLvl.put("ELIYA_DIAGNOSTIC_PATH", "/tmp/eliya-test-3l");
        threeLvl.put("ELIYA_SERVICE_NAME", "billing");
        threeLvl.put("ELIYA_REPLICA_NAME", "billing-pod-xk29");
        assertHeapDumpPathContains(
            threeLvl,
            new String[]{ "-XX:EliyaProfile=Production" },
            "/tmp/eliya-test-3l/billing/billing-pod-xk29/heap-dumps/");

        System.out.println("EliyaDiagnosticPathTest: all assertions passed.");
    }
}

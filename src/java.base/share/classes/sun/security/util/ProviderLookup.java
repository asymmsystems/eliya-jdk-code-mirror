/*
 * Copyright (c) 2026, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
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
 */

package sun.security.util;

import java.security.Provider;
import java.security.Security;

/**
 * Capability-based provider lookup helpers.
 *
 * <p>Callers inside the JDK that need a specific JCA service should ask by
 * capability, not by hardcoded provider name. This class centralises the
 * {@link Security#getProviders(String)} idiom so that a KeyFactory-for-DH
 * consumer inside {@code jdk.crypto.cryptoki} works whether the registered
 * DH provider is SunJCE, BC-FJA, or an alternative substitute.
 *
 * <p>Package-private; not part of the public API. External callers use
 * {@link Security#getProviders(String)} directly.
 */
public final class ProviderLookup {

    private ProviderLookup() {
        // no instances
    }

    /**
     * Returns the first registered provider that offers the JCA service
     * {@code serviceType.algorithm}, or {@code null} if no registered
     * provider offers it.
     *
     * @param serviceType JCA service type, e.g. {@code "KeyFactory"},
     *                    {@code "Cipher"}, {@code "KeyAgreement"},
     *                    {@code "AlgorithmParameters"}
     * @param algorithm   algorithm name, e.g. {@code "DH"}, {@code "RSA"},
     *                    {@code "AES/GCM/NoPadding"}
     * @return the first provider offering the capability, or {@code null}
     */
    public static Provider getFirstProviderFor(String serviceType,
            String algorithm) {
        Provider[] ps = Security.getProviders(serviceType + "." + algorithm);
        return (ps == null || ps.length == 0) ? null : ps[0];
    }

    /**
     * Returns the first registered provider that offers any of the given
     * {@code type.algorithm} keys, checked in order, or {@code null} if
     * no registered provider offers any of them.
     *
     * @param typeAlgorithmKeys pre-joined {@code "type.algorithm"} strings,
     *                          checked left-to-right; first match wins
     * @return the first provider offering any listed capability, or
     *         {@code null}
     */
    public static Provider getFirstProviderFor(String... typeAlgorithmKeys) {
        for (String key : typeAlgorithmKeys) {
            Provider[] ps = Security.getProviders(key);
            if (ps != null && ps.length > 0) {
                return ps[0];
            }
        }
        return null;
    }
}

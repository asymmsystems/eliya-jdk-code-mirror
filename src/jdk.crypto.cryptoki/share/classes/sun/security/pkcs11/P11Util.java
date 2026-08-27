/*
 * Copyright (c) 2003, 2024, Oracle and/or its affiliates. All rights reserved.
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

package sun.security.pkcs11;

import java.lang.ref.Cleaner;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.security.*;

import sun.security.pkcs11.wrapper.PKCS11Exception;
import static sun.security.pkcs11.wrapper.PKCS11Exception.RV.*;

/**
 * Collection of static utility methods.
 *
 * @author  Andreas Sterbenz
 * @since   1.5
 */
public final class P11Util {

    // A cleaner, shared within this module.
    public static final Cleaner cleaner = Cleaner.create();

    // JCA service-type constants used by the capability-lookup helpers below.
    private static final String KEY_FACTORY = "KeyFactory";
    private static final String ALGORITHM_PARAMETERS = "AlgorithmParameters";

    // Per-capability caches for the fixed-capability helpers. Each holds the
    // first-non-excluded provider for its capability. Volatile is enough - a
    // benign race between concurrent first-callers just repeats the O(N)
    // lookup once; the result is deterministic.
    private static volatile Provider dhProvider;
    private static volatile Provider rsaProvider;
    private static volatile Provider dsaProvider;
    private static volatile Provider ecProvider;

    private P11Util() {
        // empty
    }

    /**
     * Returns the first JCA-registered provider that offers the service
     * {@code serviceType.algorithm} and is not the {@code excluding} provider.
     *
     * <p>Intended for SunPKCS11-internal fallback lookups where SunPKCS11
     * needs a software delegate for parameter marshalling or key translation.
     * Callers pass their owning {@code SunPKCS11} instance as {@code excluding}
     * to prevent lookup-recursion when SunPKCS11 itself is registered offering
     * the same JCA service.
     *
     * @param serviceType JCA service type, e.g. "KeyFactory", "AlgorithmParameters"
     * @param algorithm   algorithm name, e.g. "DH", "RSA"
     * @param excluding   a provider instance to skip; may be null to skip
     *                    nothing
     * @throws ProviderException if no non-excluded provider offers the
     *         requested capability
     */
    static Provider firstProviderFor(String serviceType, String algorithm,
            Provider excluding) throws ProviderException {
        Provider[] ps = Security.getProviders(serviceType + "." + algorithm);
        if (ps == null || ps.length == 0) {
            throw noSuchProvider(serviceType, algorithm, excluding);
        }
        if (excluding == null) {
            return ps[0];
        }
        for (Provider p : ps) {
            if (p != excluding) {
                return p;
            }
        }
        throw noSuchProvider(serviceType, algorithm, excluding);
    }

    private static ProviderException noSuchProvider(String serviceType,
            String algorithm, Provider excluding) {
        return new ProviderException("No JCA provider offers "
                + serviceType + "." + algorithm
                + (excluding == null ? ""
                        : " (excluding " + excluding.getName() + ")"));
    }

    /**
     * Returns the first JCA-registered provider that offers
     * {@code AlgorithmParameters.<algorithm>} and is not the {@code excluding}
     * provider. Not cached: {@code algorithm} is a variable in the sole
     * calling context, so a per-algorithm cache would proliferate keys with
     * no reuse benefit.
     *
     * @see #firstProviderFor(String, String, Provider)
     */
    static Provider getFirstAlgorithmParametersProvider(String algorithm,
            Provider excluding) throws ProviderException {
        return firstProviderFor(ALGORITHM_PARAMETERS, algorithm, excluding);
    }

    /**
     * Returns the first JCA-registered provider that offers {@code KeyFactory.DH}
     * and is not the {@code excluding} provider. Result is cached across calls.
     *
     * @see #firstProviderFor(String, String, Provider)
     */
    static Provider getFirstDhProvider(Provider excluding)
            throws ProviderException {
        Provider p = dhProvider;
        if (p != null && p != excluding) {
            return p;
        }
        p = firstProviderFor(KEY_FACTORY, "DH", excluding);
        dhProvider = p;
        return p;
    }

    /**
     * Returns the first JCA-registered provider that offers {@code KeyFactory.RSA}
     * and is not the {@code excluding} provider. Result is cached across calls.
     *
     * @see #firstProviderFor(String, String, Provider)
     */
    static Provider getFirstRsaProvider(Provider excluding)
            throws ProviderException {
        Provider p = rsaProvider;
        if (p != null && p != excluding) {
            return p;
        }
        p = firstProviderFor(KEY_FACTORY, "RSA", excluding);
        rsaProvider = p;
        return p;
    }

    /**
     * Returns the first JCA-registered provider that offers {@code KeyFactory.DSA}
     * and is not the {@code excluding} provider. Result is cached across calls.
     *
     * @see #firstProviderFor(String, String, Provider)
     */
    static Provider getFirstDsaProvider(Provider excluding)
            throws ProviderException {
        Provider p = dsaProvider;
        if (p != null && p != excluding) {
            return p;
        }
        p = firstProviderFor(KEY_FACTORY, "DSA", excluding);
        dsaProvider = p;
        return p;
    }

    /**
     * Returns the first JCA-registered provider that offers {@code KeyFactory.EC}
     * and is not the {@code excluding} provider. Result is cached across calls.
     *
     * @see #firstProviderFor(String, String, Provider)
     */
    static Provider getFirstEcProvider(Provider excluding)
            throws ProviderException {
        Provider p = ecProvider;
        if (p != null && p != excluding) {
            return p;
        }
        p = firstProviderFor(KEY_FACTORY, "EC", excluding);
        ecProvider = p;
        return p;
    }

    static boolean isNSS(Token token) {
        char[] tokenLabel = token.tokenInfo.label;
        if (tokenLabel != null && tokenLabel.length >= 3) {
            return (tokenLabel[0] == 'N' && tokenLabel[1] == 'S'
                    && tokenLabel[2] == 'S');
        }
        return false;
    }

    static char[] encodePassword(char[] password, Charset cs,
            int nullTermBytes) {
        /*
         * When a Java char (2 bytes) is converted to CK_UTF8CHAR (1 byte) for
         * a PKCS #11 (native) call, the high-order byte is discarded (see
         * jCharArrayToCKUTF8CharArray in p11_util.c). In order to have an
         * encoded string passed to C_GenerateKey, we need to account for
         * truncation and expand beforehand: high and low parts of each char
         * are split into 2 chars. As an example, this is the transformation
         * for a NULL terminated password "a" that has to be encoded in
         * UTF-16 BE:
         *     char[] password       => [    0x0061,         0x0000    ]
         *                                   /    \          /    \
         * ByteBuffer passwordBytes  => [ 0x00,   0x61,   0x00,   0x00 ]
         *                                  |       |       |       |
         *     char[] encPassword    => [0x0000, 0x0061, 0x0000, 0x0000]
         *                                  |       |       |       |
         *     PKCS #11 call (bytes) => [ 0x00,   0x61,   0x00,   0x00 ]
         */
        ByteBuffer passwordBytes = cs.encode(CharBuffer.wrap(password));
        char[] encPassword =
                new char[passwordBytes.remaining() + nullTermBytes];
        int i = 0;
        while (passwordBytes.hasRemaining()) {
            encPassword[i] = (char) (passwordBytes.get() & 0xFF);
            // Erase password bytes as we read during encoding.
            passwordBytes.put(i++, (byte) 0);
        }
        return encPassword;
    }

    static byte[] convert(byte[] input, int offset, int len) {
        if ((offset == 0) && (len == input.length)) {
            return input;
        } else {
            byte[] t = new byte[len];
            System.arraycopy(input, offset, t, 0, len);
            return t;
        }
    }

    static byte[] subarray(byte[] b, int ofs, int len) {
        byte[] out = new byte[len];
        System.arraycopy(b, ofs, out, 0, len);
        return out;
    }

    static byte[] concat(byte[] b1, byte[] b2) {
        byte[] b = new byte[b1.length + b2.length];
        System.arraycopy(b1, 0, b, 0, b1.length);
        System.arraycopy(b2, 0, b, b1.length, b2.length);
        return b;
    }

    static long[] concat(long[] b1, long[] b2) {
        if (b1.length == 0) {
            return b2;
        }
        long[] b = new long[b1.length + b2.length];
        System.arraycopy(b1, 0, b, 0, b1.length);
        System.arraycopy(b2, 0, b, b1.length, b2.length);
        return b;
    }

    public static byte[] getMagnitude(BigInteger bi) {
        byte[] b = bi.toByteArray();
        if ((b.length > 1) && (b[0] == 0)) {
            int n = b.length - 1;
            byte[] newarray = new byte[n];
            System.arraycopy(b, 1, newarray, 0, n);
            b = newarray;
        }
        return b;
    }

    static byte[] sha1(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            md.update(data);
            return md.digest();
        } catch (GeneralSecurityException e) {
            throw new ProviderException(e);
        }
    }

    private static final char[] hexDigits = "0123456789abcdef".toCharArray();

    static String toString(byte[] b) {
        if (b == null) {
            return "(null)";
        }
        StringBuilder sb = new StringBuilder(b.length * 3);
        for (int i = 0; i < b.length; i++) {
            int k = b[i] & 0xff;
            if (i != 0) {
                sb.append(':');
            }
            sb.append(hexDigits[k >>> 4]);
            sb.append(hexDigits[k & 0xf]);
        }
        return sb.toString();
    }

    // returns true if successfully cancelled
    static boolean trySessionCancel(Token token, Session session, long flags)
            throws ProviderException {
        if (token.p11.getVersion().major == 3) {
            try {
                token.p11.C_SessionCancel(session.id(), flags);
                return true;
            } catch (PKCS11Exception e) {
                // return false for CKR_OPERATION_CANCEL_FAILED, so callers
                // can cancel in the pre v3.0 way, i.e. by finishing off the
                // current operation
                if (!e.match(CKR_OPERATION_CANCEL_FAILED)) {
                    throw new ProviderException("cancel failed", e);
                }
            }
        }
        return false;
    }
}

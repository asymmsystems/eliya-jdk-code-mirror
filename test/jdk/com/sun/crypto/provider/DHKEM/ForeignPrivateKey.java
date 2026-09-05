/*
 * Copyright (c) 2026, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2026, Asymm Systems (Pvt) Ltd.
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
 */

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.util.Arrays;

import javax.crypto.KEM;
import javax.crypto.SecretKey;

/*
 * @test
 * @summary DHKEM has to derive a public key from a private key, which JCA
 *          exposes no API for. It does so by translating the key until it
 *          gets one that can derive its public half. A private key that is
 *          not one of the JDK's own key classes must still work.
 * @run main ForeignPrivateKey
 */
public class ForeignPrivateKey {

    /*
     * An EC private key that is not one of the JDK's own key classes, so it
     * does not implement sun.security.util.InternalPrivateKey and cannot
     * derive its own public half. DHKEM.paramsFromKey requires an ECKey, so
     * this has to implement ECPrivateKey rather than plain PrivateKey.
     */
    private static PrivateKey foreign(ECPrivateKey delegate, byte[] encoded) {
        return new ECPrivateKey() {
            private static final long serialVersionUID = 1L;

            @Override
            public String getAlgorithm() {
                return "EC";
            }
            @Override
            public String getFormat() {
                return "PKCS#8";
            }
            @Override
            public byte[] getEncoded() {
                return encoded.clone();
            }
            @Override
            public BigInteger getS() {
                return delegate.getS();
            }
            @Override
            public ECParameterSpec getParams() {
                return delegate.getParams();
            }
        };
    }

    public static void main(String[] args) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = kpg.generateKeyPair();

        PrivateKey stranger = foreign((ECPrivateKey) kp.getPrivate(),
                kp.getPrivate().getEncoded());

        KEM kem = KEM.getInstance("DHKEM");
        KEM.Encapsulated encapsulated =
                kem.newEncapsulator(kp.getPublic()).encapsulate();

        SecretKey fromOwnKey = kem.newDecapsulator(kp.getPrivate())
                .decapsulate(encapsulated.encapsulation());
        SecretKey fromForeignKey = kem.newDecapsulator(stranger)
                .decapsulate(encapsulated.encapsulation());

        if (!Arrays.equals(fromOwnKey.getEncoded(),
                fromForeignKey.getEncoded())) {
            throw new Exception("Shared secrets differ between a JDK private "
                    + "key and an equivalent foreign one");
        }
        System.out.println("Passed");
    }
}

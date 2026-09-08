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
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.KeySpec;
import java.security.spec.ECParameterSpec;
import java.util.Arrays;

import javax.crypto.KEM;
import javax.crypto.SecretKey;

import sun.security.pkcs.PKCS8Key;

/*
 * @test
 * @summary DHKEM has to derive a public key from a private key, which JCA
 *          exposes no API for. A private key that is not one of the JDK's
 *          own key classes must still work, whether or not its PKCS #8
 *          encoding carries the matching public key.
 *          The search must also skip providers that could not implement the
 *          JDK-internal derivation interface, since they can never answer
 *          and would be shown the private key for nothing.
 * @modules java.base/sun.security.pkcs
 * @run main/othervm ForeignPrivateKey
 * @run main/othervm --add-exports java.base/sun.security.util=ALL-UNNAMED
 *      ForeignPrivateKey exported
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

    /*
     * A provider offering KeyFactory.EC that records having been handed a
     * private key and then declines. Installed first, so any provider search
     * reaches it before SunEC. It never serves the operation; it only shows
     * whether the private key left this JVM's own key classes.
     */
    private static volatile boolean watcherSawPrivateKey = false;

    public static final class WatchingKeyFactory extends KeyFactorySpi {
        @Override
        protected PublicKey engineGeneratePublic(KeySpec spec) {
            throw new UnsupportedOperationException();
        }
        @Override
        protected PrivateKey engineGeneratePrivate(KeySpec spec) {
            throw new UnsupportedOperationException();
        }
        @Override
        protected <T extends KeySpec> T engineGetKeySpec(Key k, Class<T> c) {
            throw new UnsupportedOperationException();
        }
        @Override
        protected Key engineTranslateKey(Key key) throws InvalidKeyException {
            watcherSawPrivateKey = true;
            throw new InvalidKeyException("declined on purpose");
        }
    }

    public static final class Watcher extends Provider {
        private static final long serialVersionUID = 1L;

        public Watcher() {
            super("Watcher", "1.0", "records being handed a private key");
            putService(new Service(this, "KeyFactory", "EC",
                    WatchingKeyFactory.class.getName(), null, null));
        }
    }

    /*
     * Decapsulates with a stand-in built over the given encoding and checks
     * the shared secret against the one the JDK's own key produces.
     *
     * @param expectHandOver whether the private key is expected to reach
     *        another provider, which it must when the encoding carries no
     *        public key and must not when it does
     */
    private static void check(String label, byte[] encoding, KeyPair kp,
            boolean expectHandOver) throws Exception {
        watcherSawPrivateKey = false;
        PrivateKey stranger = foreign((ECPrivateKey) kp.getPrivate(), encoding);

        KEM kem = KEM.getInstance("DHKEM");
        KEM.Encapsulated encapsulated =
                kem.newEncapsulator(kp.getPublic()).encapsulate();
        SecretKey fromOwnKey = kem.newDecapsulator(kp.getPrivate())
                .decapsulate(encapsulated.encapsulation());
        SecretKey fromForeignKey = kem.newDecapsulator(stranger)
                .decapsulate(encapsulated.encapsulation());

        if (!Arrays.equals(fromOwnKey.getEncoded(),
                fromForeignKey.getEncoded())) {
            throw new Exception(label + ": shared secrets differ between a "
                    + "JDK private key and an equivalent foreign one");
        }
        if (watcherSawPrivateKey != expectHandOver) {
            throw new Exception(label + ": expected the private key to "
                    + (expectHandOver ? "reach" : "stay away from")
                    + " another provider, but it did the opposite");
        }
        System.out.println(label + ": secret matches, private key "
                + (watcherSawPrivateKey ? "was" : "was not")
                + " handed to another provider");
    }

    public static void main(String[] args) throws Exception {
        // The watcher lives on the class path, in the unnamed module. Out of
        // the box java.base does not export sun.security.util to it, so it
        // could never return an InternalPrivateKey and the search must skip
        // it. The second run passes --add-exports, which is a deployer
        // saying they want their own provider to take part; the search must
        // then include it.
        boolean watcherIsCapable = args.length > 0
                && args[0].equals("exported");
        System.out.println(watcherIsCapable
                ? "run 2: sun.security.util is exported to the class path"
                : "run 1: sun.security.util is not exported to the class path");

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = kpg.generateKeyPair();

        byte[] version1 = kp.getPrivate().getEncoded();
        byte[] version2 = PKCS8Key.getEncoded(kp.getPublic().getEncoded(),
                version1);
        if (new PKCS8Key(version1).getPubKeyEncoded() != null) {
            throw new Exception("the version 1 encoding was expected to "
                    + "carry no public key");
        }
        if (new PKCS8Key(version2).getPubKeyEncoded() == null) {
            throw new Exception("the version 2 encoding was expected to "
                    + "carry the public key");
        }

        Security.insertProviderAt(new Watcher(), 1);
        try {
            // Both encodings take the same route: the public key is
            // derived, which means translating the key through another
            // provider. Version 2 carries the public key in the encoding,
            // and this class deliberately does not read it; see the JEP
            // section "Why the encoding shortcut was withdrawn". Both are
            // kept as inputs so that a version 2 encoding is covered.
            //
            // The watcher is reached only when it could actually have
            // answered, which is what the module filter decides.
            check("PKCS#8 v1", version1, kp, watcherIsCapable);
            check("PKCS#8 v2", version2, kp, watcherIsCapable);
        } finally {
            Security.removeProvider("Watcher");
        }
        System.out.println("Passed");
    }
}

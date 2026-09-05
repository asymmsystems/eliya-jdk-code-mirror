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

import java.security.AlgorithmParameters;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/*
 * @test
 * @summary SunPKCS11 delegates to another provider in several places. Each
 *          such site must look up the JCA service type it is about to use.
 *          A site that looks up one service type and uses another works on
 *          the default provider list, where SunJCE offers everything
 *          involved, and selects an unusable provider on any other list.
 * @library /test/lib ..
 * @modules jdk.crypto.cryptoki
 * @run main/othervm CapabilityLookupMatchesUse
 */
public class CapabilityLookupMatchesUse extends PKCS11Test {

    /*
     * Registers KeyFactory.DH and nothing else, ahead of every other
     * provider. Any SunPKCS11 site that looks up KeyFactory.DH and then asks
     * the winner for a different service selects this provider and fails.
     * A site that looks up the service it actually uses skips it, because it
     * offers nothing else.
     *
     * The implementation class name is deliberately not loadable. Nothing
     * should ever construct a service from this provider.
     */
    private static final class OnlyKeyFactoryDH extends Provider {
        private static final long serialVersionUID = 1L;

        OnlyKeyFactoryDH() {
            super("OnlyKeyFactoryDH", "1.0",
                    "offers KeyFactory.DH and no other service");
            putService(new Service(this, "KeyFactory", "DH",
                    "CapabilityLookupMatchesUse$Unusable", null, null));
        }
    }

    private static final char[] PASSWORD = "password".toCharArray();

    /*
     * Cipher.getParameters on a PKCS #11 PBE cipher reaches
     * P11PBECipher.engineGetParameters, which hands a provider to
     * sun.security.util.PBEUtil. PBEUtil calls
     * AlgorithmParameters.getInstance(pbeAlg, provider) and converts a
     * NoSuchAlgorithmException into an unchecked exception, so a provider
     * chosen for the wrong service type surfaces as a RuntimeException out
     * of a method that declares none.
     */
    private static void testPbeCipherParameters(Provider p11)
            throws Exception {
        String alg = "PBEWithHmacSHA256AndAES_128";
        if (p11.getService("Cipher", alg) == null) {
            System.out.println("skip: token has no Cipher." + alg);
            return;
        }
        SecretKey key = SecretKeyFactory.getInstance("PBE")
                .generateSecret(new PBEKeySpec(PASSWORD));
        Cipher c = Cipher.getInstance(alg, p11);
        c.init(Cipher.ENCRYPT_MODE, key);
        AlgorithmParameters params = c.getParameters();
        if (params == null) {
            throw new Exception("no AlgorithmParameters returned");
        }
        System.out.println("PBE cipher parameters from "
                + params.getProvider().getName());
    }

    /*
     * doPhase with lastPhase false takes the multi-party branch of
     * P11KeyAgreement.engineDoPhase, which builds a KeyAgreement from
     * another provider. Two-party agreement never reaches it, which is why
     * the rest of the SunPKCS11 test tree does not cover this branch.
     */
    private static void testMultiPartyKeyAgreement(Provider p11)
            throws Exception {
        if (p11.getService("KeyAgreement", "DH") == null) {
            System.out.println("skip: token has no KeyAgreement.DH");
            return;
        }
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH", p11);
        kpg.initialize(2048);
        KeyPair a = kpg.generateKeyPair();
        KeyPair b = kpg.generateKeyPair();

        KeyAgreement ka = KeyAgreement.getInstance("DH", p11);
        ka.init(a.getPrivate());
        ka.doPhase(b.getPublic(), false);
        System.out.println("multi-party key agreement initialised");
    }

    public static void main(String[] args) throws Exception {
        main(new CapabilityLookupMatchesUse(), args);
    }

    @Override
    public void main(Provider p11) throws Exception {
        Security.insertProviderAt(new OnlyKeyFactoryDH(), 1);
        try {
            testPbeCipherParameters(p11);
            testMultiPartyKeyAgreement(p11);
        } finally {
            Security.removeProvider("OnlyKeyFactoryDH");
        }
        System.out.println("All tests passed");
    }
}

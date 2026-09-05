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
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

/*
 * @test
 * @summary A raw public key cannot be imported into CNG, so SunMSCAPI's
 *          RSASSA-PSS verification falls back to another provider. That
 *          fallback must find whichever provider offers RSASSA-PSS rather
 *          than one named provider, and must never select SunMSCAPI itself,
 *          which registers RSASSA-PSS pointing at the class doing the lookup.
 * @requires os.family == "windows"
 * @run main/othervm PssFallbackWithoutSunRsaSign
 */
public class PssFallbackWithoutSunRsaSign {

    private static final PSSParameterSpec PSS = new PSSParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32,
            PSSParameterSpec.TRAILER_FIELD_BC);

    private static final byte[] MESSAGE = "fallback".getBytes();

    /*
     * A working RSASSA-PSS implementation that is neither SunRsaSign nor
     * SunMSCAPI, so the fallback has to reach it by capability rather than
     * by name. It delegates to a Provider instance captured before that
     * provider was removed from the installed list: removing a provider
     * from the list does not stop an already-held reference from working.
     */
    public static final class DelegatingPss extends SignatureSpi {
        static volatile Provider delegate;
        static volatile int instantiations;

        private final Signature real;

        public DelegatingPss() {
            instantiations++;
            try {
                real = Signature.getInstance("RSASSA-PSS", delegate);
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException(e);
            }
        }
        @Override
        protected void engineInitVerify(PublicKey k) throws InvalidKeyException {
            real.initVerify(k);
        }
        @Override
        protected void engineInitSign(PrivateKey k) throws InvalidKeyException {
            real.initSign(k);
        }
        @Override
        protected void engineUpdate(byte b) throws SignatureException {
            real.update(b);
        }
        @Override
        protected void engineUpdate(byte[] b, int off, int len)
                throws SignatureException {
            real.update(b, off, len);
        }
        @Override
        protected byte[] engineSign() throws SignatureException {
            return real.sign();
        }
        @Override
        protected boolean engineVerify(byte[] sig) throws SignatureException {
            return real.verify(sig);
        }
        @Override
        @Deprecated
        protected void engineSetParameter(String p, Object v) {
            throw new UnsupportedOperationException();
        }
        @Override
        @Deprecated
        protected Object engineGetParameter(String p) {
            throw new UnsupportedOperationException();
        }
        @Override
        protected void engineSetParameter(AlgorithmParameterSpec p)
                throws InvalidAlgorithmParameterException {
            real.setParameter(p);
        }
        @Override
        protected AlgorithmParameters engineGetParameters() {
            return real.getParameters();
        }
    }

    public static final class AltPss extends Provider {
        private static final long serialVersionUID = 1L;

        public AltPss() {
            super("AltPss", "1.0",
                    "RSASSA-PSS delegating to a captured provider");
            putService(new Service(this, "Signature", "RSASSA-PSS",
                    DelegatingPss.class.getName(), null, null));
        }
    }

    public static void main(String[] args) throws Exception {
        Provider sunRsaSign = Security.getProvider("SunRsaSign");
        if (sunRsaSign == null) {
            throw new Exception("SunRsaSign is not installed");
        }
        if (Security.getProvider("SunMSCAPI") == null) {
            throw new Exception("SunMSCAPI is not installed");
        }
        DelegatingPss.delegate = sunRsaSign;

        // A key pair that SunMSCAPI did not produce. Its public key is not a
        // CPublicKey, which is what sends engineInitVerify down the fallback.
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", sunRsaSign);
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        Signature signer = Signature.getInstance("RSASSA-PSS", sunRsaSign);
        signer.setParameter(PSS);
        signer.initSign(kp.getPrivate());
        signer.update(MESSAGE);
        byte[] sig = signer.sign();

        // Leave SunMSCAPI in place and take SunRsaSign out, so the only
        // provider the fallback may select is one it was never told about.
        Security.removeProvider("SunRsaSign");
        Security.insertProviderAt(new AltPss(), 1);
        try {
            Signature verifier =
                    Signature.getInstance("RSASSA-PSS", "SunMSCAPI");
            verifier.setParameter(PSS);
            verifier.initVerify(kp.getPublic());
            verifier.update(MESSAGE);
            boolean verified = verifier.verify(sig);
            if (!verified) {
                throw new Exception("signature did not verify through the "
                        + "substitute provider");
            }
            if (DelegatingPss.instantiations == 0) {
                throw new Exception("the fallback did not use the substitute "
                        + "provider, so this test proved nothing");
            }
            System.out.println("Verified through AltPss, "
                    + DelegatingPss.instantiations + " instantiation(s)");
        } finally {
            Security.removeProvider("AltPss");
            Security.addProvider(sunRsaSign);
        }
        System.out.println("Passed");
    }
}

/*
 * Copyright (c) 2023, 2025, Oracle and/or its affiliates. All rights reserved.
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
package com.sun.crypto.provider;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.XECKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.HKDFParameterSpec;

import sun.security.jca.JCAUtil;
import sun.security.pkcs.PKCS8Key;
import sun.security.util.*;

import jdk.internal.access.SharedSecrets;

// Implementing DHKEM defined inside https://www.rfc-editor.org/rfc/rfc9180.html,
// without the AuthEncap and AuthDecap functions
public class DHKEM implements KEMSpi {

    private static final byte[] KEM = new byte[]
            {'K', 'E', 'M'};
    private static final byte[] EAE_PRK = new byte[]
            {'e', 'a', 'e', '_', 'p', 'r', 'k'};
    private static final byte[] SHARED_SECRET = new byte[]
            {'s', 'h', 'a', 'r', 'e', 'd', '_', 's', 'e', 'c', 'r', 'e', 't'};
    private static final byte[] DKP_PRK = new byte[]
            {'d', 'k', 'p', '_', 'p', 'r', 'k'};
    private static final byte[] CANDIDATE = new byte[]
            {'c', 'a', 'n', 'd', 'i', 'd', 'a', 't', 'e'};
    private static final byte[] SK = new byte[]
            {'s', 'k'};
    private static final byte[] HPKE_V1 = new byte[]
            {'H', 'P', 'K', 'E', '-', 'v', '1'};
    private static final byte[] EMPTY = new byte[0];

    private record Handler(Params params, SecureRandom secureRandom,
                           PrivateKey skR, PublicKey pkR)
                implements EncapsulatorSpi, DecapsulatorSpi {

        @Override
        public KEM.Encapsulated engineEncapsulate(int from, int to, String algorithm) {
            Objects.checkFromToIndex(from, to, params.Nsecret);
            Objects.requireNonNull(algorithm, "null algorithm");
            KeyPair kpE = params.generateKeyPair(secureRandom);
            PrivateKey skE = kpE.getPrivate();
            PublicKey pkE = kpE.getPublic();
            byte[] pkEm = params.SerializePublicKey(pkE);
            byte[] pkRm = params.SerializePublicKey(pkR);
            byte[] kem_context = concat(pkEm, pkRm);
            try {
                byte[] dh = params.DH(skE, pkR);
                byte[] key = params.ExtractAndExpand(dh, kem_context);
                return new KEM.Encapsulated(
                        new SecretKeySpec(key, from, to - from, algorithm),
                        pkEm, null);
            } catch (Exception e) {
                throw new ProviderException("internal error", e);
            }
        }

        @Override
        public SecretKey engineDecapsulate(byte[] encapsulation,
                int from, int to, String algorithm) throws DecapsulateException {
            Objects.checkFromToIndex(from, to, params.Nsecret);
            Objects.requireNonNull(algorithm, "null algorithm");
            Objects.requireNonNull(encapsulation, "null encapsulation");
            if (encapsulation.length != params.Npk) {
                throw new DecapsulateException("incorrect encapsulation size");
            }
            try {
                PublicKey pkE = params.DeserializePublicKey(encapsulation);
                byte[] dh = params.DH(skR, pkE);
                byte[] pkRm = params.SerializePublicKey(pkR);
                byte[] kem_context = concat(encapsulation, pkRm);
                byte[] key = params.ExtractAndExpand(dh, kem_context);
                return new SecretKeySpec(key, from, to - from, algorithm);
            } catch (IOException | InvalidKeyException e) {
                throw new DecapsulateException("Cannot decapsulate", e);
            } catch (Exception e) {
                throw new ProviderException("internal error", e);
            }
        }

        @Override
        public int engineSecretSize() {
            return params.Nsecret;
        }

        @Override
        public int engineEncapsulationSize() {
            return params.Npk;
        }
    }

    // Not really a random. For KAT test only. It generates key pair from ikm.
    public static class RFC9180DeriveKeyPairSR extends SecureRandom {

        static final long serialVersionUID = 0L;

        private final byte[] ikm;

        public RFC9180DeriveKeyPairSR(byte[] ikm) {
            super(null, null); // lightest constructor
            this.ikm = ikm;
        }

        public KeyPair derive(Params params) {
            try {
                return params.deriveKeyPair(ikm);
            } catch (Exception e) {
                throw new UnsupportedOperationException(e);
            }
        }

        public KeyPair derive(int kem_id) {
            Params params = Arrays.stream(Params.values())
                    .filter(p -> p.kem_id == kem_id)
                    .findFirst()
                    .orElseThrow();
            return derive(params);
        }
    }

    private enum Params {

        P256(0x10, 32, 32, 2 * 32 + 1,
                "ECDH", "EC", CurveDB.P_256, "HKDF-SHA256"),

        P384(0x11, 48, 48, 2 * 48 + 1,
                "ECDH", "EC", CurveDB.P_384, "HKDF-SHA384"),

        P521(0x12, 64, 66, 2 * 66 + 1,
                "ECDH", "EC", CurveDB.P_521, "HKDF-SHA512"),

        X25519(0x20, 32, 32, 32,
                "XDH", "XDH", NamedParameterSpec.X25519, "HKDF-SHA256"),

        X448(0x21, 64, 56, 56,
                "XDH", "XDH", NamedParameterSpec.X448, "HKDF-SHA512"),
        ;

        private final int kem_id;
        private final int Nsecret;
        private final int Nsk;
        private final int Npk;
        private final String kaAlgorithm;
        private final String keyAlgorithm;
        private final AlgorithmParameterSpec spec;
        private final String hkdfAlgorithm;

        private final byte[] suiteId;

        Params(int kem_id, int Nsecret, int Nsk, int Npk,
                String kaAlgorithm, String keyAlgorithm, AlgorithmParameterSpec spec,
                String hkdfAlgorithm) {
            this.kem_id = kem_id;
            this.spec = spec;
            this.Nsecret = Nsecret;
            this.Nsk = Nsk;
            this.Npk = Npk;
            this.kaAlgorithm = kaAlgorithm;
            this.keyAlgorithm = keyAlgorithm;
            this.hkdfAlgorithm = hkdfAlgorithm;
            suiteId = concat(KEM, I2OSP(kem_id, 2));
        }

        private boolean isEC() {
            return this == P256 || this == P384 || this == P521;
        }

        private KeyPair generateKeyPair(SecureRandom sr) {
            if (sr instanceof RFC9180DeriveKeyPairSR r9) {
                return r9.derive(this);
            }
            try {
                KeyPairGenerator g = KeyPairGenerator.getInstance(keyAlgorithm);
                g.initialize(spec, sr);
                return g.generateKeyPair();
            } catch (Exception e) {
                throw new ProviderException("internal error", e);
            }
        }

        private byte[] SerializePublicKey(PublicKey k) {
            if (isEC()) {
                ECPoint w = ((ECPublicKey) k).getW();
                return ECUtil.encodePoint(w, ((NamedCurve) spec).getCurve());
            } else {
                byte[] uArray = ((XECPublicKey) k).getU().toByteArray();
                ArrayUtil.reverse(uArray);
                return Arrays.copyOf(uArray, Npk);
            }
        }

        private PublicKey DeserializePublicKey(byte[] data)
                throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
            KeySpec keySpec;
            if (isEC()) {
                NamedCurve curve = (NamedCurve) this.spec;
                keySpec = new ECPublicKeySpec(
                        ECUtil.decodePoint(data, curve.getCurve()), curve);
            } else {
                data = data.clone();
                ArrayUtil.reverse(data);
                keySpec = new XECPublicKeySpec(
                        this.spec, new BigInteger(1, data));
            }
            return KeyFactory.getInstance(keyAlgorithm).generatePublic(keySpec);
        }

        private byte[] DH(PrivateKey skE, PublicKey pkR)
                throws NoSuchAlgorithmException, InvalidKeyException {
            KeyAgreement ka = KeyAgreement.getInstance(kaAlgorithm);
            ka.init(skE);
            ka.doPhase(pkR, true);
            return ka.generateSecret();
        }

        private byte[] ExtractAndExpand(byte[] dh, byte[] kem_context)
                throws NoSuchAlgorithmException, InvalidKeyException {
            KDF hkdf = KDF.getInstance(hkdfAlgorithm);
            SecretKey eae_prk = LabeledExtract(hkdf, suiteId, EAE_PRK, dh);
            try {
                return LabeledExpand(hkdf, suiteId, eae_prk, SHARED_SECRET,
                        kem_context, Nsecret);
            } finally {
                if (eae_prk instanceof SecretKeySpec s) {
                    SharedSecrets.getJavaxCryptoSpecAccess()
                            .clearSecretKeySpec(s);
                }
            }
        }

        private PublicKey getPublicKey(PrivateKey sk)
                throws InvalidKeyException {
            if (sk instanceof InternalPrivateKey ik) {
                return derivePublicKey(ik);
            }
            // The answer may already be in the key's own encoding, in which
            // case nothing has to derive it and no other provider is
            // involved at all. Only worth trying for a key this class did
            // not get as an InternalPrivateKey, which is why it sits after
            // the check above.
            PublicKey embedded = publicKeyFromEncoding(sk);
            if (embedded != null) {
                return embedded;
            }
            return derivePublicKey(translateToInternalKey(sk));
        }

        /*
         * Returns the public key carried inside the private key's own
         * encoding, or null if it does not carry one.
         *
         * A PKCS #8 encoding has two versions. Version 1 holds the private
         * key alone. Version 2 may also hold the matching public key, in an
         * optional field, in the same structure. When it does, deriving
         * anything is unnecessary: the public key is already there, and
         * reading it is DER decoding inside this module, so the private key
         * is never handed to another provider.
         *
         * The public key that comes back is built through an unqualified
         * KeyFactory lookup, which is what DeserializePublicKey in this
         * class already does. That call receives a public key and nothing
         * secret.
         *
         * The embedded value is used as given, not checked against the
         * private key, since checking it would mean deriving the public key,
         * which is the work being avoided. RFC 5958 requires the field, when
         * present, to correspond to the private key.
         *
         * This does change behaviour: an encoding whose embedded public key
         * does not correspond used to produce the derived, correct key and
         * now produces the stated, wrong one, so the shared secret differs
         * and the peer cannot decrypt. It fails closed rather than silently
         * agreeing on something an attacker chose. DH() is computed from the
         * real private key and the sender's ephemeral public key, so a wrong
         * value here reaches only kem_context, a KDF input, and never enters
         * point arithmetic. AuthEncap and AuthDecap, the modes where a
         * public key carries authentication weight, are not implemented in
         * this class.
         *
         * It is also not a new trust boundary. The private key and the
         * embedded public key are one DER structure from one source, so
         * anyone able to choose the second can choose the first. And the
         * alternative for a key in this position is not safe derivation, it
         * is handing the caller's private key to another provider, which is
         * the larger exposure of the two.
         *
         * Any problem reading it returns null and leaves the caller to the
         * provider search, which reports a proper diagnostic. This is an
         * optimisation, not the authority on whether the key is usable.
         */
        private PublicKey publicKeyFromEncoding(PrivateKey sk) {
            if (!"PKCS#8".equalsIgnoreCase(sk.getFormat())) {
                return null;
            }
            byte[] encoded = sk.getEncoded();
            if (encoded == null) {
                return null;
            }
            try {
                byte[] publicKeyEncoded =
                        new PKCS8Key(encoded).getPubKeyEncoded();
                if (publicKeyEncoded == null) {
                    return null;
                }
                return KeyFactory.getInstance(keyAlgorithm).generatePublic(
                        new X509EncodedKeySpec(publicKeyEncoded));
            } catch (InvalidKeyException | NoSuchAlgorithmException
                    | InvalidKeySpecException e) {
                return null;
            }
        }

        /*
         * Returns an equivalent key that can derive its own public half.
         *
         * JCA has no public API for deriving a public key from a private
         * one. The JDK does it through sun.security.util.InternalPrivateKey,
         * which only the JDK's own key classes implement, so the requirement
         * at this call is not "give me SunEC" but "give me a KeyFactory whose
         * keys can derive their public half". Ask each registered provider in
         * turn rather than naming one. On a stock JDK the first provider that
         * answers is SunEC, which is what the previous hardcoded lookup asked
         * for by name.
         *
         * This does not make the site substitutable by a third-party
         * provider, and it is not meant to. InternalPrivateKey lives in
         * sun.security.util, which is exported only to a fixed list of jdk.*
         * modules, so a provider on the class path cannot implement it.
         * Lifting that limit needs a public API for the operation. One
         * placement, a method on java.security.PrivateKey, was proposed and
         * closed Won't Fix as JDK-8372538 on 2026-05-02; the objection
         * recorded there was to that placement rather than to the operation
         * itself. Either way it is upstream-owned and out of scope here.
         * What this does buy is that
         * the code states its actual requirement rather than one provider
         * that happens to meet it, and reports every reason it failed.
         */
        private InternalPrivateKey translateToInternalKey(PrivateKey sk)
                throws InvalidKeyException {
            // Two filters, and each removes providers for a different
            // reason.
            //
            // Offering the algorithm is the obvious one. Asking providers
            // that do not offer it collects a NoSuchAlgorithmException from
            // each, and on a stock JDK the first of those comes from SUN,
            // which would then be reported as the cause ahead of any real
            // failure.
            //
            // Being able to implement InternalPrivateKey is the one that
            // matters. The interface lives in sun.security.util, which
            // java.base exports to a fixed list of modules, so a provider
            // outside that list cannot return one however it is asked. Such
            // a provider can never answer, and every provider asked is shown
            // the caller's private key, so asking it would be exposure
            // bought for nothing.
            //
            // Reading the module graph rather than naming modules keeps this
            // true if the export list changes, and lets a deployer who has
            // opened the package with --add-exports have their own provider
            // take part.
            Module javaBase = InternalPrivateKey.class.getModule();
            List<Provider> capable = new ArrayList<>();
            Provider[] offering =
                    Security.getProviders("KeyFactory." + keyAlgorithm);
            if (offering != null) {
                for (Provider p : offering) {
                    if (javaBase.isExported("sun.security.util",
                            p.getClass().getModule())) {
                        capable.add(p);
                    }
                }
            }
            if (capable.isEmpty()) {
                throw new InvalidKeyException("Error translating key",
                        new NoSuchAlgorithmException("no provider able to "
                                + "derive a public key offers KeyFactory."
                                + keyAlgorithm));
            }

            List<Exception> failures = new ArrayList<>();
            for (Provider p : capable) {
                try {
                    Key k = KeyFactory.getInstance(keyAlgorithm, p)
                            .translateKey(sk);
                    if (k instanceof InternalPrivateKey ik) {
                        return ik;
                    }
                } catch (InvalidKeyException | NoSuchAlgorithmException
                        | RuntimeException e) {
                    // InvalidKeyException: this provider offers the
                    // algorithm but cannot translate this key.
                    // RuntimeException: it is broken. Walking a list means
                    // one broken provider must not end the search, which a
                    // single hardcoded lookup never had to consider.
                    failures.add(e);
                }
            }
            if (failures.isEmpty()) {
                // Every candidate translated the key and none returned one
                // that can derive its public half. That is an installation
                // problem rather than a problem with the key, and it is the
                // case this method has always reported this way.
                throw new ProviderException("Unknown key");
            }
            // Report all of them. The first is the cause, so getCause()
            // stays non-null as it was when one hardcoded provider failed,
            // and the rest are suppressed. Every entry here is a provider
            // that could have answered and did not, so the first is a real
            // answer rather than an artefact of ordering.
            InvalidKeyException failure = new InvalidKeyException(
                    "Error translating key", failures.get(0));
            for (int i = 1; i < failures.size(); i++) {
                failure.addSuppressed(failures.get(i));
            }
            throw failure;
        }

        private static PublicKey derivePublicKey(InternalPrivateKey ik)
                throws InvalidKeyException {
            try {
                return ik.calculatePublicKey();
            } catch (UnsupportedOperationException e) {
                throw new InvalidKeyException("Error retrieving key", e);
            }
        }

        // For KAT tests only. See RFC9180DeriveKeyPairSR.
        public KeyPair deriveKeyPair(byte[] ikm) throws Exception {
            KDF hkdf = KDF.getInstance(hkdfAlgorithm);
            SecretKey dkp_prk = LabeledExtract(hkdf, suiteId, DKP_PRK, ikm);
            try {
                if (isEC()) {
                    NamedCurve curve = (NamedCurve) spec;
                    BigInteger sk = BigInteger.ZERO;
                    int counter = 0;
                    while (sk.signum() == 0 ||
                            sk.compareTo(curve.getOrder()) >= 0) {
                        if (counter > 255) {
                            throw new RuntimeException();
                        }
                        byte[] bytes = LabeledExpand(hkdf, suiteId, dkp_prk,
                                CANDIDATE, I2OSP(counter, 1), Nsk);
                        // bitmask is defined to be 0xFF for P-256 and P-384,
                        // and 0x01 for P-521
                        if (this == Params.P521) {
                            bytes[0] = (byte) (bytes[0] & 0x01);
                        }
                        sk = new BigInteger(1, (bytes));
                        counter = counter + 1;
                    }
                    PrivateKey k = DeserializePrivateKey(sk.toByteArray());
                    return new KeyPair(getPublicKey(k), k);
                } else {
                    byte[] sk = LabeledExpand(hkdf, suiteId, dkp_prk, SK, EMPTY,
                            Nsk);
                    PrivateKey k = DeserializePrivateKey(sk);
                    return new KeyPair(getPublicKey(k), k);
                }
            } finally {
                if (dkp_prk instanceof SecretKeySpec s) {
                    SharedSecrets.getJavaxCryptoSpecAccess()
                            .clearSecretKeySpec(s);
                }
            }
        }

        private PrivateKey DeserializePrivateKey(byte[] data) throws Exception {
            KeySpec keySpec = isEC()
                    ? new ECPrivateKeySpec(new BigInteger(1, (data)), (NamedCurve) spec)
                    : new XECPrivateKeySpec(spec, data);
            return KeyFactory.getInstance(keyAlgorithm).generatePrivate(keySpec);
        }
    }

    private static SecureRandom getSecureRandom(SecureRandom userSR) {
        return userSR != null ? userSR : JCAUtil.getSecureRandom();
    }

    @Override
    public EncapsulatorSpi engineNewEncapsulator(
            PublicKey pk, AlgorithmParameterSpec spec, SecureRandom secureRandom)
            throws InvalidAlgorithmParameterException, InvalidKeyException {
        if (pk == null) {
            throw new InvalidKeyException("input key is null");
        }
        if (spec != null) {
            throw new InvalidAlgorithmParameterException("no spec needed");
        }
        Params params = paramsFromKey(pk);
        return new Handler(params, getSecureRandom(secureRandom), null, pk);
    }

    @Override
    public DecapsulatorSpi engineNewDecapsulator(PrivateKey sk, AlgorithmParameterSpec spec)
            throws InvalidAlgorithmParameterException, InvalidKeyException {
        if (sk == null) {
            throw new InvalidKeyException("input key is null");
        }
        if (spec != null) {
            throw new InvalidAlgorithmParameterException("no spec needed");
        }
        Params params = paramsFromKey(sk);
        return new Handler(params, null, sk, params.getPublicKey(sk));
    }

    private Params paramsFromKey(Key k) throws InvalidKeyException {
        if (k instanceof ECKey eckey) {
            if (ECUtil.equals(eckey.getParams(), CurveDB.P_256)) {
                return Params.P256;
            } else if (ECUtil.equals(eckey.getParams(), CurveDB.P_384)) {
                return Params.P384;
            } else if (ECUtil.equals(eckey.getParams(), CurveDB.P_521)) {
                return Params.P521;
            }
        } else if (k instanceof XECKey xkey
                && xkey.getParams() instanceof NamedParameterSpec ns) {
            if (ns.getName().equalsIgnoreCase("X25519")) {
                return Params.X25519;
            } else if (ns.getName().equalsIgnoreCase("X448")) {
                return Params.X448;
            }
        }
        throw new InvalidKeyException("Unsupported key");
    }

    private static byte[] concat(byte[]... inputs) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        Arrays.stream(inputs).forEach(o::writeBytes);
        return o.toByteArray();
    }

    private static byte[] I2OSP(int n, int w) {
        assert n < 256;
        assert w == 1 || w == 2;
        if (w == 1) {
            return new byte[] { (byte) n };
        } else {
            return new byte[] { (byte) (n >> 8), (byte) n };
        }
    }

    private static SecretKey LabeledExtract(KDF hkdf, byte[] suite_id,
            byte[] label, byte[] ikm) throws InvalidKeyException {
        SecretKeySpec s = new SecretKeySpec(concat(HPKE_V1, suite_id, label,
                ikm), "IKM");
        try {
            HKDFParameterSpec spec =
                    HKDFParameterSpec.ofExtract().addIKM(s).extractOnly();
            return hkdf.deriveKey("Generic", spec);
        } catch (InvalidAlgorithmParameterException |
                 NoSuchAlgorithmException e) {
            throw new InvalidKeyException(e.getMessage(), e);
        } finally {
            SharedSecrets.getJavaxCryptoSpecAccess().clearSecretKeySpec(s);
        }
    }

    private static byte[] LabeledExpand(KDF hkdf, byte[] suite_id,
            SecretKey prk, byte[] label, byte[] info, int L)
            throws InvalidKeyException {
        byte[] labeled_info = concat(I2OSP(L, 2), HPKE_V1, suite_id, label,
                info);
        try {
            return hkdf.deriveData(HKDFParameterSpec.expandOnly(
                    prk, labeled_info, L));
        } catch (InvalidAlgorithmParameterException iape) {
            throw new InvalidKeyException(iape.getMessage(), iape);
        }
    }
}

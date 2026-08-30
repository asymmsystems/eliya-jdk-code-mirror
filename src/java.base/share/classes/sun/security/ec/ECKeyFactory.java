/*
 * Copyright (c) 2006, 2025, Oracle and/or its affiliates. All rights reserved.
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

package sun.security.ec;

import sun.security.pkcs.PKCS8Key;

import java.security.*;
import java.security.interfaces.*;
import java.security.spec.*;
import java.util.Arrays;

/**
 * KeyFactory for EC keys. Keys must be instances of PublicKey or PrivateKey
 * and getAlgorithm() must return "EC". For such keys, it supports conversion
 * between the following:
 *
 * For public keys:
 *  . PublicKey with an X.509 encoding
 *  . ECPublicKey
 *  . ECPublicKeySpec
 *  . X509EncodedKeySpec
 *
 * For private keys:
 *  . PrivateKey with a PKCS#8 encoding
 *  . ECPrivateKey
 *  . ECPrivateKeySpec
 *  . PKCS8EncodedKeySpec
 *
 * @since   1.6
 * @author  Andreas Sterbenz
 */
public final class ECKeyFactory extends KeyFactorySpi {

    // Singleton used by toECKey() for direct SunEC-native key translation.
    //
    // This class lives INSIDE the SunEC provider package (sun.security.ec)
    // and IS SunEC's EC KeyFactory implementation. Pre-JEP-D, the code
    // routed through KeyFactory.getInstance("EC", "SunEC") to get a JCA
    // KeyFactory wrapper around this same SPI. That was a self-lookup via
    // JCA - unnecessary overhead when SunEC-internal code (toECKey below)
    // is calling SunEC-internal translation.
    //
    // JEP-D fix per CA direction 2026-08-30: skip the JCA lookup entirely
    // and call engineTranslateKey() directly on a same-class singleton.
    // Same-class access to the protected engineTranslateKey() method is
    // permitted; no reflection, no unnecessary JCA wrapper, no dependency
    // on the SunEC name string.
    //
    // Trade-off: KeyFactory.translateKey() loops through all registered
    // EC KeyFactories via nextSpi() when one throws; direct engine
    // TranslateKey() has no such fallback. This is semantically preferred
    // for toECKey() because the method's contract is "translate to a Sun
    // key" (per the toECKey Javadoc). Loop-through would give back a
    // foreign-provider ECKey instead of a SunEC-native ECPublicKeyImpl /
    // ECPrivateKeyImpl - contradicting toECKey's stated intent. If SunEC
    // cannot translate, failing loudly is the correct behavior.
    //
    // Toll on the "substitute provider" narrative: none. toECKey() is
    // called only from SunEC-internal ECDSA/ECDH code paths; those paths
    // only run when SunEC is providing the ECDSA/ECDH service. Under a
    // SunEC-source-removed variant, this class is not loaded at all.
    // The JCA-lookup indirection was never adding substitute-provider
    // value at this site - only cost.
    private static final ECKeyFactory INSTANCE = new ECKeyFactory();

    public ECKeyFactory() {
        // empty
    }

    /**
     * Static method to convert Key into a usable instance of
     * ECPublicKey or ECPrivateKey. Check the key and convert it
     * to a Sun key if necessary. If the key is not an EC key
     * or cannot be used, throw an InvalidKeyException.
     *
     * The difference between this method and engineTranslateKey() is that
     * we do not convert keys of other providers that are already an
     * instance of ECPublicKey or ECPrivateKey.
     *
     * To be used by future Java ECDSA and ECDH implementations.
     */
    public static ECKey toECKey(Key key) throws InvalidKeyException {
        if (key instanceof ECKey ecKey) {
            checkKey(ecKey);
            return ecKey;
        } else {
            // Direct call on SunEC's own translation SPI - same-class
            // access; no JCA wrapper overhead; SunEC-native output as
            // the toECKey javadoc contract requires. See INSTANCE
            // comment above for the design rationale.
            return (ECKey) INSTANCE.engineTranslateKey(key);
        }
    }

    /**
     * Check that the given EC key is valid.
     */
    private static void checkKey(ECKey key) throws InvalidKeyException {
        // check for subinterfaces, omit additional checks for our keys
        if (key instanceof ECPublicKey) {
            if (key instanceof ECPublicKeyImpl) {
                return;
            }
        } else if (key instanceof ECPrivateKey) {
            if (key instanceof ECPrivateKeyImpl) {
                return;
            }
        } else {
            throw new InvalidKeyException("Neither a public nor a private key");
        }
        // ECKey does not extend Key, so we need to do a cast
        String keyAlg = ((Key)key).getAlgorithm();
        if (keyAlg.equals("EC") == false) {
            throw new InvalidKeyException("Not an EC key: " + keyAlg);
        }
        // XXX further sanity checks about whether this key uses supported
        // fields, point formats, etc. would go here
    }

    /**
     * Translate an EC key into a Sun EC key. If conversion is
     * not possible, throw an InvalidKeyException.
     * See also JCA doc.
     */
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException("Key must not be null");
        }
        String keyAlg = key.getAlgorithm();
        if (keyAlg.equals("EC") == false) {
            throw new InvalidKeyException("Not an EC key: " + keyAlg);
        }
        if (key instanceof PublicKey) {
            return implTranslatePublicKey((PublicKey)key);
        } else if (key instanceof PrivateKey) {
            return implTranslatePrivateKey((PrivateKey)key);
        } else {
            throw new InvalidKeyException("Neither a public nor a private key");
        }
    }

    // see JCA doc
    protected PublicKey engineGeneratePublic(KeySpec keySpec)
        throws InvalidKeySpecException {
        try {
            return implGeneratePublic(keySpec);
        } catch (InvalidKeySpecException e) {
            throw e;
        } catch (GeneralSecurityException e) {
            throw new InvalidKeySpecException(e);
        }
    }

    // see JCA doc
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec)
        throws InvalidKeySpecException {
        try {
            return implGeneratePrivate(keySpec);
        } catch (InvalidKeySpecException e) {
            throw e;
        } catch (GeneralSecurityException e) {
            throw new InvalidKeySpecException(e);
        }
    }

    // internal implementation of translateKey() for public keys. See JCA doc
    private PublicKey implTranslatePublicKey(PublicKey key)
        throws InvalidKeyException {
        if (key instanceof ECPublicKeyImpl) {
            return key;
        } else if (key instanceof ECPublicKey ecKey) {
            return new ECPublicKeyImpl(ecKey.getW(), ecKey.getParams());
        } else if ("X.509".equals(key.getFormat())) {
            return new ECPublicKeyImpl(key.getEncoded());
        } else {
            throw new InvalidKeyException("Public keys must be instance "
                + "of ECPublicKey or have X.509 encoding");
        }
    }

    // internal implementation of translateKey() for private keys. See JCA doc
    private PrivateKey implTranslatePrivateKey(PrivateKey key)
        throws InvalidKeyException {
        if (key instanceof ECPrivateKeyImpl) {
            return key;
        } else if (key instanceof ECPrivateKey ecKey) {
            return new ECPrivateKeyImpl(ecKey.getS(), ecKey.getParams());
        } else if ("PKCS#8".equals(key.getFormat())) {
            byte[] encoded = key.getEncoded();
            try {
                return new ECPrivateKeyImpl(encoded);
            } finally {
                Arrays.fill(encoded, (byte)0);
            }
        }

        throw new InvalidKeyException("Private keys must be instance "
            + "of ECPrivateKey or have PKCS#8 encoding");
    }

    // internal implementation of generatePublic. See JCA doc
    private PublicKey implGeneratePublic(KeySpec keySpec)
        throws GeneralSecurityException {
        return switch (keySpec) {
            case X509EncodedKeySpec x -> new ECPublicKeyImpl(x.getEncoded());
            case ECPublicKeySpec e ->
                new ECPublicKeyImpl(e.getW(), e.getParams());
            case PKCS8EncodedKeySpec p8 -> {
                PKCS8Key p8key = new ECPrivateKeyImpl(p8.getEncoded());
                if (!p8key.hasPublicKey()) {
                    throw new InvalidKeySpecException("No public key found.");
                }
                yield new ECPublicKeyImpl(p8key.getPubKeyEncoded());
            }
            case null -> throw new InvalidKeySpecException(
                "keySpec must not be null");
            default ->
                throw new InvalidKeySpecException(keySpec.getClass().getName() +
                    " not supported.");
        };
    }

    // internal implementation of generatePrivate. See JCA doc
    private PrivateKey implGeneratePrivate(KeySpec keySpec)
        throws GeneralSecurityException {
        return switch (keySpec) {
            case PKCS8EncodedKeySpec p8 -> {
                byte[] encoded = p8.getEncoded();
                try {
                    yield new ECPrivateKeyImpl(encoded);
                } finally {
                    Arrays.fill(encoded, (byte) 0);
                }
            }
            case ECPrivateKeySpec e ->
                new ECPrivateKeyImpl(e.getS(), e.getParams());
            case null -> throw new InvalidKeySpecException(
                "keySpec must not be null");
            default ->
                throw new InvalidKeySpecException(keySpec.getClass().getName() +
                    " not supported.");
        };
    }

    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec)
        throws InvalidKeySpecException {
        try {
            // convert key to one of our keys
            // this also verifies that the key is a valid EC key and ensures
            // that the encoding is X.509/PKCS#8 for public/private keys
            key = engineTranslateKey(key);
        } catch (InvalidKeyException e) {
            throw new InvalidKeySpecException(e);
        }
        if (key instanceof ECPublicKey ecKey) {
            if (keySpec.isAssignableFrom(ECPublicKeySpec.class)) {
                return keySpec.cast(new ECPublicKeySpec(
                    ecKey.getW(),
                    ecKey.getParams()
                ));
            } else if (keySpec.isAssignableFrom(X509EncodedKeySpec.class)) {
                return keySpec.cast(new X509EncodedKeySpec(key.getEncoded()));
            } else {
                throw new InvalidKeySpecException
                        ("KeySpec must be ECPublicKeySpec or "
                        + "X509EncodedKeySpec for EC public keys");
            }
        } else if (key instanceof ECPrivateKey) {
            if (keySpec.isAssignableFrom(PKCS8EncodedKeySpec.class)) {
                byte[] encoded = key.getEncoded();
                try {
                    return keySpec.cast(new PKCS8EncodedKeySpec(encoded));
                } finally {
                    Arrays.fill(encoded, (byte)0);
                }
            } else if (keySpec.isAssignableFrom(ECPrivateKeySpec.class)) {
                ECPrivateKey ecKey = (ECPrivateKey)key;
                return keySpec.cast(new ECPrivateKeySpec(
                    ecKey.getS(),
                    ecKey.getParams()
                ));
            } else {
                throw new InvalidKeySpecException
                        ("KeySpec must be ECPrivateKeySpec or "
                        + "PKCS8EncodedKeySpec for EC private keys");
            }
        } else {
            // should not occur, caught in engineTranslateKey()
            throw new InvalidKeySpecException("Neither public nor private key");
        }
    }
}

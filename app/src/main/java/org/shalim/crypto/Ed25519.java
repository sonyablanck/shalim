package org.shalim.crypto;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.NamedParameterSpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Ed25519 signatures (RFC 8032) on the JDK provider. Public keys are passed
 * around as their 32 raw bytes.
 */
public final class Ed25519 {

    public static final int PUBLIC_KEY_BYTES = 32;
    public static final int SIGNATURE_BYTES = 64;

    /** DER SubjectPublicKeyInfo prefix for an Ed25519 key (OID 1.3.101.112). */
    private static final byte[] SPKI_PREFIX = Bytes.fromHex("302a300506032b6570032100");

    private Ed25519() {
    }

    public static KeyPair generate() {
        return generate(new SecureRandom());
    }

    /**
     * Rebuilds a key pair from its 32-byte RFC 8032 seed. The JDK has no
     * public API for deriving the public key from a private one, so the seed
     * is fed through the generator as its only randomness, which is exactly
     * how the generator uses it. The RFC 8032 test vectors check this.
     */
    public static KeyPair fromSeed(byte[] seed) {
        if (seed == null || seed.length != 32) {
            throw new CryptoException("Ed25519 seed must be 32 bytes");
        }
        return generate(new FixedRandom(seed));
    }

    private static KeyPair generate(SecureRandom random) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");
            generator.initialize(NamedParameterSpec.ED25519, random);
            return generator.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Ed25519 unavailable", e);
        }
    }

    public static byte[] rawPublicKey(PublicKey key) {
        byte[] encoded = key.getEncoded();
        if (encoded.length != SPKI_PREFIX.length + PUBLIC_KEY_BYTES) {
            throw new CryptoException("not an Ed25519 public key");
        }
        byte[] raw = new byte[PUBLIC_KEY_BYTES];
        System.arraycopy(encoded, SPKI_PREFIX.length, raw, 0, PUBLIC_KEY_BYTES);
        return raw;
    }

    public static PublicKey publicKeyFromRaw(byte[] raw) {
        if (raw == null || raw.length != PUBLIC_KEY_BYTES) {
            throw new CryptoException("Ed25519 public key must be 32 bytes");
        }
        try {
            return KeyFactory.getInstance("Ed25519")
                    .generatePublic(new X509EncodedKeySpec(Bytes.concat(SPKI_PREFIX, raw)));
        } catch (GeneralSecurityException e) {
            throw new CryptoException("malformed Ed25519 public key", e);
        }
    }

    public static byte[] sign(PrivateKey key, byte[] message) {
        try {
            Signature signature = Signature.getInstance("Ed25519");
            signature.initSign(key);
            signature.update(message);
            return signature.sign();
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Ed25519 signing failed", e);
        }
    }

    /** False for any malformed input, never an exception. */
    public static boolean verify(byte[] rawPublicKey, byte[] message, byte[] signature) {
        if (rawPublicKey == null || message == null || signature == null
                || rawPublicKey.length != PUBLIC_KEY_BYTES || signature.length != SIGNATURE_BYTES) {
            return false;
        }
        try {
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(publicKeyFromRaw(rawPublicKey));
            verifier.update(message);
            return verifier.verify(signature);
        } catch (GeneralSecurityException | CryptoException e) {
            return false;
        }
    }

    /** Hex-signature convenience for the record types that store signatures as text. */
    public static boolean verifyHex(byte[] rawPublicKey, byte[] message, String signatureHex) {
        if (signatureHex == null) {
            return false;
        }
        try {
            return verify(rawPublicKey, message, Bytes.fromHex(signatureHex));
        } catch (IllegalArgumentException malformed) {
            return false;
        }
    }

    /** Hands out a fixed seed, once. Only for {@link #fromSeed}. */
    private static final class FixedRandom extends SecureRandom {
        private static final long serialVersionUID = 1L;
        private final byte[] seed;
        private boolean used;

        FixedRandom(byte[] seed) {
            this.seed = seed.clone();
        }

        @Override
        public void nextBytes(byte[] bytes) {
            if (used || bytes.length != seed.length) {
                throw new IllegalStateException("fixed seed consumed unexpectedly");
            }
            System.arraycopy(seed, 0, bytes, 0, seed.length);
            Bytes.wipe(seed);
            used = true;
        }
    }
}

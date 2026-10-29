package org.shalim.crypto;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPrivateKeySpec;
import java.security.spec.XECPublicKeySpec;
import javax.crypto.KeyAgreement;

/** X25519 key agreement (RFC 7748). Public keys travel as their 32 raw bytes. */
public final class X25519 {

    public static final int KEY_BYTES = 32;

    /** The base point, u = 9, little-endian. */
    private static final byte[] BASE_POINT = new byte[KEY_BYTES];

    static {
        BASE_POINT[0] = 9;
    }

    private X25519() {
    }

    public static KeyPair generate() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("X25519");
            return generator.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new CryptoException("X25519 unavailable", e);
        }
    }

    public static PrivateKey privateKeyFromRaw(byte[] scalar) {
        if (scalar == null || scalar.length != KEY_BYTES) {
            throw new CryptoException("X25519 private key must be 32 bytes");
        }
        try {
            return KeyFactory.getInstance("X25519")
                    .generatePrivate(new XECPrivateKeySpec(NamedParameterSpec.X25519, scalar.clone()));
        } catch (GeneralSecurityException e) {
            throw new CryptoException("malformed X25519 private key", e);
        }
    }

    /** The public key for a private one: X25519(k, 9). */
    public static byte[] publicFromPrivate(PrivateKey privateKey) {
        return agreeRaw(privateKey, BASE_POINT);
    }

    public static byte[] rawPublicKey(PublicKey key) {
        // The u-coordinate, little-endian, as RFC 7748 encodes it.
        BigInteger u = ((XECPublicKey) key).getU();
        byte[] bigEndian = u.toByteArray();
        byte[] raw = new byte[KEY_BYTES];
        for (int i = 0; i < KEY_BYTES && i < bigEndian.length; i++) {
            raw[i] = bigEndian[bigEndian.length - 1 - i];
        }
        return raw;
    }

    public static PublicKey publicKeyFromRaw(byte[] raw) {
        if (raw == null || raw.length != KEY_BYTES) {
            throw new CryptoException("X25519 public key must be 32 bytes");
        }
        byte[] bigEndian = new byte[KEY_BYTES + 1];
        for (int i = 0; i < KEY_BYTES; i++) {
            bigEndian[KEY_BYTES - i] = raw[i];
        }
        // RFC 7748: mask the top bit of the final byte when decoding u.
        bigEndian[1] &= 0x7f;
        try {
            return KeyFactory.getInstance("X25519").generatePublic(
                    new XECPublicKeySpec(NamedParameterSpec.X25519, new BigInteger(bigEndian)));
        } catch (GeneralSecurityException e) {
            throw new CryptoException("malformed X25519 public key", e);
        }
    }

    /**
     * Shared secret with a peer's raw public key. Rejects the all-zero output
     * that low-order points produce (RFC 7748 §6.1), so a hostile peer cannot
     * force a known key.
     */
    public static byte[] agree(PrivateKey privateKey, byte[] peerRawPublicKey) {
        byte[] shared = agreeRaw(privateKey, peerRawPublicKey);
        int acc = 0;
        for (byte b : shared) {
            acc |= b;
        }
        if (acc == 0) {
            throw new CryptoException("X25519 produced the all-zero secret");
        }
        return shared;
    }

    private static byte[] agreeRaw(PrivateKey privateKey, byte[] peerRawPublicKey) {
        try {
            KeyAgreement agreement = KeyAgreement.getInstance("X25519");
            agreement.init(privateKey);
            agreement.doPhase(publicKeyFromRaw(peerRawPublicKey), true);
            return agreement.generateSecret();
        } catch (GeneralSecurityException e) {
            throw new CryptoException("X25519 agreement failed", e);
        }
    }
}

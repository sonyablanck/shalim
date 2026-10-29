package org.shalim.crypto;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/** SHA-256. For structured data, prefer {@link Canonical#digest()}. */
public final class Hashing {

    private Hashing() {
    }

    public static byte[] sha256(byte[]... parts) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            for (byte[] part : parts) {
                digest.update(part);
            }
            return digest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException("SHA-256 unavailable", e);
        }
    }

    public static String sha256Hex(byte[] data) {
        return Bytes.hex(sha256(data));
    }

    public static String sha256Hex(String text) {
        return sha256Hex(text.getBytes(StandardCharsets.UTF_8));
    }
}

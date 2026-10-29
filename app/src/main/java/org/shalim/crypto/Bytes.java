package org.shalim.crypto;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;

/** Byte helpers shared by the primitives. */
public final class Bytes {

    private static final HexFormat HEX = HexFormat.of();
    private static final SecureRandom RANDOM = new SecureRandom();

    private Bytes() {
    }

    public static String hex(byte[] bytes) {
        return bytes == null ? null : HEX.formatHex(bytes);
    }

    public static byte[] fromHex(String hex) {
        return hex == null ? null : HEX.parseHex(hex);
    }

    public static byte[] random(int length) {
        byte[] out = new byte[length];
        RANDOM.nextBytes(out);
        return out;
    }

    /** 128 random bits as hex. For record ids that must carry no meaning. */
    public static String randomId() {
        return hex(random(16));
    }

    public static byte[] concat(byte[]... parts) {
        int length = 0;
        for (byte[] part : parts) {
            length += part.length;
        }
        byte[] out = new byte[length];
        int offset = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, out, offset, part.length);
            offset += part.length;
        }
        return out;
    }

    /** Constant-time comparison. Null equals only null. */
    public static boolean equal(byte[] a, byte[] b) {
        if (a == null || b == null) {
            return a == b;
        }
        return MessageDigest.isEqual(a, b);
    }

    /** Constant-time comparison of two hex strings, case-insensitive. */
    public static boolean equalHex(String a, String b) {
        if (a == null || b == null) {
            return a == b;
        }
        try {
            return equal(fromHex(a), fromHex(b));
        } catch (IllegalArgumentException malformed) {
            return false;
        }
    }

    /**
     * Overwrites secret material. Best effort only: the JVM may already have
     * copied the array, and immutable Strings can never be wiped, which is why
     * secrets in this codebase are byte arrays and never Strings.
     */
    public static void wipe(byte[] secret) {
        if (secret != null) {
            Arrays.fill(secret, (byte) 0);
        }
    }
}

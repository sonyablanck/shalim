package org.shalim.crypto;

/** HKDF with HMAC-SHA256 (RFC 5869). */
public final class Hkdf {

    private static final int HASH_LEN = 32;

    private Hkdf() {
    }

    public static byte[] extract(byte[] salt, byte[] ikm) {
        return Prf.hmac(salt == null || salt.length == 0 ? new byte[HASH_LEN] : salt, ikm);
    }

    public static byte[] expand(byte[] prk, byte[] info, int length) {
        if (length <= 0 || length > 255 * HASH_LEN) {
            throw new CryptoException("HKDF output length out of range");
        }
        byte[] out = new byte[length];
        byte[] previous = new byte[0];
        int offset = 0;
        for (int i = 1; offset < length; i++) {
            previous = Prf.hmac(prk, Bytes.concat(previous, info == null ? new byte[0] : info,
                    new byte[] {(byte) i}));
            int n = Math.min(HASH_LEN, length - offset);
            System.arraycopy(previous, 0, out, offset, n);
            offset += n;
        }
        return out;
    }

    public static byte[] derive(byte[] salt, byte[] ikm, byte[] info, int length) {
        byte[] prk = extract(salt, ikm);
        try {
            return expand(prk, info, length);
        } finally {
            Bytes.wipe(prk);
        }
    }
}

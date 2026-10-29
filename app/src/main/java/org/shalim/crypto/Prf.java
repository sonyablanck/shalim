package org.shalim.crypto;

import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** HMAC-SHA256, and deterministic sampling driven by it. */
public final class Prf {

    private Prf() {
    }

    public static byte[] hmac(byte[] key, byte[] message) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(message);
        } catch (GeneralSecurityException e) {
            throw new CryptoException("HMAC-SHA256 unavailable", e);
        }
    }

    /**
     * {@code count} distinct indices in {@code [0, bound)}, fixed by
     * {@code (key, input)} and unbiased. Draws come from HMAC in counter mode.
     * Each draw is a 63-bit value, rejected if it falls in the incomplete top
     * band, so no index is more likely than another. Repeats are redrawn.
     * Indices come back in draw order. If {@code count >= bound}, every index
     * is returned.
     *
     * <p>Anyone holding the same key and input gets the same sample. That is
     * the point: the sampled party can check the sample was not chosen by
     * hand.
     */
    public static List<Long> sampleDistinct(byte[] key, byte[] input, int count, long bound) {
        if (bound <= 0 || count <= 0) {
            return new ArrayList<>();
        }
        if (count >= bound) {
            List<Long> all = new ArrayList<>();
            for (long i = 0; i < bound; i++) {
                all.add(i);
            }
            return all;
        }
        long range = Long.MAX_VALUE; // 2^63 - 1 values in [0, 2^63 - 1)
        long limit = range - (range % bound);
        Set<Long> drawn = new LinkedHashSet<>();
        long block = 0;
        while (drawn.size() < count) {
            byte[] stream = hmac(key, Bytes.concat(input, Canonical.longBytes(block++)));
            for (int offset = 0; offset + 8 <= stream.length && drawn.size() < count; offset += 8) {
                long v = 0;
                for (int i = 0; i < 8; i++) {
                    v = (v << 8) | (stream[offset + i] & 0xff);
                }
                v >>>= 1;
                if (v < limit) {
                    drawn.add(v % bound);
                }
            }
        }
        return new ArrayList<>(drawn);
    }
}

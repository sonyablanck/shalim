package org.shalim.crypto;

import java.time.LocalDate;
import java.time.temporal.ChronoUnit;

/**
 * Commit once, reveal one value a day: each revealed value can be checked
 * against the commitment, and none of them gives away the next.
 *
 * <p>The auditor picks a secret seed {@code s} and a length {@code N}, and
 * sends the peer the anchor {@code c = H^N(s)} when the link is set up. The
 * nonce for day {@code k} after the start (k = 1..N) is
 * {@code H^(N-k)(s)}. The peer checks a revealed nonce by hashing it {@code k}
 * times and comparing with {@code c}, or by hashing it once to reach the
 * previous day's nonce. Working backwards would mean inverting SHA-256, so the
 * peer cannot predict tomorrow's nonce. And because every nonce was fixed when
 * {@code c} was sent, the auditor cannot choose one after seeing a root.
 *
 * <p>This replaces the earlier pseudo-code's {@code HMAC(nonceSecret, day)}
 * with commitment {@code H(nonceSecret)}. That version could not be checked:
 * the peer can only verify an HMAC output if it holds the key, and once it
 * holds the key every future nonce is known. So the auditor could have
 * revealed any nonce it liked, after seeing the root, and aimed the sample.
 *
 * <p>Every step is domain-separated and bound to the step number, so values
 * from different chains or positions never coincide.
 */
public final class HashChain {

    /** About thirteen months. A link renews its anchor before this runs out. */
    public static final int DEFAULT_LENGTH_DAYS = 400;

    private HashChain() {
    }

    /** The anchor {@code H^N(s)}, sent to the peer at link setup. */
    public static byte[] anchor(byte[] seed, int length) {
        return iterate(seed, 0, length);
    }

    /**
     * The value for {@code day}: {@code H^(N-k)(s)} with k counted from
     * {@code startDay}. Null when the day falls outside the chain, which means
     * a new anchor is due.
     */
    public static byte[] reveal(byte[] seed, int length, LocalDate startDay, LocalDate day) {
        long k = ChronoUnit.DAYS.between(startDay, day);
        if (k < 1 || k > length) {
            return null;
        }
        return iterate(seed, 0, (int) (length - k));
    }

    /** Checks a revealed value for {@code day} against the anchor. */
    public static boolean verify(byte[] anchor, int length, LocalDate startDay, LocalDate day,
                                 byte[] revealed) {
        long k = ChronoUnit.DAYS.between(startDay, day);
        if (anchor == null || revealed == null || k < 1 || k > length) {
            return false;
        }
        return Bytes.equal(iterate(revealed, (int) (length - k), length), anchor);
    }

    /** Applies steps {@code from+1 .. to} to {@code value}, where {@code value} sits at position {@code from}. */
    private static byte[] iterate(byte[] value, int from, int to) {
        byte[] v = value;
        for (int i = from + 1; i <= to; i++) {
            v = Canonical.of("shalim.hashchain.v1").u64(i).bytes(v).digest();
        }
        return v == value ? value.clone() : v;
    }
}

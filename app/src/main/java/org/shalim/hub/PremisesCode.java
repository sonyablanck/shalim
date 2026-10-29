package org.shalim.hub;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import org.shalim.crypto.Bytes;
import org.shalim.crypto.Canonical;
import org.shalim.crypto.Prf;

/**
 * Rotating, single-use codes shown on the premises (a screen by the door, a
 * QR code), for hubs whose Wi-Fi is not theirs to run.
 *
 * <p>A code is 80 bits of {@code HMAC(key, window)}, as hex, for a
 * five-minute window. The current and the previous window's codes are
 * accepted, so someone who photographs the screen just before it changes is
 * not turned away. Each code is accepted once: it is spent on first use, so a
 * photo passed round a group chat admits one person, not the whole chat.
 * There is still nothing stopping that one person being outside. That is
 * why this is a weaker attachment than the hub's own Wi-Fi.
 */
public final class PremisesCode {

    public static final long WINDOW_SECONDS = 300;

    private final byte[] key;
    /** Spent codes, with the window they belonged to, kept just long enough to refuse reuse. */
    private final Map<String, Long> spent = new HashMap<>();

    /** @param key 32-byte secret held by the hub runtime and the display only */
    public PremisesCode(byte[] key) {
        this.key = key.clone();
    }

    public String current(Instant now) {
        return codeFor(window(now));
    }

    /** Accepts and spends a current, unspent code. */
    public synchronized boolean redeem(String code, Instant now) {
        long w = window(now);
        spent.values().removeIf(window -> window < w - 1);
        if (code == null || spent.containsKey(code)) {
            return false;
        }
        for (long candidate : new long[] {w, w - 1}) {
            if (Bytes.equalHex(code, codeFor(candidate))) {
                spent.put(code, candidate);
                return true;
            }
        }
        return false;
    }

    private String codeFor(long window) {
        byte[] mac = Prf.hmac(key, Canonical.of("shalim.premises.v1").u64(window).encode());
        byte[] truncated = new byte[10];
        System.arraycopy(mac, 0, truncated, 0, truncated.length);
        return Bytes.hex(truncated);
    }

    private static long window(Instant now) {
        return Math.floorDiv(now.getEpochSecond(), WINDOW_SECONDS);
    }
}

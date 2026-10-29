package org.shalim.transport;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;

/**
 * Duty-cycle accounting: how much of a rolling window a radio has already
 * spent transmitting. In the EU 868 MHz sub-bands Shalim uses, the limit is
 * 1%: 36 seconds of transmission in any hour. Exceeding it is not just
 * antisocial, it is unlawful, so a send that would exceed it is refused,
 * not queued.
 */
public final class AirtimeBudget {

    private final double dutyCycle;
    private final Duration window;
    private final Deque<double[]> spent = new ArrayDeque<>(); // {epochSecond, seconds}

    public AirtimeBudget(double dutyCycle, Duration window) {
        if (dutyCycle <= 0 || dutyCycle > 1) {
            throw new IllegalArgumentException("duty cycle must be in (0, 1]");
        }
        this.dutyCycle = dutyCycle;
        this.window = window;
    }

    /** One hour, as the EU rules measure it. */
    public static AirtimeBudget hourly(double dutyCycle) {
        return new AirtimeBudget(dutyCycle, Duration.ofHours(1));
    }

    /** Seconds of transmission still allowed in the current window. */
    public synchronized double remaining(Instant now) {
        expire(now);
        double used = 0;
        for (double[] s : spent) {
            used += s[1];
        }
        return dutyCycle * window.toSeconds() - used;
    }

    /** Spends {@code seconds} if they fit, and says whether they did. */
    public synchronized boolean trySpend(double seconds, Instant now) {
        if (seconds > remaining(now)) {
            return false;
        }
        spent.addLast(new double[] {now.getEpochSecond() + now.getNano() / 1e9, seconds});
        return true;
    }

    private void expire(Instant now) {
        double cutoff = now.getEpochSecond() + now.getNano() / 1e9 - window.toSeconds();
        while (!spent.isEmpty() && spent.peekFirst()[0] <= cutoff) {
            spent.removeFirst();
        }
    }
}

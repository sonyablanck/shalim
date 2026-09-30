package org.shalim.trust;

import java.time.LocalDate;

/**
 * A rate-limiting nullifier in the style of RLN: lets the target hub enforce
 * "one presentation per member per link per day" without knowing who the
 * member is, and makes breaking that limit cost the member their anonymity.
 *
 * <h2>How it works</h2>
 *
 * <p>From the member's hidden secret {@code a0} and the epoch, the device
 * derives {@code a1 = H(a0, target, epoch)} and publishes:
 * <ul>
 *   <li>{@code nullifier = H(a1)} — the same for every presentation this
 *       member makes in this epoch, so the target can see a repeat;</li>
 *   <li>a share {@code (x, y)} with {@code x = H(challenge)} and
 *       {@code y = a0 + a1·x} — a point on a line whose intercept is the
 *       secret.</li>
 * </ul>
 * One presentation reveals one point: nothing. Two presentations in the same
 * epoch with different challenges reveal two points on the same line, and the
 * target solves for {@code a0}. It then matches {@code H(a0)} against the
 * secret commitments it recorded at join, and knows exactly which member
 * broke the limit. No one has to adjudicate.
 *
 * <p>A correct client never presents twice in an epoch, so honest probers are
 * never exposed. A modified client that tries to flood a hub unmasks itself.
 */
public class EpochNullifier {

    private String nullifier;
    private LocalDate epoch;
    private byte[] shareX;
    private byte[] shareY;

    public EpochNullifier() {
        // TODO: pseudo-code
    }

    public static EpochNullifier derive(byte[] memberSecret, String targetHubKeyFingerprint,
                                        LocalDate epoch, byte[] challenge) {
        // PSEUDO-CODE
        // a1 = H(memberSecret || target || epoch)
        // x  = H(challenge)
        // y  = memberSecret + a1 * x   (in the proof system's field)
        // RETURN EpochNullifier(H(a1), epoch, x, y)
        return null;
    }

    /** Recovers the secret from two shares with the same nullifier and different x. */
    public static byte[] recoverSecret(EpochNullifier first, EpochNullifier second) {
        // PSEUDO-CODE
        // IF first.nullifier != second.nullifier OR first.x == second.x -> RETURN null
        // a1 = (y2 - y1) / (x2 - x1)
        // RETURN y1 - a1 * x1
        return null;
    }

    public String getNullifier() {
        return nullifier;
    }

    public LocalDate getEpoch() {
        return epoch;
    }
}

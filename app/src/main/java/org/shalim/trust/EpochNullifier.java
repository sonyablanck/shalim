package org.shalim.trust;

import java.math.BigInteger;
import java.time.LocalDate;
import org.shalim.crypto.Bytes;
import org.shalim.crypto.Canonical;

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
 *   <li>{@code nullifier = H(a1)}: the same for every presentation this
 *       member makes in this epoch, so the target can see a repeat;</li>
 *   <li>a share {@code (x, y)} with {@code x = H(challenge)} and
 *       {@code y = a0 + a1·x}: a point on a line whose intercept is the
 *       secret.</li>
 * </ul>
 * One presentation reveals one point: nothing. Two presentations in the same
 * epoch with different challenges reveal two points on the same line, and the
 * target solves for {@code a0}. It then matches {@link #commitment} of
 * {@code a0} against the commitments it recorded at join, and knows exactly
 * which member broke the limit. No one has to adjudicate.
 *
 * <p>Arithmetic is in the scalar field of BLS12-381, the curve BBS runs over,
 * so the same secret can later be bound inside a BBS proof. This class is the
 * arithmetic only. That a presented share really comes from the secret inside
 * the presented credential is the credential scheme's job
 * ({@link MemberCredentialScheme}); without one, nothing is presented at all.
 */
public final class EpochNullifier {

    /** Order of the BLS12-381 scalar field. */
    static final BigInteger FIELD = new BigInteger(
            "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);

    private final String nullifier;
    private final LocalDate epoch;
    private final byte[] shareX;
    private final byte[] shareY;

    private EpochNullifier(String nullifier, LocalDate epoch, byte[] shareX, byte[] shareY) {
        this.nullifier = nullifier;
        this.epoch = epoch;
        this.shareX = shareX;
        this.shareY = shareY;
    }

    /** A nullifier as received from a prober's device. */
    public static EpochNullifier received(String nullifier, LocalDate epoch, byte[] shareX, byte[] shareY) {
        if (nullifier == null || epoch == null || shareX == null || shareY == null) {
            throw new IllegalArgumentException("incomplete nullifier");
        }
        return new EpochNullifier(nullifier, epoch, shareX.clone(), shareY.clone());
    }

    public static EpochNullifier derive(byte[] memberSecret, String targetHubKeyFingerprint,
                                        LocalDate epoch, byte[] challenge) {
        BigInteger a0 = toField(memberSecret);
        BigInteger a1 = toField(Canonical.of("shalim.rln.a1.v1").bytes(fieldBytes(a0))
                .hex(targetHubKeyFingerprint).date(epoch).digest());
        BigInteger x = toField(Canonical.of("shalim.rln.x.v1").bytes(challenge).digest());
        BigInteger y = a0.add(a1.multiply(x)).mod(FIELD);
        String n = Canonical.of("shalim.rln.nullifier.v1").bytes(fieldBytes(a1)).digestHex();
        return new EpochNullifier(n, epoch, fieldBytes(x), fieldBytes(y));
    }

    /** Recovers the secret from two shares with the same nullifier and different x. Null otherwise. */
    public static byte[] recoverSecret(EpochNullifier first, EpochNullifier second) {
        if (first == null || second == null || !first.nullifier.equals(second.nullifier)
                || !first.epoch.equals(second.epoch) || Bytes.equal(first.shareX, second.shareX)) {
            return null;
        }
        BigInteger x1 = new BigInteger(1, first.shareX);
        BigInteger y1 = new BigInteger(1, first.shareY);
        BigInteger x2 = new BigInteger(1, second.shareX);
        BigInteger y2 = new BigInteger(1, second.shareY);
        BigInteger a1 = y2.subtract(y1).multiply(x2.subtract(x1).modInverse(FIELD)).mod(FIELD);
        return fieldBytes(y1.subtract(a1.multiply(x1)).mod(FIELD));
    }

    /**
     * Commitment to a member secret, recorded by the issuer at join. The only
     * link between a secret and a membership.
     */
    public static String commitment(byte[] memberSecret) {
        return Canonical.of("shalim.member.secret.v1").bytes(fieldBytes(toField(memberSecret))).digestHex();
    }

    /** A fresh member secret, already reduced into the field. */
    public static byte[] newSecret() {
        return fieldBytes(toField(Bytes.random(48)));
    }

    static BigInteger toField(byte[] bytes) {
        return new BigInteger(1, bytes).mod(FIELD);
    }

    static byte[] fieldBytes(BigInteger v) {
        byte[] raw = v.toByteArray();
        byte[] out = new byte[32];
        int copy = Math.min(raw.length, 32);
        System.arraycopy(raw, raw.length - copy, out, 32 - copy, copy);
        return out;
    }

    public boolean sameShareAs(EpochNullifier other) {
        return other != null && nullifier.equals(other.nullifier) && Bytes.equal(shareX, other.shareX)
                && Bytes.equal(shareY, other.shareY);
    }

    public String getNullifier() {
        return nullifier;
    }

    public LocalDate getEpoch() {
        return epoch;
    }

    public byte[] getShareX() {
        return shareX.clone();
    }

    public byte[] getShareY() {
        return shareY.clone();
    }
}

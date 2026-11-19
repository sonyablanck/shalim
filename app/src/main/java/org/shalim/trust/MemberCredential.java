package org.shalim.trust;

import java.time.LocalDate;
import java.time.temporal.ChronoUnit;
import java.util.List;
import org.shalim.crypto.Bytes;
import org.shalim.crypto.Canonical;
import org.shalim.crypto.Prf;

/**
 * An anonymous credential that says "an ordinary member of this hub" without
 * saying which one. Every ordinary member's device holds one for each hub it
 * belongs to, whether or not it ever probes, so that a prober is one of many.
 *
 * <h2>Why every member has one</h2>
 *
 * <p>The prober's anonymity is only as large as the set of people who could
 * have produced the same proof. If only probers held credentials, holding one
 * would identify them. So the hub issues a fresh credential to every MEMBER
 * and MODERATOR on sync, automatically, every day.
 *
 * <h2>What it certifies</h2>
 * <ul>
 *   <li>{@code hubKeyFingerprint}: the issuing hub.</li>
 *   <li>{@code roleClass}: ORDINARY (MEMBER or MODERATOR). ADMINs and GUESTs
 *       are not issued one, so an admin there simply cannot present.</li>
 *   <li>{@code joinedWeek}: week of joining, coarse, proved only as "long
 *       enough ago".</li>
 *   <li>{@code attested}: proved only as the predicate "attested = true".</li>
 *   <li>{@code epoch}: the day. Credentials expire daily, which is how
 *       promotion to admin ends eligibility the same day.</li>
 *   <li>A hidden member secret, committed at join, from which pseudonyms and
 *       {@link EpochNullifier}s are derived.</li>
 * </ul>
 *
 * <p>The proof itself comes from a {@link MemberCredentialScheme}; with none
 * bound, {@link #presentEligibility} returns null.
 */
public class MemberCredential {

    public enum RoleClass {
        /** MEMBER or MODERATOR. The only class ever issued. */
        ORDINARY
    }

    /** Weeks are counted from this Monday, so joinedWeek is a small integer. */
    static final LocalDate WEEK_ZERO = LocalDate.of(2024, 1, 1);

    private final String hubKeyFingerprint;
    private final RoleClass roleClass;
    private final int joinedWeek;
    private final boolean attested;
    private final LocalDate epoch;

    /** Opaque scheme signature over the attributes and the committed secret. */
    private final byte[] signature;

    /** Never leaves the device. Held in the hardware keystore alongside the account key. */
    private transient byte[] memberSecret;

    public MemberCredential(String hubKeyFingerprint, RoleClass roleClass, int joinedWeek, boolean attested,
                            LocalDate epoch, byte[] signature) {
        this.hubKeyFingerprint = hubKeyFingerprint;
        this.roleClass = roleClass;
        this.joinedWeek = joinedWeek;
        this.attested = attested;
        this.epoch = epoch;
        this.signature = signature == null ? null : signature.clone();
    }

    /** Device side: attaches the member's own secret on receipt. */
    public MemberCredential holding(byte[] secret) {
        this.memberSecret = secret == null ? null : secret.clone();
        return this;
    }

    public static int weekOf(LocalDate day) {
        return (int) ChronoUnit.WEEKS.between(WEEK_ZERO, day);
    }

    /** Latest joinedWeek that satisfies "member for at least minMembershipDays". */
    public static int maxJoinedWeek(LocalDate today, int minMembershipDays) {
        // A whole week earlier than the boundary week, so a coarse week never
        // admits someone a few days short.
        return weekOf(today.minusDays(minMembershipDays)) - 1;
    }

    /** Stable for (member, target, auditor): what the target records the link under. */
    public static String linkPseudonym(byte[] memberSecret, String targetKeyFingerprint,
                                       String auditorKeyFingerprint) {
        return Bytes.hex(Prf.hmac(memberSecret, Canonical.of("shalim.pseudonym.link.v1")
                .hex(targetKeyFingerprint).hex(auditorKeyFingerprint).encode()));
    }

    /** Stable for (member, target), whatever the auditing hub: one member carries one link. */
    public static String proberPseudonym(byte[] memberSecret, String targetKeyFingerprint) {
        return Bytes.hex(Prf.hmac(memberSecret, Canonical.of("shalim.pseudonym.prober.v1")
                .hex(targetKeyFingerprint).encode()));
    }

    /** The values a proof must bind to the hidden secret, in a fixed order. */
    static List<byte[]> boundValues(String linkPseudonym, String proberPseudonym, EpochNullifier n) {
        return List.of(Bytes.fromHex(linkPseudonym), Bytes.fromHex(proberPseudonym),
                Bytes.fromHex(n.getNullifier()), n.getShareX(), n.getShareY());
    }

    /**
     * Produces the anonymous proof a target hub checks when a link is set up,
     * and again on every day the link runs. Null if stale, if the device holds
     * no secret, if no scheme is bound, or if the predicates cannot be met.
     */
    public EligibilityProof presentEligibility(MemberCredentialScheme scheme, String auditingHubKeyFingerprint,
                                               LocalDate today, int minMembershipDays, byte[] challenge) {
        if (scheme == null || memberSecret == null || !isCurrent(today) || challenge == null
                || joinedWeek > maxJoinedWeek(today, minMembershipDays)) {
            return null; // the device knows it is too new; see ProberCredentials.whyNot
        }
        String link = linkPseudonym(memberSecret, hubKeyFingerprint, auditingHubKeyFingerprint);
        String prober = proberPseudonym(memberSecret, hubKeyFingerprint);
        EpochNullifier n = EpochNullifier.derive(memberSecret, hubKeyFingerprint, today, challenge);
        byte[] proof = scheme.prove(this, memberSecret, maxJoinedWeek(today, minMembershipDays), challenge,
                boundValues(link, prober, n));
        if (proof == null) {
            return null;
        }
        return new EligibilityProof(hubKeyFingerprint, auditingHubKeyFingerprint, today, proof, link, prober, n,
                challenge);
    }

    public boolean isCurrent(LocalDate today) {
        return epoch != null && epoch.equals(today);
    }

    public String getHubKeyFingerprint() {
        return hubKeyFingerprint;
    }

    public RoleClass getRoleClass() {
        return roleClass;
    }

    public LocalDate getEpoch() {
        return epoch;
    }

    public boolean isAttested() {
        return attested;
    }

    public int getJoinedWeek() {
        return joinedWeek;
    }

    public byte[] getSignature() {
        return signature == null ? null : signature.clone();
    }
}

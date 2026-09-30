package org.shalim.trust;

import java.time.LocalDate;

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
 * and MODERATOR on sync, automatically, every day, and nothing about fetching
 * one distinguishes a prober from anyone else.
 *
 * <h2>What it certifies</h2>
 * <ul>
 *   <li>{@code hubKeyFingerprint} — the issuing hub.</li>
 *   <li>{@code roleClass} — ORDINARY (MEMBER or MODERATOR). ADMINs and GUESTs
 *       are not issued one at all, so "not an admin there" needs no separate
 *       check: an admin simply cannot present.</li>
 *   <li>{@code joinedWeek} — week of joining, coarse. Lets a proof show the
 *       member joined at least {@code AuditSchedule.minProberMembershipDays}
 *       ago without disclosing when, so a link set up the week after someone
 *       joined does not point at them.</li>
 *   <li>{@code attested} — whether the member's account key passed a device
 *       attestation at issuance (see {@link org.shalim.identity.DeviceBinding}).
 *       Hidden in presentations except as the predicate "attested = true".</li>
 *   <li>{@code epoch} — the day. Credentials expire daily, which is how
 *       promotion to admin ends eligibility the same day without a
 *       revocation list: the promoted member simply stops being issued one.</li>
 *   <li>A hidden member secret, committed at join, from which
 *       {@link EpochNullifier}s are derived.</li>
 * </ul>
 *
 * <h2>Scheme</h2>
 *
 * <p>BBS signatures (IRTF CFRG draft) with blind issuance for the secret and
 * per-context pseudonyms. Chosen because BBS supports hiding attributes,
 * proving predicates over them and deriving a pseudonym per verifier context
 * from one hidden secret. Java support is thin; the reference plan is a Rust
 * implementation behind JNI. Scheme choice is still open; see the README.
 */
public class MemberCredential {

    public enum RoleClass {
        /** MEMBER or MODERATOR. The only class ever issued. */
        ORDINARY
    }

    private String hubKeyFingerprint;
    private RoleClass roleClass;
    private int joinedWeek;
    private boolean attested;
    private LocalDate epoch;

    /** Opaque BBS signature over the attributes and the committed secret. */
    private byte[] signature;

    /** Never leaves the device. Held in the hardware keystore alongside the account key. */
    private transient byte[] memberSecret;

    public MemberCredential() {
        // TODO: pseudo-code
    }

    /**
     * Produces the anonymous proof a target hub checks when a link is set up,
     * and again on every day the link runs.
     *
     * @param context the verifier context: target hub key, auditing hub key and
     *                purpose. The pseudonym is stable within a context and
     *                unlinkable across contexts.
     */
    public EligibilityProof presentEligibility(String auditingHubKeyFingerprint, LocalDate today,
                                               int minMembershipDays, byte[] context,
                                               byte[] challenge) {
        // PSEUDO-CODE
        // IF epoch != today -> RETURN null   // stale; refresh on next sync
        // proof = BBS.proofGen(signature,
        //    disclosed  = { hubKeyFingerprint, roleClass, epoch },
        //    predicates = { attested == true,
        //                   joinedWeek <= week(today - minMembershipDays) },
        //    hidden     = { joinedWeek, attested, memberSecret },
        //    challenge)
        // linkPseudonym = pseudonym(memberSecret, context = target||auditor||"link")
        //    // Same member, same pair of hubs -> same pseudonym, so one member
        //    // cannot register as two probers for one auditing hub.
        // proberPseudonym = pseudonym(memberSecret, context = target||"prober")
        //    // Same member, any auditing hub -> same pseudonym, so one ordinary
        //    // member of the target cannot carry links for several hubs. The
        //    // "recruit a friend" Sybil route now costs one friend per hub.
        // nullifier = EpochNullifier.derive(memberSecret, target, today, challenge)
        // RETURN EligibilityProof(proof, linkPseudonym, proberPseudonym, nullifier)
        return null;
    }

    public boolean isCurrent(LocalDate today) {
        // TODO: pseudo-code
        return false;
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
}

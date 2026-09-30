package org.shalim.trust;

import java.time.Instant;
import java.time.LocalDate;

/**
 * Who may carry probes from one hub into another — now checked without the
 * target learning <em>who</em> is carrying them.
 *
 * <p>The rule is unchanged: a hub admin may authenticate another hub only
 * through a membership in which they are an ordinary user there, the two hubs
 * may share no admin, and the prober's account must be the only one on a
 * genuine device. What changed is how each part is proved.
 *
 * <table>
 *   <caption>Checks, before and after the September 30 revision</caption>
 *   <tr><th>Check</th><th>Before</th><th>Now</th></tr>
 *   <tr><td>Admin here</td><td>Local roster</td><td>Unchanged (the
 *       authenticating hub knows its own admins)</td></tr>
 *   <tr><td>Ordinary user there</td><td>Target looked up the prober's user id
 *       in its roster</td><td>Prober presents a {@link MemberCredential}; admins
 *       and guests are never issued one</td></tr>
 *   <tr><td>No shared admins</td><td>Salted hashes — which let the target
 *       name the prober</td><td>{@link AdminOverlapCheck}, cardinality
 *       only</td></tr>
 *   <tr><td>Attested device</td><td>Attestation chain sent at link
 *       setup, naming the prober's key</td><td>Checked once at join by
 *       {@link MemberCredentialIssuer#enrol}, carried as a hidden credential
 *       attribute</td></tr>
 *   <tr><td>New</td><td>—</td><td>Membership older than
 *       {@code minProberMembershipDays}; anonymity set at least
 *       {@code minProberAnonymitySet}; one link per member</td></tr>
 * </table>
 *
 * <p>What this still does not stop: a person with several devices, several
 * people acting together, or an admin who recruits a friend. The friend can
 * now carry a link for one hub only (the prober pseudonym), which raises the
 * cost; it does not remove it.
 */
public class ProberEligibility {

    public enum Result {
        ELIGIBLE,
        NOT_ADMIN_HERE,
        /**
         * No valid credential: the prober is an admin or guest there, not a
         * member at all, not attested, or the proof failed. Deliberately one
         * result — distinguishing them would tell the target something about
         * an anonymous member.
         */
        NO_VALID_CREDENTIAL,
        /** Membership too new to hide in the set of members who could present. */
        MEMBERSHIP_TOO_RECENT,
        SHARED_ADMIN,
        /** This member already carries a link for a different auditing hub. */
        PROBER_ALREADY_ASSIGNED,
        /** A second presentation this epoch with a different challenge. */
        NULLIFIER_DOUBLE_SPENT,
        /**
         * Too few ordinary, attested, old-enough members for the prober to be
         * anonymous. Not a refusal of the link: it runs in REPLAY_ONLY mode.
         */
        ANONYMITY_SET_TOO_SMALL
    }

    private ProberEligibility() {
    }

    /**
     * The authenticating hub's side. Checks admin-here locally, runs the admin
     * overlap check, and has the prober's device present a credential.
     */
    public static Result checkOutbound(String proberUserId, org.shalim.hub.Hub authenticatingHub,
                                       org.shalim.transport.PeerEndpoint target, Instant now) {
        // PSEUDO-CODE
        // IF authenticatingHub.roster.membershipOf(prober).role != ADMIN
        //    RETURN NOT_ADMIN_HERE
        // exp = fresh secret exponent
        // send AdminOverlapCheck.blindOwnAdmins(own admin keys, exp) to target
        //    // Sent hub-to-hub, not through the prober's membership, so it does
        //    // not travel alongside anything that identifies them.
        // challenge = target's fresh challenge
        // proof = prober's device: credential(target).presentEligibility(
        //            own hub key, today, schedule.minProberMembershipDays,
        //            context, challenge)
        // IF proof null -> RETURN NO_VALID_CREDENTIAL
        // RETURN target's checkInbound(proof, overlap result)
        return null;
    }

    /**
     * The target hub's side. Everything decided here comes from the proof, the
     * target's own issuer key and registry, and the PSI-CA result. No roster
     * lookup of the prober happens, because the target does not know who they
     * are.
     */
    public static Result checkInbound(EligibilityProof proof, org.shalim.hub.Hub targetHub,
                                      byte[] issuerPublicKey, int adminOverlap,
                                      NullifierRegistry registry, MemberCredentialIssuer issuer,
                                      AuditSchedule schedule, LocalDate today, Instant now) {
        // PSEUDO-CODE
        // IF adminOverlap > 0 -> RETURN SHARED_ADMIN
        // IF NOT proof.verify(issuerPublicKey, schedule.minProberMembershipDays)
        //    // the predicate "joined long enough ago" is inside the proof;
        //    // a failure there is reported as MEMBERSHIP_TOO_RECENT only when
        //    // the proof verifies without that predicate, so a member who is
        //    // merely new learns why, and nothing else is distinguished
        //    RETURN NO_VALID_CREDENTIAL or MEMBERSHIP_TOO_RECENT
        // SWITCH registry.observe(proof.nullifier, now)
        //    DOUBLE_SPENT -> registry.trace(...); RETURN NULLIFIER_DOUBLE_SPENT
        //    REPLAYED     -> continue    // retransmission, same answer as before
        // IF registry.proberAlreadyAssigned(proof.proberPseudonym, proof.auditingHub)
        //    RETURN PROBER_ALREADY_ASSIGNED
        // IF issuer.anonymitySetSize(targetHub.roster, schedule.minProberMembershipDays, today)
        //       < schedule.minProberAnonymitySet
        //    RETURN ANONYMITY_SET_TOO_SMALL
        // RETURN ELIGIBLE
        return null;
    }

    /** Whether a result still allows a link to run, in some mode. */
    public static boolean permitsLink(Result result) {
        // PSEUDO-CODE
        // RETURN result IN (ELIGIBLE, ANONYMITY_SET_TOO_SMALL)
        return false;
    }

    /** Plain-language reason for the admin who tried to set up the link. */
    public static String explain(Result result) {
        // PSEUDO-CODE
        // NO_VALID_CREDENTIAL -> "You need to be an ordinary member of that hub
        //    (not an admin or guest), using the official Shalim app on a phone
        //    or computer that hasn't been modified."
        // MEMBERSHIP_TOO_RECENT -> "You joined that hub recently. You can check
        //    it once you've been a member for <n> days, so the check can't be
        //    traced to you by when you joined."
        // SHARED_ADMIN -> "Your hub and that hub share an admin, so they can't
        //    check each other."
        // PROBER_ALREADY_ASSIGNED -> "You're already checking that hub for
        //    another hub. Each member can check a hub for one hub only."
        // ANONYMITY_SET_TOO_SMALL -> "That hub is small, so your checks there
        //    could be traced to you. It will be checked from its records only,
        //    and you won't send any test questions."
        return null;
    }
}

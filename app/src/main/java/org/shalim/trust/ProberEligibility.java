package org.shalim.trust;

import java.time.LocalDate;
import org.shalim.hub.Hub;
import org.shalim.identity.Membership;
import org.shalim.identity.Role;

/**
 * Who may carry probes from one hub into another, checked without the target
 * learning <em>who</em> is carrying them.
 *
 * <p>The rule: a hub admin may authenticate another hub only through a
 * membership in which they are an ordinary user there, the two hubs may share
 * no admin, and the prober's account must be on a genuine, attested device.
 * The authenticating hub checks "admin here" from its own roster
 * ({@link #checkOutbound}); everything about the target is decided by the
 * target from an anonymous proof ({@link #checkInbound}).
 *
 * <p>What this still does not stop: a person with several devices, several
 * people acting together, or an admin who recruits a friend. The friend can
 * carry a link for one hub only (the prober pseudonym), which raises the
 * cost; it does not remove it.
 */
public final class ProberEligibility {

    public enum Result {
        ELIGIBLE,
        NOT_ADMIN_HERE,
        /**
         * No valid credential: the prober is an admin or guest there, not a
         * member at all, not attested, the proof failed, or no credential
         * scheme is bound. Deliberately one result.
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

    /** The authenticating hub's own part: the prober must be an admin here. */
    public static Result checkOutbound(String proberUserId, Hub authenticatingHub) {
        Membership m = authenticatingHub.getRoster().membershipOf(proberUserId).orElse(null);
        return m != null && m.getRole() == Role.ADMIN ? Result.ELIGIBLE : Result.NOT_ADMIN_HERE;
    }

    /**
     * The target hub's side. Everything decided here comes from the proof, the
     * target's own issuer key and registry, and the PSI-CA result. No roster
     * lookup of the prober happens, because the target does not know who they
     * are.
     */
    public static Result checkInbound(EligibilityProof proof, Hub targetHub, byte[] issuerPublicKey,
                                      String issuerKeyFingerprint, int adminOverlap, NullifierRegistry registry,
                                      MemberCredentialIssuer issuer, AuditSchedule schedule, LocalDate today) {
        if (adminOverlap > 0) {
            return Result.SHARED_ADMIN;
        }
        MemberCredentialScheme scheme = issuer == null ? null : issuer.getScheme();
        if (proof == null || scheme == null || !issuerKeyFingerprint.equals(proof.getTargetHubKeyFingerprint())) {
            return Result.NO_VALID_CREDENTIAL;
        }
        if (!proof.verify(scheme, issuerPublicKey, schedule.getMinProberMembershipDays(), today)) {
            // Distinguish "merely new" only when the proof is otherwise valid.
            return proof.verify(scheme, issuerPublicKey, -1, today) ? Result.MEMBERSHIP_TOO_RECENT
                    : Result.NO_VALID_CREDENTIAL;
        }
        if (registry.isBarred(proof.getProberPseudonym())) {
            return Result.NO_VALID_CREDENTIAL;
        }
        NullifierRegistry.Outcome seen = registry.observe(proof.getNullifier());
        if (seen == NullifierRegistry.Outcome.DOUBLE_SPENT) {
            return Result.NULLIFIER_DOUBLE_SPENT;
        }
        if (registry.proberAlreadyAssigned(proof.getProberPseudonym(), proof.getAuditingHubKeyFingerprint())) {
            return Result.PROBER_ALREADY_ASSIGNED;
        }
        if (issuer.anonymitySetSize(targetHub.getRoster(), schedule.getMinProberMembershipDays(), today)
                < schedule.getMinProberAnonymitySet()) {
            return Result.ANONYMITY_SET_TOO_SMALL;
        }
        return Result.ELIGIBLE;
    }

    /** Whether a result still allows a link to run, in some mode. */
    public static boolean permitsLink(Result result) {
        return result == Result.ELIGIBLE || result == Result.ANONYMITY_SET_TOO_SMALL;
    }

    /** Plain-language reason for the admin who tried to set up the link. */
    public static String explain(Result result, int minMembershipDays) {
        return switch (result) {
            case ELIGIBLE -> null;
            case NOT_ADMIN_HERE -> "Only an admin of this hub can set up checks on another hub.";
            case NO_VALID_CREDENTIAL -> "You need to be an ordinary member of that hub (not an admin or guest),"
                    + " using the official Shalim app on a phone or computer that hasn't been modified.";
            case MEMBERSHIP_TOO_RECENT -> "You joined that hub recently. You can check it once you've been a member"
                    + " for " + minMembershipDays + " days, so the check can't be traced to you by when you joined.";
            case SHARED_ADMIN -> "Your hub and that hub share an admin, so they can't check each other.";
            case PROBER_ALREADY_ASSIGNED -> "You're already checking that hub for another hub."
                    + " Each member can check a hub for one hub only.";
            case NULLIFIER_DOUBLE_SPENT -> "That hub refused the check because this app presented twice today.";
            case ANONYMITY_SET_TOO_SMALL -> "That hub is small, so your checks there could be traced to you."
                    + " It will be checked from its records only, and you won't send any test questions.";
        };
    }
}

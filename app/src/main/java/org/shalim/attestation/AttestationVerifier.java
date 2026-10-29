package org.shalim.attestation;

import java.time.Instant;
import org.shalim.hub.HubPolicy;
import org.shalim.identity.Restriction;
import org.shalim.identity.Role;

/**
 * Receiving-hub side: decides what a presented proof — or a missing one — is
 * worth here.
 *
 * <p>The key judgement is what absence of proof costs. Treating "no proof" as
 * "presumed bad" makes the network unusable in exactly the conditions Shalim is
 * built for, since a blackout stops everyone refreshing. So absence caps a
 * member at guest <em>only where the hub's policy says so</em>, and only while
 * the hub believes refresh is actually possible.
 */
public class AttestationVerifier {

    private String hubId;
    private HubPolicy policy;

    /** Verdict for one presented proof, or its absence. */
    public enum Outcome {
        /** Valid, signed, from an accepted issuer, in date. */
        ACCEPTED,
        /** Signature or subject mismatch. Treat as hostile. */
        INVALID,
        /** Well-formed but lapsed. Common and usually benign. */
        EXPIRED,
        /** Issuer not in this hub's accepted set. Not an accusation. */
        UNTRUSTED_ISSUER,
        /** No proof presented at all. */
        ABSENT
    }

    public AttestationVerifier() {
        // TODO: pseudo-code
    }

    public AttestationVerifier(String hubId, HubPolicy policy) {
        // TODO: pseudo-code
    }

    /** Checks signature, subject binding, validity window, and issuer trust. */
    public Outcome verify(Attestation attestation, String expectedSubject, Instant now) {
        // PSEUDO-CODE
        //
        // IF attestation == null -> RETURN ABSENT
        // IF attestation.subjectKeyFingerprint != expectedSubject -> RETURN INVALID
        //    // Binding check first: an otherwise valid proof for someone else
        //    // is a replay attempt, not an expiry.
        // IF NOT attestation.verify(publicKeyFor(issuerKeyFingerprint)) -> RETURN INVALID
        // IF NOT attestation.isValid(now) -> RETURN EXPIRED
        // IF issuer NOT IN policy.trustedRestrictionSources -> RETURN UNTRUSTED_ISSUER
        // RETURN ACCEPTED
        return null;
    }

    /**
     * The restriction, if any, that this hub should apply given what the user
     * could show. Returns null when no cap is warranted.
     */
    public Restriction evaluate(AttestationWallet wallet, String membershipId,
                                boolean refreshPlausible, Instant now) {
        // PSEUDO-CODE
        //
        // 1. ACTIVE OUTCOMES FIRST
        //    // A presented moderation outcome is the strongest signal and the
        //    // one that actually targets "radicaliser moves hub".
        //    outcome = wallet.present(ACTIVE_MODERATION_OUTCOME, trustedIssuers, now)
        //    IF outcome present AND verify(...) == ACCEPTED
        //       RETURN Restriction(
        //          reason   = MODERATION_ACTION,
        //          scope    = FEDERATED,
        //          roleCap  = GUEST,
        //          discharge = EXPIRY,          // lapses with the outcome
        //          expiresAt = outcome.expiresAt,
        //          appealable = true,
        //          explanation = "Another hub you belong to has an active
        //                         moderation decision about you.")
        //
        // 2. GOOD STANDING
        //    IF NOT policy.requireGoodStanding -> RETURN null
        //       // Most hubs should leave this off. Requiring proof is a
        //       // meaningful cost to people with patchy connectivity.
        //
        //    proof = wallet.present(GOOD_STANDING, trustedIssuers, now)
        //    result = verify(proof, user's fingerprint, now)
        //
        //    IF result == ACCEPTED -> RETURN null
        //
        //    IF result IN (EXPIRED, ABSENT) AND NOT refreshPlausible
        //       RETURN null
        //       // THE IMPORTANT CASE. During a blackout nobody can refresh, so
        //       // treating absence as guilt would silence a whole hub exactly
        //       // when it is most needed. Fail open here; the censor and
        //       // moderation outcomes still apply.
        //
        //    IF result == INVALID
        //       RETURN Restriction(reason = MODERATION_ACTION, roleCap = GUEST,
        //                          discharge = MANUAL, appealable = true)
        //       // Forged proof is a deliberate act; a human should look.
        //
        //    RETURN Restriction(
        //       reason   = COMPROMISED_CENSOR,
        //       scope    = FEDERATED,
        //       roleCap  = GUEST,
        //       discharge = LEAVE_ORIGIN_HUB,
        //       appealable = true,
        //       explanation = "A hub you belong to cannot currently vouch for
        //                      you. This lifts when it is fixed, or if you
        //                      leave that hub.")
        //       // No originHubId is set: this hub does not know which hub
        //       // failed, only that no valid proof exists. The discharge
        //       // condition is satisfied by a fresh proof appearing.
        return null;
    }

    /** Highest role this hub will grant given the proofs on offer. */
    public Role permittedRole(AttestationWallet wallet, Role requestedRole,
                              boolean refreshPlausible, Instant now) {
        // TODO: pseudo-code
        return null;
    }
}

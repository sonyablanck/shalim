package org.shalim.attestation;

import java.time.Instant;
import org.shalim.hub.Hub;

/**
 * Hub-side issuer of {@link Attestation}s about its own members.
 *
 * <p>This is where the "member of a flagged hub" boolean actually lives, and it
 * lives here rather than travelling with the user because a user-held flag can
 * simply be withheld. A hub declines to issue {@link Attestation.Claim#GOOD_STANDING}
 * while its own censor is flagged; the member's existing proof then lapses on
 * its own, and every other hub sees only "no current proof" — never which hub
 * failed, or that this person is in it.
 */
public class AttestationIssuer {

    private String hubId;

    /** Fingerprint of this hub's signing key, published to peers. */
    private String issuerKeyFingerprint;

    /**
     * How long issued proofs last. Short enough that leaving a flagged hub
     * clears the cap quickly; long enough to survive a normal outage.
     */
    private java.time.Duration attestationTtl;

    public AttestationIssuer() {
        // TODO: pseudo-code
    }

    public AttestationIssuer(Hub hub) {
        // TODO: pseudo-code
    }

    /**
     * Issues a good-standing proof, or refuses. Refusal is the mechanism: it
     * caps the member elsewhere without telling anyone why.
     */
    public Attestation issueGoodStanding(String subjectKeyFingerprint, Instant now) {
        // PSEUDO-CODE
        //
        // 1. IF subject is not a member here -> RETURN null
        //
        // 2. IF this hub's censorIntegrity.requiresRestriction()
        //       RETURN null
        //       // The flagged-hub condition, expressed as withheld proof.
        //       // Note MISMATCHED restricts but UNAVAILABLE does not: a member
        //       // who has simply not downloaded the model yet is not suspect.
        //
        // 3. IF subject has an active, non-overturned ModerationOutcome here
        //       RETURN null
        //
        // 4. RETURN signed Attestation(
        //       claim = GOOD_STANDING,
        //       subject = subjectKeyFingerprint,
        //       issuer = issuerKeyFingerprint,
        //       expiresAt = now + attestationTtl)
        //       // No hubId, no display name, no membership list. A receiving
        //       // hub learns "some hub it may trust vouches for this key".
        return null;
    }

    /**
     * Issues a shareable record of a moderation decision. Only for outcomes the
     * hub has explicitly marked federatable.
     */
    public Attestation issueOutcomeAttestation(ModerationOutcome outcome, Instant now) {
        // PSEUDO-CODE
        //
        // 1. IF NOT outcome.federatable -> RETURN null
        // 2. IF outcome.overturned OR NOT outcome.isActive(now) -> RETURN null
        // 3. IF outcome.underAppeal AND policy withholds during appeal
        //       RETURN null
        //       // Do not export a contested finding as settled fact.
        // 4. RETURN signed Attestation(
        //       claim = ACTIVE_MODERATION_OUTCOME,
        //       outcomeId = outcome.outcomeId,
        //       expiresAt = min(now + attestationTtl, outcome.expiresAt))
        return null;
    }

    /** Issues an adult attestation. Carries no date of birth or document data. */
    public Attestation issueAdult(String subjectKeyFingerprint, Instant now) {
        // TODO: pseudo-code
        return null;
    }

    /**
     * Whether this hub is currently able to vouch for anyone. False while its
     * censor is flagged.
     */
    public boolean canIssue() {
        // TODO: pseudo-code
        return false;
    }

    public String getIssuerKeyFingerprint() {
        return issuerKeyFingerprint;
    }
}

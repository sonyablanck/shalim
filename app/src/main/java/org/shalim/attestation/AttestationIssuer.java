package org.shalim.attestation;

import java.time.Instant;
import org.shalim.hub.Hub;
import org.shalim.hub.HubPolicy;

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

    private transient Hub hub;
    private transient org.shalim.crypto.Signer issuerKey;

    public AttestationIssuer() {
        this.attestationTtl = java.time.Duration.ofHours(72);
    }

    public AttestationIssuer(Hub hub) {
        this();
        this.hub = hub;
        this.hubId = hub.getHubId();
        if (hub.getPolicy() != null && hub.getPolicy().getAttestationTtlHours() > 0) {
            this.attestationTtl = java.time.Duration.ofHours(hub.getPolicy().getAttestationTtlHours());
        }
    }

    /** The issuer as the hub runtime builds it, holding the hub's issuer key. */
    public AttestationIssuer(Hub hub, org.shalim.crypto.Signer issuerKey) {
        this(hub);
        this.issuerKey = issuerKey;
        this.issuerKeyFingerprint = issuerKey.fingerprint();
    }

    /**
     * Issues a good-standing proof, or refuses. Refusal is the mechanism: it
     * caps the member elsewhere without telling anyone why.
     */
    public Attestation issueGoodStanding(String subjectKeyFingerprint, Instant now) {
        if (!canIssue() || hub.getRoster().membershipOf(subjectKeyFingerprint).isEmpty()) {
            return null;
        }
        if (hasActiveOutcome(subjectKeyFingerprint, now)) {
            return null;
        }
        // No hubId, no display name, no membership list. A receiving hub learns
        // "some hub it may trust vouches for this key".
        return Attestation.issue(Attestation.Claim.GOOD_STANDING, subjectKeyFingerprint, issuerKey, now,
                now.plus(attestationTtl), null);
    }

    private boolean hasActiveOutcome(String subject, Instant now) {
        for (ModerationOutcome o : hub.getModerationOutcomes()) {
            if (subject.equals(o.getSubjectKeyFingerprint()) && o.isActive(now)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Issues a shareable record of a moderation decision. Only for outcomes the
     * hub has explicitly marked federatable, and never one under appeal where
     * policy withholds them: a contested finding is not exported as settled fact.
     */
    public Attestation issueOutcomeAttestation(ModerationOutcome outcome, Instant now) {
        if (issuerKey == null || outcome == null || !outcome.isFederatable() || !outcome.isActive(now)) {
            return null;
        }
        if (hub.getPolicy() != null && !hub.getPolicy().isFederateModerationOutcomes()) {
            return null;
        }
        boolean withhold = hub.getPolicy() == null || hub.getPolicy().isWithholdOutcomesUnderAppeal();
        if (outcome.isUnderAppeal() && withhold) {
            return null;
        }
        Instant expires = now.plus(attestationTtl);
        if (outcome.getExpiresAt().isBefore(expires)) {
            expires = outcome.getExpiresAt();
        }
        return Attestation.issue(Attestation.Claim.ACTIVE_MODERATION_OUTCOME, outcome.getSubjectKeyFingerprint(),
                issuerKey, now, expires, outcome.getOutcomeId());
    }

    /**
     * Issues an adult attestation. Carries no date of birth or document data.
     * Only for a member whose assurance this hub has itself seen and accepted
     * under its own policy.
     */
    public Attestation issueAdult(String subjectKeyFingerprint, org.shalim.identity.AgeAssurance seen, Instant now) {
        if (!canIssue() || hub.getRoster().membershipOf(subjectKeyFingerprint).isEmpty()
                || seen == null || !seen.isValid(now)) {
            return null;
        }
        HubPolicy policy = hub.getPolicy();
        if (policy != null && policy.isRequireAgeAssurance() && !seen.satisfies(policy.getMinimumAssuranceMethod())) {
            return null;
        }
        Instant expires = now.plus(attestationTtl);
        Instant assuranceEnds = seen.getAssuredAt().plus(org.shalim.identity.AgeAssurance.validityOf(seen.getMethod()));
        if (assuranceEnds.isBefore(expires)) {
            expires = assuranceEnds;
        }
        return Attestation.issue(Attestation.Claim.ADULT, subjectKeyFingerprint, issuerKey, now, expires, null);
    }

    /**
     * Whether this hub is currently able to vouch for anyone. False while its
     * censor is flagged, and while it holds no key.
     */
    public boolean canIssue() {
        return issuerKey != null && hub != null
                && (hub.getCensorIntegrity() == null || !hub.getCensorIntegrity().requiresRestriction())
                // A provisional hub has not been checked, so it vouches for no one elsewhere.
                && (hub.getStanding() == null || hub.getStanding().getState() != org.shalim.hub.HubStanding.State.PROVISIONAL);
    }

    public java.time.Duration getAttestationTtl() {
        return attestationTtl;
    }

    public String getIssuerKeyFingerprint() {
        return issuerKeyFingerprint;
    }
}

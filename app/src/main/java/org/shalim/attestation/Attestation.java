package org.shalim.attestation;

import java.time.Instant;

/**
 * A signed, short-lived claim a user carries between hubs.
 *
 * <p>Deliberately inverted: hubs ask for a <em>proof of good standing</em>
 * rather than looking for a bad-news flag. A user-held flag can simply be
 * withheld, so absence of proof is what restricts, not presence of a mark.
 *
 * <p>Equally deliberately, an attestation says only "the issuer asserts this
 * claim about this key, until this time". It does not name which hubs the
 * subject belongs to. That is the whole point: it lets hub B act on hub A's
 * judgement without learning that the subject is in hub A, so no cross-hub
 * membership graph is built.
 */
public class Attestation {

    public enum Claim {
        /**
         * Subject is in good standing: no active moderation outcome, and not a
         * member of any hub whose censor is currently flagged. The everyday
         * claim, and the one whose absence caps you at guest.
         */
        GOOD_STANDING,

        /**
         * Subject has an active removal or suspension somewhere. Issued
         * alongside a {@link ModerationOutcome} so a receiving hub can weigh it.
         */
        ACTIVE_MODERATION_OUTCOME,

        /** Subject has been age-assured as an adult. Carries no date of birth. */
        ADULT
    }

    private String attestationId;
    private Claim claim;

    /** Fingerprint of the subject's key. The only identifier present. */
    private String subjectKeyFingerprint;

    /**
     * Fingerprint of the issuing hub's key — not its name or id. A receiving
     * hub can check the signature and decide whether it trusts this issuer
     * without the fingerprint revealing anything about the subject.
     */
    private String issuerKeyFingerprint;

    private Instant issuedAt;

    /**
     * Short by design. Expiry is what makes "leaving a flagged hub clears it"
     * actually work: nothing is revoked, the old proof simply lapses and the
     * next one comes back clean.
     */
    private Instant expiresAt;

    /** Detached signature over the claim, subject, and validity window. */
    private byte[] signature;

    /**
     * Present only for {@link Claim#ACTIVE_MODERATION_OUTCOME}, and only when
     * the issuer's policy permits sharing the reason.
     */
    private String outcomeId;

    public Attestation() {
        // TODO: pseudo-code
    }

    public boolean isValid(Instant now) {
        // TODO: pseudo-code
        return false;
    }

    /** Verifies the signature against the issuer's public key. */
    public boolean verify(byte[] issuerPublicKey) {
        // TODO: pseudo-code
        return false;
    }

    /** Whether this proof is close enough to expiry to be worth refreshing. */
    public boolean needsRefresh(Instant now) {
        // TODO: pseudo-code
        return false;
    }

    // --- accessors --------------------------------------------------------

    public String getAttestationId() {
        return attestationId;
    }

    public Claim getClaim() {
        return claim;
    }

    public String getSubjectKeyFingerprint() {
        return subjectKeyFingerprint;
    }

    public String getIssuerKeyFingerprint() {
        return issuerKeyFingerprint;
    }

    public Instant getIssuedAt() {
        return issuedAt;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public String getOutcomeId() {
        return outcomeId;
    }
}

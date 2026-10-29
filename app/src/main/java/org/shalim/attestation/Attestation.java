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

    /**
     * Clock skew tolerated on {@link #issuedAt}. Devices in a blackout drift,
     * and a proof issued a minute "in the future" by a fast hub clock should
     * not bounce.
     */
    public static final java.time.Duration MAX_CLOCK_SKEW = java.time.Duration.ofMinutes(5);

    public Attestation() {
    }

    private Attestation(String attestationId, Claim claim, String subjectKeyFingerprint,
                        String issuerKeyFingerprint, Instant issuedAt, Instant expiresAt,
                        String outcomeId, byte[] signature) {
        this.attestationId = attestationId;
        this.claim = claim;
        this.subjectKeyFingerprint = subjectKeyFingerprint;
        this.issuerKeyFingerprint = issuerKeyFingerprint;
        this.issuedAt = issuedAt;
        this.expiresAt = expiresAt;
        this.outcomeId = outcomeId;
        this.signature = signature == null ? null : signature.clone();
    }

    /**
     * Signs a new attestation. The decision whether to issue at all belongs
     * to {@link AttestationIssuer}. This only produces the signed record.
     */
    public static Attestation issue(Claim claim, String subjectKeyFingerprint,
                                    org.shalim.crypto.Signer issuerKey, Instant issuedAt,
                                    Instant expiresAt, String outcomeId) {
        if (!expiresAt.isAfter(issuedAt)) {
            throw new IllegalArgumentException("an attestation must expire after it is issued");
        }
        String id = org.shalim.crypto.Bytes.randomId();
        String issuerFp = issuerKey.fingerprint();
        byte[] signature = issuerKey.sign(payload(id, claim, subjectKeyFingerprint, issuerFp,
                issuedAt, expiresAt, outcomeId));
        return new Attestation(id, claim, subjectKeyFingerprint, issuerFp, issuedAt, expiresAt,
                outcomeId, signature);
    }

    /** An attestation as presented by its holder. Check with {@link #verify} and {@link #isValid}. */
    public static Attestation received(String attestationId, Claim claim, String subjectKeyFingerprint,
                                       String issuerKeyFingerprint, Instant issuedAt, Instant expiresAt,
                                       String outcomeId, byte[] signature) {
        return new Attestation(attestationId, claim, subjectKeyFingerprint, issuerKeyFingerprint,
                issuedAt, expiresAt, outcomeId, signature);
    }

    private static byte[] payload(String id, Claim claim, String subject, String issuer,
                                  Instant issuedAt, Instant expiresAt, String outcomeId) {
        return org.shalim.crypto.Canonical.of("shalim.attestation.v1").string(id).enumName(claim)
                .hex(subject).hex(issuer).instant(issuedAt).instant(expiresAt).string(outcomeId)
                .encode();
    }

    /** Inside its validity window, allowing {@link #MAX_CLOCK_SKEW} on issue time. */
    public boolean isValid(Instant now) {
        return issuedAt != null && expiresAt != null
                && !now.isBefore(issuedAt.minus(MAX_CLOCK_SKEW))
                && now.isBefore(expiresAt);
    }

    /**
     * Verifies the signature against the issuer's public key, and that the
     * key is the one {@link #issuerKeyFingerprint} names. Does not check
     * expiry; see {@link #isValid}.
     */
    public boolean verify(byte[] issuerPublicKey) {
        return claim != null
                && org.shalim.crypto.Fingerprints.matchesSigningKey(issuerKeyFingerprint, issuerPublicKey)
                && org.shalim.crypto.Ed25519.verify(issuerPublicKey, payload(attestationId, claim,
                        subjectKeyFingerprint, issuerKeyFingerprint, issuedAt, expiresAt, outcomeId),
                        signature);
    }

    /**
     * Whether this proof is close enough to expiry to be worth refreshing:
     * in the last quarter of its lifetime, or already expired.
     */
    public boolean needsRefresh(Instant now) {
        if (issuedAt == null || expiresAt == null) {
            return true;
        }
        java.time.Duration lifetime = java.time.Duration.between(issuedAt, expiresAt);
        return !now.isBefore(expiresAt.minus(lifetime.dividedBy(4)));
    }

    public byte[] getSignature() {
        return signature == null ? null : signature.clone();
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

package org.shalim.trust;

import java.time.LocalDate;

/**
 * What a prober presents to the target hub instead of their identity. Proves
 * "I am an ordinary, attested member of this hub who joined long enough ago",
 * plus two pseudonyms and a nullifier, and nothing else.
 *
 * <p>Produced by {@link MemberCredential#presentEligibility}; checked by
 * {@link ProberEligibility#checkInbound}.
 */
public class EligibilityProof {

    private final String targetHubKeyFingerprint;
    private final String auditingHubKeyFingerprint;
    private final LocalDate epoch;

    /** Opaque scheme proof of possession with predicates. */
    private final byte[] proof;

    /** Stable for (member, target, auditor). What the target records the link under. */
    private final String linkPseudonym;

    /** Stable for (member, target). Limits one member to carrying one link. */
    private final String proberPseudonym;

    /** Limits presentations to one per epoch per link; see {@link EpochNullifier}. */
    private final EpochNullifier nullifier;

    private final byte[] challenge;

    public EligibilityProof(String targetHubKeyFingerprint, String auditingHubKeyFingerprint, LocalDate epoch,
                            byte[] proof, String linkPseudonym, String proberPseudonym, EpochNullifier nullifier,
                            byte[] challenge) {
        this.targetHubKeyFingerprint = targetHubKeyFingerprint;
        this.auditingHubKeyFingerprint = auditingHubKeyFingerprint;
        this.epoch = epoch;
        this.proof = proof == null ? null : proof.clone();
        this.linkPseudonym = linkPseudonym;
        this.proberPseudonym = proberPseudonym;
        this.nullifier = nullifier;
        this.challenge = challenge == null ? null : challenge.clone();
    }

    /**
     * Verifies the proof against the target's issuer public key, with the
     * membership-age predicate set for {@code minMembershipDays} as of
     * {@code today}. Pass a negative {@code minMembershipDays} to verify
     * without the age predicate. Fails closed without a scheme.
     */
    public boolean verify(MemberCredentialScheme scheme, byte[] targetIssuerPublicKey, int minMembershipDays,
                          LocalDate today) {
        if (scheme == null || proof == null || nullifier == null || epoch == null || !epoch.equals(today)
                || !epoch.equals(nullifier.getEpoch())) {
            return false;
        }
        int maxWeek = minMembershipDays < 0 ? Integer.MAX_VALUE
                : MemberCredential.maxJoinedWeek(today, minMembershipDays);
        return scheme.verify(proof, targetIssuerPublicKey, targetHubKeyFingerprint, epoch, maxWeek, challenge,
                MemberCredential.boundValues(linkPseudonym, proberPseudonym, nullifier));
    }

    public String getTargetHubKeyFingerprint() {
        return targetHubKeyFingerprint;
    }

    public String getAuditingHubKeyFingerprint() {
        return auditingHubKeyFingerprint;
    }

    public LocalDate getEpoch() {
        return epoch;
    }

    public String getLinkPseudonym() {
        return linkPseudonym;
    }

    public String getProberPseudonym() {
        return proberPseudonym;
    }

    public EpochNullifier getNullifier() {
        return nullifier;
    }

    public byte[] getChallenge() {
        return challenge == null ? null : challenge.clone();
    }
}

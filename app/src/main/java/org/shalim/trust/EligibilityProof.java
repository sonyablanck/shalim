package org.shalim.trust;

import java.time.LocalDate;

/**
 * What a prober presents to the target hub instead of their identity. Proves
 * "I am an ordinary, attested member of this hub who joined long enough ago",
 * plus two pseudonyms and a nullifier, and nothing else.
 *
 * <p>Produced by {@link MemberCredential#presentEligibility}; checked by
 * {@link ProberEligibility#checkInbound}. Travels over the prober's ordinary
 * sync with the target, alongside everyone else's routine traffic.
 */
public class EligibilityProof {

    private String targetHubKeyFingerprint;
    private String auditingHubKeyFingerprint;
    private LocalDate epoch;

    /** Opaque BBS proof of possession with predicates. */
    private byte[] proof;

    /** Stable for (member, target, auditor). What the target records the link under. */
    private String linkPseudonym;

    /** Stable for (member, target). Limits one member to carrying one link. */
    private String proberPseudonym;

    /** Limits presentations to one per epoch per link; see {@link EpochNullifier}. */
    private EpochNullifier nullifier;

    private byte[] challenge;

    public EligibilityProof() {
        // TODO: pseudo-code
    }

    /** Verifies the BBS proof against the target's issuer public key. */
    public boolean verify(byte[] targetIssuerPublicKey, int minMembershipDays) {
        // PSEUDO-CODE
        // RETURN BBS.proofVerify(proof, targetIssuerPublicKey,
        //           disclosed = { target, ORDINARY, epoch },
        //           predicates = { attested, joined long enough ago },
        //           challenge)
        //    AND pseudonyms and nullifier are bound to the same hidden secret
        return false;
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
}

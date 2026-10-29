package org.shalim.trust;

import java.time.Instant;
import java.time.LocalDate;
import java.util.List;

/**
 * The target hub's memory of which nullifiers and pseudonyms it has seen. The
 * whole of what the target knows about its inbound probers.
 *
 * <p>Holds, per inbound link: the link pseudonym, the prober pseudonym, the
 * auditing hub's key, and today's nullifier. No user id. A seized target
 * device shows that some members probe for some hubs, and not which.
 */
public class NullifierRegistry {

    public enum Outcome {
        /** First presentation this epoch. */
        FRESH,
        /** Same nullifier, same challenge: a retransmission. Harmless. */
        REPLAYED,
        /** Same nullifier, different challenge: secret recovered, member traced. */
        DOUBLE_SPENT
    }

    private String hubKeyFingerprint;
    private LocalDate epoch;
    private List<EpochNullifier> seenThisEpoch;

    /** Prober pseudonym -> auditing hub key. At most one entry per pseudonym. */
    private List<String[]> proberAssignments;

    public NullifierRegistry() {
        // TODO: pseudo-code
    }

    public Outcome observe(EpochNullifier nullifier, Instant now) {
        // PSEUDO-CODE
        // IF nullifier.epoch != epoch -> roll over: clear seenThisEpoch
        // prior = seenThisEpoch WHERE nullifier == nullifier.nullifier
        // IF prior absent -> add; RETURN FRESH
        // IF prior.shareX == nullifier.shareX -> RETURN REPLAYED
        // RETURN DOUBLE_SPENT
        return null;
    }

    /**
     * Traces a double-spent nullifier to a membership. The one path by which
     * a prober's anonymity ends, and only reachable by their own client
     * breaking the protocol. Logged, and the member's prober pseudonym is
     * barred; their ordinary membership is untouched unless a moderator acts.
     */
    public String trace(EpochNullifier first, EpochNullifier second,
                        MemberCredentialIssuer issuer, Instant now) {
        // PSEUDO-CODE
        // secret = EpochNullifier.recoverSecret(first, second)
        // IF secret null -> RETURN null
        // membershipId = issuer commitment table WHERE commitment == H(secret)
        // log NULLIFIER_DOUBLE_SPENT (membershipId)
        // RETURN membershipId
        return null;
    }

    /** Whether this member already carries a link for a different auditing hub. */
    public boolean proberAlreadyAssigned(String proberPseudonym, String auditingHubKeyFingerprint) {
        // TODO: pseudo-code
        return false;
    }

    public void assign(String proberPseudonym, String auditingHubKeyFingerprint) {
        // TODO: pseudo-code
    }

    /** Duress path. */
    public void wipe() {
        // TODO: pseudo-code
    }

    public String getHubKeyFingerprint() {
        return hubKeyFingerprint;
    }
}

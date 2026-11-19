package org.shalim.trust;

import java.time.LocalDate;
import java.util.HashMap;
import java.util.Map;

/**
 * The target hub's memory of which nullifiers and pseudonyms it has seen. The
 * whole of what the target knows about its inbound probers.
 *
 * <p>Holds: today's nullifiers, and each prober pseudonym's auditing hub. No
 * user id. A seized target device shows that some members probe for some
 * hubs, and not which.
 */
public class NullifierRegistry {

    public enum Outcome {
        /** First presentation this epoch. */
        FRESH,
        /** Same nullifier, same share: a retransmission. Harmless. */
        REPLAYED,
        /** Same nullifier, different share: secret recoverable, member traceable. */
        DOUBLE_SPENT
    }

    private final String hubKeyFingerprint;
    private LocalDate epoch;
    private final Map<String, EpochNullifier> seenThisEpoch = new HashMap<>();

    /** Prober pseudonym -> auditing hub key. At most one entry per pseudonym. */
    private final Map<String, String> proberAssignments = new HashMap<>();

    /** Pseudonyms barred after a double spend. */
    private final java.util.Set<String> barred = new java.util.HashSet<>();

    public NullifierRegistry(String hubKeyFingerprint) {
        this.hubKeyFingerprint = hubKeyFingerprint;
    }

    public synchronized Outcome observe(EpochNullifier nullifier) {
        if (!nullifier.getEpoch().equals(epoch)) {
            epoch = nullifier.getEpoch();
            seenThisEpoch.clear();
        }
        EpochNullifier prior = seenThisEpoch.get(nullifier.getNullifier());
        if (prior == null) {
            seenThisEpoch.put(nullifier.getNullifier(), nullifier);
            return Outcome.FRESH;
        }
        return prior.sameShareAs(nullifier) ? Outcome.REPLAYED : Outcome.DOUBLE_SPENT;
    }

    /** The share first seen under this nullifier today, for {@link #trace}. */
    public synchronized EpochNullifier firstSeen(String nullifier) {
        return seenThisEpoch.get(nullifier);
    }

    /**
     * Traces a double-spent nullifier to a membership. The one path by which
     * a prober's anonymity ends, reachable only by their own client breaking
     * the protocol. The caller logs it and bars the prober pseudonym; the
     * member's ordinary membership is untouched unless a moderator acts.
     */
    public synchronized String trace(EpochNullifier first, EpochNullifier second, MemberCredentialIssuer issuer) {
        byte[] secret = EpochNullifier.recoverSecret(first, second);
        if (secret == null) {
            return null;
        }
        String membershipId = issuer.membershipForCommitment(EpochNullifier.commitment(secret));
        org.shalim.crypto.Bytes.wipe(secret);
        return membershipId;
    }

    /** Whether this member already carries a link for a different auditing hub. */
    public synchronized boolean proberAlreadyAssigned(String proberPseudonym, String auditingHubKeyFingerprint) {
        String assigned = proberAssignments.get(proberPseudonym);
        return assigned != null && !assigned.equals(auditingHubKeyFingerprint);
    }

    public synchronized void assign(String proberPseudonym, String auditingHubKeyFingerprint) {
        proberAssignments.putIfAbsent(proberPseudonym, auditingHubKeyFingerprint);
    }

    /** Frees a pseudonym when its link ends, so the member may carry another. */
    public synchronized void release(String proberPseudonym, String auditingHubKeyFingerprint) {
        proberAssignments.remove(proberPseudonym, auditingHubKeyFingerprint);
    }

    public synchronized void bar(String proberPseudonym) {
        barred.add(proberPseudonym);
    }

    public synchronized boolean isBarred(String proberPseudonym) {
        return barred.contains(proberPseudonym);
    }

    /** Duress path. */
    public synchronized void wipe() {
        seenThisEpoch.clear();
        proberAssignments.clear();
        barred.clear();
        epoch = null;
    }

    public String getHubKeyFingerprint() {
        return hubKeyFingerprint;
    }
}

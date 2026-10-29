package org.shalim.trust;

import java.time.Instant;
import java.util.List;

/**
 * The audit trail for authentication: every replayed leaf, every synthetic
 * probe and every organic score, per peer, with what each side did and the
 * score it got.
 *
 * <p>Retained for exactly as long as meeting requests and Matchmaker queries —
 * {@code HubPolicy.meetingRequestRetentionDays}, a fortnight by default — and
 * pruned on the same schedule. Not longer: a ledger is a dated record that
 * this hub's admin was in contact with particular peers, and on a seized
 * device that is the cross-hub graph by another route. Not shorter: a
 * revocation must be appealable, and an appeal needs the evidence that caused
 * it. A revocation is therefore only ever decided on probes still in the
 * ledger.
 *
 * <h2>What the ledger does not hold</h2>
 *
 * <p><strong>Plaintext of any kind.</strong> Synthetic probes are kept as
 * hash and generation seed and regenerated for an appeal. Replayed leaves are
 * kept as the peer's signed leaf hash, head and this hub's replay verdict;
 * the member question behind a leaf was decrypted, replayed and discarded
 * within {@link ReplayAuditor#replay}, and is never on this device again.
 * Organic probes are kept as the score alone.
 *
 * <p>No supply-request text is on this device at all any more: the old
 * daily FAIL probe, and the fortnight of apparent drug requests it left under
 * the admin's identity, are gone.
 *
 * <p><strong>Anything the peer's Matchmaker returned.</strong> Only censor
 * behaviour is recorded, as in {@link ProbeOutcome}.
 *
 * <p><strong>Hub ids.</strong> Peers are recorded by key fingerprint.
 */
public class ProbeLedger {

    /** One probe, sent to one hub, and what came back. */
    public static class Entry {
        private String entryId;
        private String runId;
        private String probeId;
        private String probeTextHash;
        private long generationSeed;
        private String seedProbeId;
        private String generatorPinHash;
        private TrustProbe.Intent intent;

        /** REPLAY, ORGANIC or SYNTHETIC. */
        private AuditRun.Kind kind;

        /** Replay only: the peer's leaf hash and the day's signed root. */
        private String leafHash;
        private String headRootHash;

        /** Key fingerprint of the hub the probe went to; this hub's own for the local leg. */
        private String targetKeyFingerprint;

        private org.shalim.ml.CensorEngine.Decision decision;
        private float confidence;
        private float differenceMagnitude;
        private AuditAnomaly.Attribution attribution;

        private Instant sentAt;
        private Instant answeredAt;

        public Entry() {
            // TODO: pseudo-code
        }

        public String getRunId() {
            return runId;
        }

        public String getProbeId() {
            return probeId;
        }

        public String getTargetKeyFingerprint() {
            return targetKeyFingerprint;
        }

        public Instant getSentAt() {
            return sentAt;
        }
    }

    private String ownerKeyFingerprint;
    private List<Entry> entries;

    public ProbeLedger() {
        // TODO: pseudo-code
    }

    public ProbeLedger(String ownerKeyFingerprint) {
        // TODO: pseudo-code
    }

    /** Records one leg of a run. Called for the local leg and each peer leg. */
    public Entry record(TrustProbe probe, ProbeOutcome outcome, DifferenceScore score) {
        // PSEUDO-CODE
        // entry = Entry from probe provenance (hash + seed, never text),
        //         outcome decision/confidence, score magnitude/attribution
        // entries.add(entry)
        // RETURN entry
        return null;
    }

    /** Records one replayed leaf. No text: only the peer's commitment and our verdict. */
    public Entry recordReplay(String peerKeyFingerprint, org.shalim.hub.CensorDecisionLog.SignedTreeHead head,
                              org.shalim.hub.CensorDecisionLog.Leaf leaf, org.shalim.ml.Verdict mine,
                              boolean mismatch) {
        // TODO: pseudo-code
        return null;
    }

    /** Records one organic score forwarded by the prober's device. */
    public Entry recordOrganic(DifferenceScore score) {
        // TODO: pseudo-code
        return null;
    }

    /** Entries about one peer within a window, for WebOfTrust.assess. */
    public List<Entry> forPeer(String peerKeyFingerprint, Instant since) {
        // TODO: pseudo-code
        return null;
    }

    /**
     * The evidence behind one revocation, with probe texts regenerated. Shown
     * only to admins of this hub, and to the revoked hub's admins if this
     * hub's admin chooses to disclose.
     */
    public List<Entry> evidenceFor(String revocationId, org.shalim.ml.ProbeEngine prober) {
        // TODO: pseudo-code
        return null;
    }

    /**
     * Drops entries older than the meeting-request retention window. Expected
     * to run daily, not optional.
     */
    public int prune(org.shalim.hub.HubPolicy policy, Instant now) {
        // PSEUDO-CODE
        // cutoff = now - policy.meetingRequestRetentionDays
        // DROP entries WHERE sentAt < cutoff
        //    EXCEPT entries cited by a revocation currently under appeal
        //    // Those are kept until the appeal closes, then dropped with it.
        return 0;
    }

    /** Duress path, alongside HubLog.wipe. */
    public void wipe() {
        // TODO: pseudo-code
    }

    public List<Entry> getEntries() {
        return entries;
    }
}

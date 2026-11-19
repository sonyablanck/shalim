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
            this.entryId = org.shalim.crypto.Bytes.randomId();
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

        public AuditRun.Kind getKind() {
            return kind;
        }

        public String getEntryId() {
            return entryId;
        }

        public String getProbeTextHash() {
            return probeTextHash;
        }

        public long getGenerationSeed() {
            return generationSeed;
        }

        public String getSeedProbeId() {
            return seedProbeId;
        }

        public TrustProbe.Intent getIntent() {
            return intent;
        }

        public String getLeafHash() {
            return leafHash;
        }

        public String getHeadRootHash() {
            return headRootHash;
        }

        public org.shalim.ml.CensorEngine.Decision getDecision() {
            return decision;
        }

        public float getConfidence() {
            return confidence;
        }

        public float getDifferenceMagnitude() {
            return differenceMagnitude;
        }

        public AuditAnomaly.Attribution getAttribution() {
            return attribution;
        }

        /** Whether this entry is usable evidence: a scored leaf or a scoreable probe. */
        public boolean isScoreable() {
            return attribution != null;
        }
    }

    /** Revocation id -> entry ids, kept past retention while the revocation is under appeal. */
    private final java.util.Map<String, java.util.Set<String>> pinned = new java.util.HashMap<>();
    private final java.util.Set<String> underAppeal = new java.util.HashSet<>();

    private String ownerKeyFingerprint;
    private List<Entry> entries;

    public ProbeLedger() {
        this.entries = new java.util.ArrayList<>();
    }

    public ProbeLedger(String ownerKeyFingerprint) {
        this();
        this.ownerKeyFingerprint = ownerKeyFingerprint;
    }

    /** Records one leg of a run. Called for the local leg and each peer leg. */
    public Entry record(TrustProbe probe, ProbeOutcome outcome, DifferenceScore score) {
        Entry e = new Entry();
        e.runId = outcome == null ? null : outcome.getRunId();
        e.kind = AuditRun.Kind.SYNTHETIC;
        e.probeId = probe.getProbeId();
        e.probeTextHash = probe.getTextHash();
        e.generationSeed = probe.getGenerationSeed();
        e.seedProbeId = probe.getSeedProbeId();
        e.generatorPinHash = probe.getGeneratorPinHash();
        e.intent = probe.getIntent();
        e.targetKeyFingerprint = outcome == null ? null : outcome.getProducedByKeyFingerprint();
        e.decision = outcome == null ? null : outcome.getDecision();
        e.confidence = outcome == null ? 0f : outcome.getConfidence();
        e.differenceMagnitude = score == null ? 0f : score.getMagnitude();
        e.attribution = score == null || !score.isScoreable() ? null : score.attribution();
        e.sentAt = outcome == null || outcome.getRespondedAt() == null ? Instant.now() : outcome.getRespondedAt();
        e.answeredAt = e.sentAt;
        synchronized (this) {
            entries.add(e);
        }
        return e;
    }

    /** Records one replayed leaf. No text: only the peer's commitment and our verdict. */
    public Entry recordReplay(String peerKeyFingerprint, org.shalim.hub.CensorDecisionLog.SignedTreeHead head,
                              org.shalim.hub.CensorDecisionLog.Leaf leaf, org.shalim.ml.Verdict mine,
                              boolean mismatch, String runId, Instant now) {
        Entry e = new Entry();
        e.runId = runId;
        e.kind = AuditRun.Kind.REPLAY;
        e.targetKeyFingerprint = peerKeyFingerprint;
        e.leafHash = leaf.getLeafHash();
        e.headRootHash = head.getRootHash();
        e.decision = mine == null ? null : mine.getDecision();
        e.confidence = mine == null ? 0f : mine.getConfidence();
        e.differenceMagnitude = mismatch ? 1f : 0f;
        // Null attribution marks a leaf too close to a threshold to score.
        e.attribution = mine == null ? null
                : mismatch ? AuditAnomaly.Attribution.PEER : AuditAnomaly.Attribution.UNDETERMINED;
        e.sentAt = now;
        e.answeredAt = now;
        synchronized (this) {
            entries.add(e);
        }
        return e;
    }

    /** Records one organic score forwarded by the prober's device. */
    public Entry recordOrganic(DifferenceScore score, Instant now) {
        Entry e = new Entry();
        e.runId = score.getRunId();
        e.kind = AuditRun.Kind.ORGANIC;
        e.probeId = score.getProbeId();
        e.intent = score.getIntent();
        e.targetKeyFingerprint = score.getPeerKeyFingerprint();
        e.differenceMagnitude = score.getMagnitude();
        e.attribution = score.isScoreable() ? score.attribution() : null;
        e.sentAt = now;
        e.answeredAt = now;
        synchronized (this) {
            entries.add(e);
        }
        return e;
    }

    /** Entries about one peer within a window, for WebOfTrust.assess. */
    public List<Entry> forPeer(String peerKeyFingerprint, Instant since) {
        List<Entry> out = new java.util.ArrayList<>();
        synchronized (this) {
            for (Entry e : entries) {
                if (peerKeyFingerprint.equals(e.targetKeyFingerprint) && !e.sentAt.isBefore(since)) {
                    out.add(e);
                }
            }
        }
        return out;
    }

    /**
     * The evidence behind one revocation, with probe texts regenerated. Shown
     * only to admins of this hub, and to the revoked hub's admins if this
     * hub's admin chooses to disclose.
     */
    public List<Entry> evidenceFor(String revocationId, org.shalim.ml.ProbeEngine prober) {
        java.util.Set<String> ids = pinned.getOrDefault(revocationId, java.util.Set.of());
        List<Entry> out = new java.util.ArrayList<>();
        synchronized (this) {
            for (Entry e : entries) {
                if (ids.contains(e.entryId)) {
                    out.add(e);
                }
            }
        }
        // Synthetic texts are regenerated from (seed, generator pin) by the
        // prober when an admin opens the evidence, never stored here.
        return out;
    }

    /**
     * Drops entries older than the meeting-request retention window. Expected
     * to run daily, not optional.
     */
    public int prune(org.shalim.hub.HubPolicy policy, Instant now) {
        Instant cutoff = now.minus(java.time.Duration.ofDays(policy.getMeetingRequestRetentionDays()));
        java.util.Set<String> keep = new java.util.HashSet<>();
        for (String rev : underAppeal) {
            keep.addAll(pinned.getOrDefault(rev, java.util.Set.of()));
        }
        int before;
        synchronized (this) {
            before = entries.size();
            entries.removeIf(e -> e.sentAt.isBefore(cutoff) && !keep.contains(e.entryId));
        }
        // Pins whose entries are all gone, and that are not under appeal, go too.
        pinned.entrySet().removeIf(p -> !underAppeal.contains(p.getKey())
                && p.getValue().stream().noneMatch(id -> entries.stream().anyMatch(e -> e.entryId.equals(id))));
        return before - entries.size();
    }

    /** Duress path, alongside HubLog.wipe. */
    public void wipe() {
        synchronized (this) {
            entries.clear();
        }
        pinned.clear();
        underAppeal.clear();
    }

    /** Pins the entries behind a revocation, so the evidence outlives retention while appealed. */
    void pin(String revocationId, List<Entry> evidence) {
        java.util.Set<String> ids = new java.util.HashSet<>();
        evidence.forEach(e -> ids.add(e.entryId));
        pinned.put(revocationId, ids);
    }

    void openAppeal(String revocationId) {
        underAppeal.add(revocationId);
    }

    void closeAppeal(String revocationId) {
        underAppeal.remove(revocationId);
    }

    public String getOwnerKeyFingerprint() {
        return ownerKeyFingerprint;
    }

    public List<Entry> getEntries() {
        return entries;
    }
}

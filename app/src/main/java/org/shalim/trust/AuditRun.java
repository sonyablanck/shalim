package org.shalim.trust;

import java.time.Instant;
import java.util.List;

/**
 * One unit of evidence about one peer: a day's replay, a batch of organic
 * scores, or one synthetic probe — with both sides' outcomes, the
 * {@link DifferenceScore}s, and any anomalies.
 *
 * <p>Synthetic and organic runs are far too small to conclude anything alone,
 * so their {@link #verdict()} is almost always {@link Verdict#INCONCLUSIVE}
 * and that is expected. A replay run can be conclusive on its own, because a
 * replayed leaf that the pinned model contradicts is not a statistical
 * finding. Decisions about a link
 * are made over the rolling window in {@link WebOfTrust#assess}, never on a
 * single run. The run is kept in the {@link ProbeLedger} for the same period
 * as meeting requests, with key fingerprints rather than hub ids.
 */
public class AuditRun {

    /** Which evidence stream produced this run. */
    public enum Kind {
        /** Sampled leaves of the peer's CensorDecisionLog, replayed locally. */
        REPLAY,
        /** Scores forwarded from the prober's device for their own real questions. */
        ORGANIC,
        /** One generated PASS-side probe, Poisson-scheduled. */
        SYNTHETIC
    }

    private Kind kind;

    /** What the run concluded. Advisory; links change state only in WebOfTrust.assess. */
    public enum Verdict {
        /** Peer matched the corpus within tolerance on an adequate sample. */
        PASSED,
        /** Peer diverged from the corpus, conclusively and attributably. */
        FAILED,
        /**
         * Sample too small, too degraded, or too noisy to say. The common case.
         * The link is left alone; the rolling window decides.
         */
        INCONCLUSIVE,
        /**
         * The auditor's own instance was the outlier. Not a finding about the
         * peer at all, and must not be recorded as one.
         */
        LOCAL_FAULT,
        /**
         * Corpus hashes differed, the peer detected probing, or the run was cut
         * short. No conclusion is drawn, because a run whose conditions were not
         * met measures nothing.
         */
        VOID
    }

    private String runId;

    /** Peer's issuer key fingerprint. Never their hub id or name. */
    private String peerKeyFingerprint;

    private String corpusVersion;
    private String corpusHash;

    /** Exchanged with the peer, so either side can reproduce the sample. */
    private long sampleSeed;

    private List<TrustProbe> sample;
    private List<ProbeOutcome> localOutcomes;
    private List<ProbeOutcome> peerOutcomes;

    private List<AuditAnomaly> anomalies;

    /** One per scored probe. What the window assessment reads. */
    private List<DifferenceScore> scores;

    private Instant startedAt;
    private Instant completedAt;

    /** Transport the run went over. A LoRa run cannot carry a real sample. */
    private org.shalim.transport.Transport.Kind via;

    /**
     * Whether the peer knows a run happened. False by default, and the reason
     * probes must look like ordinary queries. Set when a finding is disclosed —
     * see {@link PeerAuditor#disclose}.
     */
    private boolean disclosed;

    /** Replay: leaves the sample called for, real leaves scored, and of those, matches. */
    private int replayExpected;
    private int replayRealScored;
    private int replayMatched;
    private int replayPads;
    private int replayUndetermined;

    /** Replay: the peer's leaves came from a different censor release than ours. */
    private boolean pinMismatch;

    /** The local censor (or prober device's) was not verified, so nothing was measured. */
    private boolean localUnverified;

    /** Scoreable synthetic or organic outcomes needed before a run says anything. */
    static final int MIN_SCOREABLE = 3;

    public AuditRun() {
        this.runId = org.shalim.crypto.Bytes.randomId();
        this.sample = new java.util.ArrayList<>();
        this.localOutcomes = new java.util.ArrayList<>();
        this.peerOutcomes = new java.util.ArrayList<>();
        this.anomalies = new java.util.ArrayList<>();
        this.scores = new java.util.ArrayList<>();
    }

    public AuditRun(String peerKeyFingerprint, ProbeCorpus corpus, long sampleSeed) {
        this();
        this.kind = Kind.SYNTHETIC;
        this.peerKeyFingerprint = peerKeyFingerprint;
        this.corpusVersion = corpus == null ? null : corpus.getVersion();
        this.corpusHash = corpus == null ? null : corpus.getCorpusHash();
        this.sampleSeed = sampleSeed;
    }

    /**
     * Scores the run. Compares each side against the corpus first and only then
     * against each other, because the corpus is what makes a divergence
     * attributable rather than merely mutual.
     */
    public Verdict verdict() {
        // 1. Validity gate. A run whose conditions were not met measures nothing.
        if (localUnverified || pinMismatch || has(AuditAnomaly.Kind.PROBE_DETECTION)) {
            return Verdict.VOID;
        }
        if (kind == Kind.SYNTHETIC && (sample.isEmpty() || localOutcomes.isEmpty() || peerOutcomes.isEmpty())) {
            return Verdict.VOID;
        }
        // 1b. Replay is decided directly.
        if (kind == Kind.REPLAY) {
            for (AuditAnomaly a : anomalies) {
                if (a.getAttribution() == AuditAnomaly.Attribution.PEER && (a.getKind() == AuditAnomaly.Kind.REPLAY_MISMATCH
                        || a.getKind() == AuditAnomaly.Kind.EQUIVOCATION
                        || a.getKind() == AuditAnomaly.Kind.UNLOGGED_DECISION
                        || (a.getKind() == AuditAnomaly.Kind.OPENING_WITHHELD && a.isConfirmedOnRetry()))) {
                    return Verdict.FAILED;
                }
            }
            boolean allOpened = anomalies.stream().noneMatch(a -> a.getKind() == AuditAnomaly.Kind.OPENING_WITHHELD);
            return allOpened && replayExpected > 0 && replayMatched == replayRealScored ? Verdict.PASSED
                    : Verdict.INCONCLUSIVE;
        }
        // An unlogged receipt is conclusive whatever the sample size.
        if (anomalies.stream().anyMatch(a -> a.isConclusive() && a.getKind() == AuditAnomaly.Kind.UNLOGGED_DECISION)) {
            return Verdict.FAILED;
        }
        // 2. Power gate. The usual exit; the window decides.
        List<DifferenceScore> scoreable = scores.stream().filter(DifferenceScore::isScoreable).toList();
        if (scoreable.size() < MIN_SCOREABLE) {
            return Verdict.INCONCLUSIVE;
        }
        // 3. Each side against the corpus, separately.
        long peerMisses = scoreable.stream().filter(s -> !s.isPeerMetExpectation()).count();
        long localMisses = scoreable.stream().filter(s -> !s.isLocalMetExpectation()).count();
        // 4. Attribute before concluding: the audit may have found the auditor.
        if (localMisses > peerMisses) {
            return Verdict.LOCAL_FAULT;
        }
        // 5. Conclude about the peer.
        if (anomalies.stream().anyMatch(AuditAnomaly::isConclusive)) {
            return Verdict.FAILED;
        }
        return peerMisses == 0 ? Verdict.PASSED : Verdict.INCONCLUSIVE;
    }

    /**
     * Anomalies the auditing admin is shown. Includes findings against the
     * auditor's own hub, which are shown first — the local fault is the one the
     * admin can actually fix, and the one they are least likely to look for.
     */
    public List<AuditAnomaly> flagged() {
        List<AuditAnomaly> out = new java.util.ArrayList<>();
        anomalies.stream().filter(AuditAnomaly::concernsAuditor).forEach(out::add);
        anomalies.stream().filter(a -> !a.concernsAuditor()).forEach(out::add);
        return out;
    }

    /** Probe ids that would be revealed by disclosing this run's findings. */
    public List<String> probesSpentByDisclosure() {
        if (kind != Kind.SYNTHETIC) {
            return List.of(); // replay cites the peer's own leaves; organic is never disclosed
        }
        List<String> out = new java.util.ArrayList<>();
        for (AuditAnomaly a : anomalies) {
            for (String id : a.getProbeIds()) {
                if (!out.contains(id)) {
                    out.add(id);
                }
            }
        }
        return out;
    }

    /** A replay run against one peer for one day. */
    public static AuditRun replay(String peerKeyFingerprint, java.time.LocalDate day, int expected, Instant now) {
        AuditRun r = new AuditRun();
        r.kind = Kind.REPLAY;
        r.peerKeyFingerprint = peerKeyFingerprint;
        r.replayExpected = expected;
        r.startedAt = now;
        return r;
    }

    /** A run carrying organic scores, or a receipt finding, from the prober's device. */
    public static AuditRun organic(String peerKeyFingerprint, Instant now) {
        AuditRun r = new AuditRun();
        r.kind = Kind.ORGANIC;
        r.peerKeyFingerprint = peerKeyFingerprint;
        r.startedAt = now;
        return r;
    }

    void addAnomaly(AuditAnomaly a) {
        a.setRunId(runId);
        anomalies.add(a);
    }

    void addProbe(TrustProbe probe, ProbeOutcome local, ProbeOutcome peer, DifferenceScore score) {
        if (probe != null) {
            sample.add(probe);
        }
        if (local != null) {
            local.setRunId(runId);
            localOutcomes.add(local);
        }
        if (peer != null) {
            peer.setRunId(runId);
            peerOutcomes.add(peer);
        }
        if (score != null) {
            score.setRunId(runId);
            scores.add(score);
        }
    }

    void countReplay(boolean pad, boolean undetermined, boolean matched) {
        if (pad) {
            replayPads++;
        } else if (undetermined) {
            replayUndetermined++;
        } else {
            replayRealScored++;
            if (matched) {
                replayMatched++;
            }
        }
    }

    void markPinMismatch() {
        this.pinMismatch = true;
    }

    void markLocalUnverified() {
        this.localUnverified = true;
    }

    void complete(Instant now, org.shalim.transport.Transport.Kind via) {
        if (this.startedAt == null) {
            this.startedAt = now;
        }
        this.completedAt = now;
        this.via = via;
    }

    void markDisclosed() {
        this.disclosed = true;
    }

    boolean has(AuditAnomaly.Kind k) {
        return anomalies.stream().anyMatch(a -> a.getKind() == k);
    }

    public List<TrustProbe> getSample() {
        return sample;
    }

    public int getReplayExpected() {
        return replayExpected;
    }

    /** Real (non-pad) leaves scored in this replay, excluding near-threshold ones. */
    public int getReplayRealScored() {
        return replayRealScored;
    }

    public int getReplayMatched() {
        return replayMatched;
    }

    public int getReplayPads() {
        return replayPads;
    }

    public int getReplayUndetermined() {
        return replayUndetermined;
    }

    public boolean isPinMismatch() {
        return pinMismatch;
    }

    // --- accessors --------------------------------------------------------

    public String getRunId() {
        return runId;
    }

    public Kind getKind() {
        return kind;
    }

    public String getPeerKeyFingerprint() {
        return peerKeyFingerprint;
    }

    public String getCorpusVersion() {
        return corpusVersion;
    }

    public String getCorpusHash() {
        return corpusHash;
    }

    public long getSampleSeed() {
        return sampleSeed;
    }

    public List<ProbeOutcome> getLocalOutcomes() {
        return localOutcomes;
    }

    public List<ProbeOutcome> getPeerOutcomes() {
        return peerOutcomes;
    }

    public List<DifferenceScore> getScores() {
        return scores;
    }

    public List<AuditAnomaly> getAnomalies() {
        return anomalies;
    }

    public Instant getStartedAt() {
        return startedAt;
    }

    public Instant getCompletedAt() {
        return completedAt;
    }

    public org.shalim.transport.Transport.Kind getVia() {
        return via;
    }

    public boolean isDisclosed() {
        return disclosed;
    }
}

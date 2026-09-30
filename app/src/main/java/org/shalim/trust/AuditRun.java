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

    public AuditRun() {
        // TODO: pseudo-code
    }

    public AuditRun(String peerKeyFingerprint, ProbeCorpus corpus, long sampleSeed) {
        // TODO: pseudo-code
    }

    /**
     * Scores the run. Compares each side against the corpus first and only then
     * against each other, because the corpus is what makes a divergence
     * attributable rather than merely mutual.
     */
    public Verdict verdict() {
        // PSEUDO-CODE
        //
        // 1. VALIDITY GATE
        //    IF corpus hashes differed
        //       OR anomalies contain PROBE_DETECTION
        //       OR (kind == SYNTHETIC AND sample not answered by both sides)
        //       OR (kind == REPLAY AND the two hubs' censor pins differ)
        //       RETURN VOID
        //       // A peer that can spot probes can pass an audit it should fail,
        //       // so once detection is suspected nothing else in the run means
        //       // anything and none of it is recorded as a finding.
        //
        // 1b. REPLAY IS DECIDED DIRECTLY
        //    IF kind == REPLAY
        //       IF anomalies contain REPLAY_MISMATCH, EQUIVOCATION or
        //          OPENING_WITHHELD attributed to PEER -> RETURN FAILED
        //       IF every expected leaf opened and matched -> RETURN PASSED
        //       RETURN INCONCLUSIVE
        //
        // 2. POWER GATE (synthetic and organic)
        //    scoreable = outcomes WHERE isScoreable() on BOTH sides
        //    IF scoreable.size() < policy minimum -> RETURN INCONCLUSIVE
        //       // The usual exit. The window in WebOfTrust.assess decides.
        //       // There is no FAIL-expectation requirement any more: synthetic
        //       // probes are PASS-side only, and under-blocking is replay's job.
        //
        // 3. SCORE EACH SIDE AGAINST THE CORPUS, SEPARATELY
        //    peerMisses  = scoreable WHERE NOT peerOutcome.satisfies(probe)
        //    localMisses = scoreable WHERE NOT localOutcome.satisfies(probe)
        //
        // 4. ATTRIBUTE BEFORE CONCLUDING
        //    IF localMisses materially exceed peerMisses -> RETURN LOCAL_FAULT
        //       // The audit found the auditor. This is not a rare corner: a hub
        //       // whose admin has been pressured into retuning its censor will
        //       // find every honest peer "failing", and without this branch it
        //       // would spend the web of trust convicting them one by one.
        //
        // 5. CONCLUDE ABOUT THE PEER
        //    IF any anomaly WHERE attribution == PEER AND isConclusive()
        //       RETURN FAILED
        //    IF peerMisses within tolerance -> RETURN PASSED
        //    RETURN INCONCLUSIVE
        return null;
    }

    /**
     * Anomalies the auditing admin is shown. Includes findings against the
     * auditor's own hub, which are shown first — the local fault is the one the
     * admin can actually fix, and the one they are least likely to look for.
     */
    public List<AuditAnomaly> flagged() {
        // TODO: pseudo-code
        return null;
    }

    /** Probe ids that would be revealed by disclosing this run's findings. */
    public List<String> probesSpentByDisclosure() {
        // TODO: pseudo-code
        return null;
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

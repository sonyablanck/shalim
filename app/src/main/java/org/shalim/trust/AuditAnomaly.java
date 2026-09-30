package org.shalim.trust;

import java.util.List;

/**
 * One statistically flagged divergence in an audit run, together with the
 * audit's best answer to the question that actually matters: <em>which
 * instance moved?</em>
 *
 * <p>Attribution is the whole point of this class. A bare comparison of two
 * hubs yields a divergence and nothing more, and a divergence is symmetric —
 * it looks identical whether the peer has been hooked or the auditor has. An
 * auditor that treats every divergence as the peer's fault is a machine for
 * blaming whoever it disagrees with, which in a network containing both a state
 * hub and the people it is hunting is not a safety feature.
 *
 * <p>So each anomaly is scored twice: peer against the pinned corpus, and
 * auditor against the pinned corpus. The corpus is the third opinion that
 * breaks the tie. The finding an auditor least wants and most needs —
 * {@link Attribution#LOCAL} — is reachable from here, and is shown to the
 * auditing admin with the same prominence as anything about the peer.
 */
public class AuditAnomaly {

    /** What the run measured. Each has a different meaning and a different remedy. */
    public enum Kind {
        /**
         * Peer let explicit supply or coordination through. The finding the
         * audit exists for.
         */
        UNDER_BLOCKING,
        /**
         * Peer blocked protected speech — overdose response, abortion access,
         * border crossing. Not a censor that is broken; a censor that has been
         * retuned, which is what a hub under state direction looks like from
         * outside. Reported separately from under-blocking and never averaged
         * with it, because averaging lets a hub buy tolerance for suppression
         * with enthusiasm about drugs.
         */
        OVER_BLOCKING,
        /** Decisions agree but assigned harm categories do not. Weak signal alone. */
        CATEGORY_DISAGREEMENT,
        /**
         * Decisions are right and confidences are not plausibly model output —
         * clustered at extremes, quantised, or identical across unrelated
         * probes. What a lookup table in front of a dead model looks like.
         */
        DEGENERATE_CONFIDENCE,
        /** Peer's advertised pin differs from ours. Corroborating, not conclusive. */
        PIN_DIVERGENCE,
        /**
         * Peer answered probes differently from ordinary queries, or answered
         * suspiciously fast. Evidence of probe detection: the peer knows it is
         * being tested. Any amount of this invalidates the whole run. Rarer
         * now that the peer does not know who the prober is, and irrelevant
         * to replay, which does not depend on the peer being fooled.
         */
        PROBE_DETECTION,
        /**
         * A replayed leaf that the pinned model contradicts — decision,
         * categories or confidence beyond tolerance — or an action taken that
         * does not follow from the logged decision. Near-proof on its own:
         * the pinned model is deterministic and the peer committed before the
         * sample was chosen.
         */
        REPLAY_MISMATCH,
        /**
         * The peer signed two different trees for one day, or broke the chain
         * of daily heads. Conclusive: an honest hub never does either.
         */
        EQUIVOCATION,
        /**
         * A member's receipt, signed by the peer, is not in the tree the peer
         * showed this auditor. The peer routed that screening around its log,
         * or showed auditors a different log from the one it served.
         */
        UNLOGGED_DECISION,
        /**
         * The peer did not open a sampled leaf, sent an invalid proof, or a
         * pad that did not open as a pad. Counts only after a retry on the
         * next sync.
         */
        OPENING_WITHHELD,
        /**
         * Peer declined, timed out, or returned degraded on most of the sample.
         * Not a failure. Recorded so a hub is not revoked for having a flat
         * battery during a blackout — it goes DORMANT instead.
         */
        INSUFFICIENT_SAMPLE
    }

    /** Which instance the evidence points at. */
    public enum Attribution {
        /** Peer diverges from the corpus; auditor matches it. */
        PEER,
        /**
         * Auditor diverges from the corpus; peer matches it. The auditor's own
         * censor is the outlier, and the audit has just found it. Surfaced to
         * the auditing admin as a fault in their hub, not the peer's.
         */
        LOCAL,
        /**
         * Both diverge from the corpus. Usually a stale artefact on both sides
         * after a model release; occasionally two hubs running the same hook.
         */
        BOTH,
        /**
         * They disagree and neither is clearly wrong against the corpus —
         * typically a near-miss cluster. Recorded, never acted on. Silence here
         * is the correct output.
         */
        UNDETERMINED
    }

    private String anomalyId;
    private String runId;
    private Kind kind;
    private Attribution attribution;

    /** Probes that drove the finding, so the admin can read them and judge. */
    private List<String> probeIds;

    /** The measured rate, and the rate at which the corpus says to be worried. */
    private double observedRate;
    private double threshold;

    /**
     * Probability of seeing a divergence at least this large between two honest
     * instances of the same artefact on a sample this size. Reported so a small
     * sample cannot be waved about as proof — most daily runs are too small to
     * conclude anything, and should say so.
     */
    private double pValue;

    /** Plain-language account for the admin, and for an appeal afterwards. */
    private String explanation;

    public AuditAnomaly() {
        // TODO: pseudo-code
    }

    public AuditAnomaly(Kind kind, Attribution attribution, double observedRate) {
        // TODO: pseudo-code
    }

    /**
     * Whether this finding is strong enough to count toward suspending or
     * revoking an {@link AuthLink}. Deliberately strict: revocation can now
     * drop a hub out of search, and a hub that revokes on one fortnight's noise
     * has built a random number generator with consequences attached.
     */
    public boolean isConclusive() {
        // PSEUDO-CODE
        // IF attribution != PEER -> RETURN false
        // IF kind IN (REPLAY_MISMATCH, EQUIVOCATION, UNLOGGED_DECISION)
        //    RETURN true   // not statistical; one verified instance suffices
        // IF kind == OPENING_WITHHELD -> RETURN withheld again after a retry
        // RETURN kind IN (UNDER_BLOCKING, OVER_BLOCKING, DEGENERATE_CONFIDENCE,
        //                 PROBE_DETECTION)
        //    AND observedRate > threshold
        //    AND pValue < 0.01
        //        // One in a hundred, not one in twenty. Daily assessment over a
        //        // year is hundreds of chances to be wrong about a hub.
        return false;
    }

    /**
     * Whether the auditing admin must be shown this even though it concerns
     * their own hub. Always true for {@link Attribution#LOCAL}: an auditor
     * quietly discarding evidence against itself is the exact failure the
     * corpus was introduced to prevent.
     */
    public boolean concernsAuditor() {
        // TODO: pseudo-code
        return false;
    }

    // --- accessors --------------------------------------------------------

    public String getAnomalyId() {
        return anomalyId;
    }

    public String getRunId() {
        return runId;
    }

    public Kind getKind() {
        return kind;
    }

    public Attribution getAttribution() {
        return attribution;
    }

    public List<String> getProbeIds() {
        return probeIds;
    }

    public double getObservedRate() {
        return observedRate;
    }

    public double getThreshold() {
        return threshold;
    }

    public double getPValue() {
        return pValue;
    }

    public String getExplanation() {
        return explanation;
    }
}

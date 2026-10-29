package org.shalim.query;

import java.util.List;
import org.shalim.ml.Match;

/** Ranked answers to a {@link HubQuery}, plus an optional narrative summary. */
public class QueryResult {

    private String queryId;
    private List<Match> matches;

    /** Generated prose answer. Null when the engine ran in ranking-only mode. */
    private String answer;

    /** True when results came from keyword fallback; surfaced in the UI. */
    private boolean degraded;

    /** Set when the question was blocked, so the UI can explain rather than fail silently. */
    private String blockedReason;

    private int totalCandidatesConsidered;

    /**
     * The asker's receipt for the screening of their question: proof that the
     * hub committed its censor decision to the day's
     * {@link org.shalim.hub.CensorDecisionLog}. Every member's device keeps
     * its receipts for the retention window and checks them against the
     * day's tree, so a prober doing the same stands out from no one.
     */
    private org.shalim.hub.CensorDecisionLog.Receipt censorReceipt;

    public QueryResult() {
        // TODO: pseudo-code
    }

    public boolean wasBlocked() {
        // TODO: pseudo-code
        return false;
    }

    public boolean isEmpty() {
        // TODO: pseudo-code
        return false;
    }

    // --- accessors --------------------------------------------------------

    public String getQueryId() {
        return queryId;
    }

    public List<Match> getMatches() {
        return matches;
    }

    public String getAnswer() {
        return answer;
    }

    public boolean isDegraded() {
        return degraded;
    }

    public String getBlockedReason() {
        return blockedReason;
    }

    public int getTotalCandidatesConsidered() {
        return totalCandidatesConsidered;
    }

    public org.shalim.hub.CensorDecisionLog.Receipt getCensorReceipt() {
        return censorReceipt;
    }
}

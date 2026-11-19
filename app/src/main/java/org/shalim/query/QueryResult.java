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

    /** Set when the question was held for a moderator rather than answered or refused. */
    private boolean held;

    public QueryResult() {
        this.matches = List.of();
    }

    /** Refused, with a reason that is safe to show. Every refusal says why. */
    public static QueryResult refused(String queryId, String reason) {
        QueryResult r = new QueryResult();
        r.queryId = queryId;
        r.blockedReason = reason == null || reason.isBlank() ? "This question could not be asked here." : reason;
        return r;
    }

    /** Held for a moderator: not refused, not answered yet. */
    public static QueryResult held(String queryId, org.shalim.hub.CensorDecisionLog.Receipt receipt) {
        QueryResult r = new QueryResult();
        r.queryId = queryId;
        r.held = true;
        r.censorReceipt = receipt;
        return r;
    }

    public static QueryResult answered(String queryId, List<Match> matches, String answer, boolean degraded,
                                       int considered) {
        QueryResult r = new QueryResult();
        r.queryId = queryId;
        r.matches = matches == null ? List.of() : List.copyOf(matches);
        r.answer = answer;
        r.degraded = degraded;
        r.totalCandidatesConsidered = considered;
        return r;
    }

    /** Attaches the asker's screening receipt; every result past the censor gate carries one. */
    public QueryResult withReceipt(org.shalim.hub.CensorDecisionLog.Receipt receipt) {
        this.censorReceipt = receipt;
        return this;
    }

    /** A copy with the matches replaced, for filtering after the engine has answered. */
    public QueryResult withMatches(List<Match> filtered) {
        QueryResult r = answered(queryId, filtered, answer, degraded, totalCandidatesConsidered);
        r.held = held;
        r.blockedReason = blockedReason;
        r.censorReceipt = censorReceipt;
        return r;
    }

    public boolean wasBlocked() {
        return blockedReason != null;
    }

    public boolean isHeld() {
        return held;
    }

    public boolean isEmpty() {
        return matches == null || matches.isEmpty();
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

package org.shalim.query;

import java.time.Instant;

/**
 * A member's question to their hub: "I want to start a permaculture garden on
 * my balcony — who can help?"
 *
 * <p>A first-class object rather than a loose string because it must be
 * screened, logged, rate-limited, and answerable over a transport that may
 * only carry a few hundred bytes.
 */
public class HubQuery {

    private String queryId;
    private String hubId;
    private String askerUserId;

    /** The question as typed. Screened before it reaches the skills layer. */
    private String question;

    private Instant askedAt;

    /** Verdict from screening the question. Null means not yet screened. */
    private String verdictId;

    /** Cap on returned matches, kept low so queries do not enumerate the hub. */
    private int maxMatches;

    /** Whether the asker consents to being named to the people they match. */
    private boolean revealAskerIdentity;

    public HubQuery() {
        // TODO: pseudo-code
    }

    public HubQuery(String hubId, String askerUserId, String question) {
        // TODO: pseudo-code
    }

    /** Enforces length limits before the question hits a constrained transport. */
    public boolean isWellFormed() {
        // TODO: pseudo-code
        return false;
    }

    // --- accessors --------------------------------------------------------

    public String getQueryId() {
        return queryId;
    }

    public String getHubId() {
        return hubId;
    }

    public String getAskerUserId() {
        return askerUserId;
    }

    public String getQuestion() {
        return question;
    }

    public Instant getAskedAt() {
        return askedAt;
    }

    public int getMaxMatches() {
        return maxMatches;
    }

    public boolean isRevealAskerIdentity() {
        return revealAskerIdentity;
    }
}

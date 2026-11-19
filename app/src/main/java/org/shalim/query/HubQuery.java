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

    /** Longest question, in characters. Short enough to cross Bluetooth mesh in one frame. */
    public static final int MAX_QUESTION_LENGTH = 280;

    /** Most matches a query may ask for. Low, so queries cannot enumerate the hub. */
    public static final int MAX_MATCHES = 5;

    public HubQuery() {
        this.queryId = org.shalim.crypto.Bytes.randomId();
        this.askedAt = Instant.now();
        this.maxMatches = 3;
    }

    public HubQuery(String hubId, String askerUserId, String question) {
        this();
        this.hubId = hubId;
        this.askerUserId = askerUserId;
        this.question = question == null ? null : question.strip();
    }

    public HubQuery withMaxMatches(int n) {
        this.maxMatches = n;
        return this;
    }

    public HubQuery revealingAsker(boolean reveal) {
        this.revealAskerIdentity = reveal;
        return this;
    }

    public HubQuery askedAt(Instant when) {
        this.askedAt = when;
        return this;
    }

    void setVerdictId(String verdictId) {
        this.verdictId = verdictId;
    }

    /** Recorded by the censor gate. Package-external callers use this. */
    public void recordScreening(org.shalim.ml.Verdict verdict) {
        this.verdictId = verdict == null ? null : verdict.getVerdictId();
    }

    public String getVerdictId() {
        return verdictId;
    }

    /**
     * Enforces length limits before the question hits a constrained transport:
     * a question, of at most {@link #MAX_QUESTION_LENGTH} characters and
     * {@code 4 × MAX_QUESTION_LENGTH} UTF-8 bytes, asking for 1 to
     * {@link #MAX_MATCHES} matches, with a hub and an asker. Shape only;
     * content is the censor's job.
     */
    public boolean isWellFormed() {
        return hubId != null && askerUserId != null && question != null && !question.isBlank()
                && question.codePointCount(0, question.length()) <= MAX_QUESTION_LENGTH
                && question.getBytes(java.nio.charset.StandardCharsets.UTF_8).length <= 4 * MAX_QUESTION_LENGTH
                && maxMatches >= 1 && maxMatches <= MAX_MATCHES;
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

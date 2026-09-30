package org.shalim.query;

import java.time.Instant;

/**
 * The only direct channel between members, and deliberately a bad one for
 * abuse: one short message, sent once, to someone a query surfaced.
 *
 * <p>The 150-character cap is a safety control as much as a bandwidth one — it
 * is too small to groom or harass at length, and it fits in a single LoRa
 * frame. Recipients see the request only after screening, and declining is
 * silent so refusal carries no social cost.
 *
 * <p><strong>The message is screened, and the cap is not a substitute for
 * screening.</strong> Brevity limits grooming, which needs rapport and
 * therefore needs room. It does not limit dealing, which needs one line:
 * "Purple Haze, 50 an eighth, can drop Thursday" is under sixty characters and
 * contains a strain, a price, a quantity and a delivery. The short message is
 * in fact the ideal one for a transaction, and this is the worst surface for it
 * to happen on — the sender picked this recipient out of a query result, and
 * the hub is standing by to schedule them a meeting on its own premises.
 *
 * <p>So every message goes to {@link org.shalim.ml.CensorEngine} at
 * {@link org.shalim.ml.CensorEngine.Surface#MEETING_REQUEST}, the hardest
 * thresholds of any surface, before the recipient is told anything at all. An
 * unscreened request is not deliverable: {@link #isScreened()} gates delivery,
 * so a bug that skips the censor produces a request that never arrives rather
 * than one that arrives unread.
 */
public class MeetingRequest {

    /** Hard cap. Enforced at construction, not just in the UI. */
    public static final int MAX_MESSAGE_LENGTH = 150;

    public enum Status {
        PENDING,
        ACCEPTED,
        DECLINED,
        EXPIRED,
        BLOCKED
    }

    private String requestId;
    private String hubId;
    private String fromUserId;
    private String toUserId;

    /** The query that surfaced the recipient. Unsolicited requests are not permitted. */
    private String originatingQueryId;

    /** Why the meeting is wanted. At most {@link #MAX_MESSAGE_LENGTH} characters. */
    private String message;

    private Status status;
    private Instant sentAt;
    private Instant respondedAt;
    private Instant expiresAt;

    /**
     * Verdict from screening the message. Null means not yet screened, which is
     * not the same as clear — see {@link #isScreened()}.
     */
    private String verdictId;

    /**
     * Held for a moderator rather than blocked or delivered. The expected
     * outcome for anything ambiguous, since first contact is where a false
     * block costs someone the only channel they had.
     */
    private boolean heldForReview;

    public MeetingRequest() {
        // TODO: pseudo-code
    }

    public MeetingRequest(String hubId, String fromUserId, String toUserId,
                          String originatingQueryId, String message) {
        // TODO: pseudo-code
    }

    /** Length and provenance checks. Rejects requests with no originating query. */
    public boolean isWellFormed() {
        // PSEUDO-CODE
        // RETURN message non-blank
        //    AND message.length() <= MAX_MESSAGE_LENGTH
        //    AND message contains no URLs, phone numbers or e-mail addresses
        //        // 150 chars is plenty for "off-app, here's my number" — moving
        //        // a stranger to an unmoderated channel is the first step in
        //        // both grooming and dealing, so keep first contact in-app.
        //    AND originatingQueryId is present
        //        // No cold contact: you may only message someone a query of
        //        // yours surfaced, which stops the member list being a directory.
        //    AND fromUserId != toUserId
        //
        // Shape only. This does NOT judge content — a well-formed message is
        // still unscreened, and "Purple Haze, 50 an eighth" passes every check
        // above. Content is the censor's job, at Surface.MEETING_REQUEST.
        return false;
    }

    // --- screening --------------------------------------------------------

    /**
     * Whether the message has been through the censor. Delivery is gated on
     * this, so a code path that forgets to screen produces an undeliverable
     * request rather than an unscreened one that arrives.
     */
    public boolean isScreened() {
        // PSEUDO-CODE
        // RETURN verdictId != null
        //    // Fails closed. Null is "not screened", never "nothing found".
        return false;
    }

    /**
     * Records the censor's verdict and sets status accordingly. The only way a
     * request reaches {@link Status#PENDING}, and therefore the only way it
     * reaches a recipient.
     */
    public boolean applyVerdict(org.shalim.ml.Verdict verdict, Instant now) {
        // PSEUDO-CODE
        //
        // 1. IF verdict == null -> RETURN false
        //    verdictId = verdict.verdictId
        //
        // 2. SWITCH verdict.effectiveDecision()
        //      BLOCK  -> status = BLOCKED
        //                // The sender is told it was blocked and roughly why.
        //                // A silently swallowed message teaches nothing and the
        //                // sender simply retries in worse words. The recipient
        //                // is never told the message existed.
        //      REVIEW -> heldForReview = true; status stays unset
        //                // Not delivered, not refused. Where nearly all true
        //                // positives and almost every false positive land.
        //      ALLOW  -> status = PENDING; sentAt = now
        //
        // 3. RETURN true
        return false;
    }

    /** Whether this may be shown to the recipient. Screened, clear, and current. */
    public boolean isDeliverable() {
        // PSEUDO-CODE
        // RETURN isScreened()
        //    AND NOT heldForReview
        //    AND status == PENDING
        return false;
    }

    public boolean accept(Instant when) {
        // PSEUDO-CODE
        // IF status != PENDING -> RETURN false
        // IF now > expiresAt -> status = EXPIRED; RETURN false
        // status = ACCEPTED; respondedAt = when
        // // Acceptance is the ONLY thing that unlocks scheduling. Until this
        // // point no calendar entry, no availability, no location is shared.
        // RETURN true
        return false;
    }

    /** Declining is silent: the sender learns nothing beyond "no response". */
    public boolean decline(Instant when) {
        // PSEUDO-CODE
        // IF status != PENDING -> RETURN false
        // status = DECLINED; respondedAt = when
        // // The sender sees only "no response" — never a decline event, never
        // // a timestamp. A visible refusal is something a persistent person can
        // // punish, and it tells them the account is live and reading.
        // RETURN true
        return false;
    }

    /** Fits in one LoRa frame; used to decide whether this can go over mesh. */
    public byte[] toCompactFrame() {
        // TODO: pseudo-code
        return null;
    }

    // --- accessors --------------------------------------------------------

    public String getRequestId() {
        return requestId;
    }

    public String getFromUserId() {
        return fromUserId;
    }

    public String getToUserId() {
        return toUserId;
    }

    public String getMessage() {
        return message;
    }

    public Status getStatus() {
        return status;
    }

    public Instant getSentAt() {
        return sentAt;
    }

    public String getVerdictId() {
        return verdictId;
    }

    public boolean isHeldForReview() {
        return heldForReview;
    }

    public String getOriginatingQueryId() {
        return originatingQueryId;
    }

    public String getHubId() {
        return hubId;
    }
}

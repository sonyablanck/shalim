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

    /** How long a delivered request waits for an answer before it lapses. */
    public static final java.time.Duration TTL = java.time.Duration.ofDays(7);

    private static final java.util.regex.Pattern URL = java.util.regex.Pattern.compile(
            "(?i)(https?://|www\\.|\\b[a-z0-9-]+\\.(com|org|net|io|me|co|uk|app|link|ly|gg|to|xyz|info)\\b)");
    private static final java.util.regex.Pattern EMAIL = java.util.regex.Pattern.compile(
            "(?i)[a-z0-9._%+-]+\\s*(@|\\(at\\)|\\[at\\])\\s*[a-z0-9.-]+\\s*(\\.|\\(dot\\)|\\[dot\\])\\s*[a-z]{2,}");
    /** Nine or more digits, allowing the spaces, dots, dashes and brackets people put in numbers. Dates (eight) pass. */
    private static final java.util.regex.Pattern PHONE = java.util.regex.Pattern.compile(
            "(\\+?\\d[\\s().-]*){9,}");
    /** Common handles for moving off-app: "@name", "tg:", "snap:", "insta". */
    private static final java.util.regex.Pattern HANDLE = java.util.regex.Pattern.compile(
            "(?i)(^|\\s)@[a-z0-9_.]{3,}|\\b(telegram|whatsapp|signal|snapchat|snap|insta|instagram|discord|tg)\\s*[:@]");

    public MeetingRequest() {
        this.requestId = org.shalim.crypto.Bytes.randomId();
    }

    public MeetingRequest(String hubId, String fromUserId, String toUserId,
                          String originatingQueryId, String message) {
        this();
        if (message != null && message.codePointCount(0, message.length()) > MAX_MESSAGE_LENGTH) {
            // Enforced at construction, not just in the UI.
            throw new IllegalArgumentException("meeting requests are at most " + MAX_MESSAGE_LENGTH + " characters");
        }
        this.hubId = hubId;
        this.fromUserId = fromUserId;
        this.toUserId = toUserId;
        this.originatingQueryId = originatingQueryId;
        this.message = message == null ? null : message.strip();
    }

    /**
     * Length and provenance checks. Rejects requests with no originating query.
     *
     * <p>Shape only. This does NOT judge content — a well-formed message is
     * still unscreened, and "Purple Haze, 50 an eighth" passes every check
     * here. Content is the censor's job, at Surface.MEETING_REQUEST.
     */
    public boolean isWellFormed() {
        return message != null && !message.isBlank()
                && message.codePointCount(0, message.length()) <= MAX_MESSAGE_LENGTH
                // 150 chars is plenty for "off-app, here's my number": moving a
                // stranger to an unmoderated channel is the first step in both
                // grooming and dealing, so first contact stays in-app.
                && !containsContactDetails(message)
                // No cold contact: you may only message someone a query of yours
                // surfaced, which stops the member list being a directory.
                && originatingQueryId != null && !originatingQueryId.isBlank()
                && fromUserId != null && toUserId != null && !fromUserId.equals(toUserId);
    }

    /**
     * URLs, e-mail addresses (including "name (at) host (dot) com"), phone
     * numbers and messaging-app handles. A determined sender can spell a
     * number out in words; this catches the ordinary case, and the censor and
     * the 150-character limit carry the rest.
     */
    public static boolean containsContactDetails(String text) {
        return URL.matcher(text).find() || EMAIL.matcher(text).find() || PHONE.matcher(text).find()
                || HANDLE.matcher(text).find();
    }

    // --- screening --------------------------------------------------------

    /**
     * Whether the message has been through the censor. Delivery is gated on
     * this, so a code path that forgets to screen produces an undeliverable
     * request rather than an unscreened one that arrives. Fails closed: null
     * is "not screened", never "nothing found".
     */
    public boolean isScreened() {
        return verdictId != null;
    }

    /**
     * Records the censor's verdict and sets status accordingly. The only way a
     * request reaches {@link Status#PENDING}, and therefore the only way it
     * reaches a recipient.
     */
    public boolean applyVerdict(org.shalim.ml.Verdict verdict, Instant now) {
        if (verdict == null || verdict.effectiveDecision() == null) {
            return false;
        }
        this.verdictId = verdict.getVerdictId();
        switch (verdict.effectiveDecision()) {
            // The sender is told it was blocked and roughly why; the recipient
            // is never told the message existed.
            case BLOCK -> {
                status = Status.BLOCKED;
                heldForReview = false;
            }
            // Not delivered, not refused. Where nearly all true positives and
            // almost every false positive land.
            case REVIEW -> {
                heldForReview = true;
                status = null;
            }
            case ALLOW -> {
                heldForReview = false;
                status = Status.PENDING;
                sentAt = now;
                expiresAt = now.plus(TTL);
            }
        }
        return true;
    }

    /** Whether this may be shown to the recipient. Screened, clear, and current. */
    public boolean isDeliverable() {
        return isScreened() && !heldForReview && status == Status.PENDING;
    }

    /**
     * Acceptance is the ONLY thing that unlocks scheduling. Until this point
     * no calendar entry, no availability, no location is shared.
     */
    public boolean accept(Instant when) {
        if (status != Status.PENDING || !isScreened()) {
            return false;
        }
        if (expiresAt != null && !when.isBefore(expiresAt)) {
            status = Status.EXPIRED;
            return false;
        }
        status = Status.ACCEPTED;
        respondedAt = when;
        return true;
    }

    /**
     * Declining is silent: the sender sees only "no response", never a decline
     * event or a timestamp. A visible refusal is something a persistent person
     * can punish, and it tells them the account is live and reading.
     */
    public boolean decline(Instant when) {
        if (status != Status.PENDING) {
            return false;
        }
        status = Status.DECLINED;
        respondedAt = when;
        return true;
    }

    /** Lapses an unanswered request. */
    public boolean expireIfDue(Instant now) {
        if (status == Status.PENDING && expiresAt != null && !now.isBefore(expiresAt)) {
            status = Status.EXPIRED;
            return true;
        }
        return false;
    }

    /**
     * What the sender is shown. DECLINED and EXPIRED both read as "no
     * response", so a decline cannot be told from silence.
     */
    public String senderView() {
        if (heldForReview) {
            return "Sent. It is being checked before delivery.";
        }
        if (status == null) {
            return "Not sent.";
        }
        return switch (status) {
            case PENDING -> "Sent.";
            case ACCEPTED -> "Accepted. You can now arrange a time at the hub.";
            case DECLINED, EXPIRED -> "No response.";
            case BLOCKED -> "This message can't be sent through the hub.";
        };
    }

    /**
     * {@code version ‖ requestId(16) ‖ queryId(16) ‖ length(1) ‖ message}. The
     * two user ids are not in it: the session carrying it already
     * authenticates the sender, and the hub resolves the recipient from the
     * query. At most 184 bytes for 150 characters of Latin script; see
     * {@link #fitsLoRa()}.
     */
    public byte[] toCompactFrame() {
        byte[] text = message == null ? new byte[0] : message.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        if (text.length > 254) {
            throw new IllegalStateException("message too long in bytes for a compact frame");
        }
        return org.shalim.transport.Wire.writer().u8(1)
                .fixed(org.shalim.crypto.Bytes.fromHex(requestId), 16)
                .fixed(org.shalim.crypto.Bytes.fromHex(originatingQueryId), 16)
                .small(text)
                .done();
    }

    /**
     * Whether the compact frame, sealed in a session delivery (4 bytes of
     * delivery header, 33 of session overhead), fits one LoRa frame at SF7–8
     * (222 bytes). True for 150 characters of Latin script. Scripts that take
     * two or three bytes a character, such as Arabic, Cyrillic or Chinese, do
     * not fit at full length and go over Bluetooth or Wi-Fi instead.
     */
    public boolean fitsLoRa() {
        byte[] text = message == null ? new byte[0] : message.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        return text.length <= 254 && 1 + 16 + 16 + 1 + text.length + 4 + 33 <= 222;
    }

    /** Parses {@link #toCompactFrame()}. Sender and recipient are supplied by the receiving hub. */
    public static MeetingRequest fromCompactFrame(byte[] frame, String hubId, String fromUserId, String toUserId) {
        org.shalim.transport.Wire.Reader r = org.shalim.transport.Wire.reader(frame);
        if (r.u8() != 1) {
            throw new org.shalim.transport.Wire.WireException("unknown meeting request version");
        }
        String id = org.shalim.crypto.Bytes.hex(r.fixed(16));
        String query = org.shalim.crypto.Bytes.hex(r.fixed(16));
        String text = r.smallString();
        r.end();
        MeetingRequest m = new MeetingRequest(hubId, fromUserId, toUserId, query, text);
        m.requestId = id;
        return m;
    }

    public Instant getRespondedAt() {
        return respondedAt;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    /** Restores persisted state. Persistence only. */
    public static MeetingRequest restore(String id, String hubId, String from, String to, String query, String message,
                                         Status status, Instant sentAt, Instant respondedAt, Instant expiresAt,
                                         String verdictId, boolean held) {
        MeetingRequest m = new MeetingRequest(hubId, from, to, query, message);
        m.requestId = id;
        m.status = status;
        m.sentAt = sentAt;
        m.respondedAt = respondedAt;
        m.expiresAt = expiresAt;
        m.verdictId = verdictId;
        m.heldForReview = held;
        return m;
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

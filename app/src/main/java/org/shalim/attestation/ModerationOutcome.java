package org.shalim.attestation;

import java.time.Instant;

/**
 * A moderation decision about a person, made by one hub, in a form other hubs
 * can weigh.
 *
 * <p>This is the signal that actually targets the "radicaliser moves to a new
 * hub" problem. Hub-level censor integrity does not: a failed model download
 * demotes an innocent hub's whole membership, while a real predator operates in
 * a hub whose censor is working perfectly, because grooming happens in person
 * and in coded language no classifier catches. What travels with a person
 * should be what a human moderator concluded about that person.
 *
 * <p>Outcomes are evidence-bearing, expiring, and appealable by construction.
 * A permanent, unappealable, unevidenced mark that follows someone across every
 * hub is a denunciation system, and it would be trivially weaponised against
 * exactly the people Shalim exists to protect.
 */
public class ModerationOutcome {

    public enum Kind {
        /** Formal warning. Rarely worth federating. */
        WARNING,
        /** Temporary loss of privileges in the issuing hub. */
        SUSPENSION,
        /** Removed from the issuing hub. The main federatable outcome. */
        REMOVAL,
        /** Removed with a safeguarding concern recorded. Highest weight. */
        SAFEGUARDING_REMOVAL
    }

    /**
     * Why, in categories a receiving hub can act on. Kept coarse: a free-text
     * reason travelling between hubs is a rumour with a signature on it.
     */
    public enum Ground {
        CENSOR_FLAG_UPHELD,
        MEETING_REPORTED,
        REPEATED_UNWANTED_CONTACT,
        SAFEGUARDING_CONCERN,
        IMPERSONATION,
        OTHER
    }

    private String outcomeId;
    private String subjectKeyFingerprint;
    private String issuerKeyFingerprint;

    private Kind kind;
    private Ground ground;

    private Instant decidedAt;

    /** Outcomes lapse. Nothing here is permanent without renewal by a human. */
    private Instant expiresAt;

    /** Moderator who decided, for accountability within the issuing hub. */
    private String decidedByUserId;

    /**
     * Log entry hashes supporting the decision. Hashes, not content: a
     * receiving hub can confirm evidence exists without reading it.
     */
    private java.util.List<String> evidenceEntryHashes;

    /** Whether the subject contested it. Travels with the outcome. */
    private boolean underAppeal;

    /** Set if an appeal succeeded; the outcome then stops being honoured. */
    private boolean overturned;

    /**
     * Whether the issuing hub consents to this being shared beyond itself.
     * False by default: most moderation is local business.
     */
    private boolean federatable;

    private String overturnedByUserId;
    private String overturnJustification;

    /** Longest an outcome may run without a human renewing it. */
    public static final java.time.Duration MAX_TERM = java.time.Duration.ofDays(365);

    public ModerationOutcome() {
        this.outcomeId = org.shalim.crypto.Bytes.randomId();
        this.evidenceEntryHashes = new java.util.ArrayList<>();
    }

    /**
     * A decision about a person. Must expire, must cite log evidence, and is
     * local unless {@code federatable} is set explicitly.
     */
    public ModerationOutcome(String subjectKeyFingerprint, String issuerKeyFingerprint, Kind kind, Ground ground,
                             String decidedByUserId, Instant decidedAt, Instant expiresAt,
                             java.util.List<String> evidenceEntryHashes) {
        this();
        if (expiresAt == null || !expiresAt.isAfter(decidedAt)
                || expiresAt.isAfter(decidedAt.plus(MAX_TERM))) {
            throw new IllegalArgumentException("an outcome expires, within a year");
        }
        if (evidenceEntryHashes == null || evidenceEntryHashes.isEmpty()) {
            throw new IllegalArgumentException("an outcome cites evidence in the hub log");
        }
        this.subjectKeyFingerprint = subjectKeyFingerprint;
        this.issuerKeyFingerprint = issuerKeyFingerprint;
        this.kind = kind;
        this.ground = ground;
        this.decidedByUserId = decidedByUserId;
        this.decidedAt = decidedAt;
        this.expiresAt = expiresAt;
        this.evidenceEntryHashes = new java.util.ArrayList<>(evidenceEntryHashes);
    }

    /** Consents to sharing beyond this hub. The default is not to. */
    public void setFederatable(boolean federatable) {
        this.federatable = federatable;
    }

    public boolean isActive(Instant now) {
        return !overturned && decidedAt != null && !now.isBefore(decidedAt)
                && expiresAt != null && now.isBefore(expiresAt);
    }

    /**
     * How much a receiving hub should weigh this, 0..100. Deliberately not a
     * boolean: a warning from an unknown hub and a safeguarding removal from a
     * trusted one should not have the same effect. An appeal halves the weight,
     * and an overturned outcome weighs nothing.
     */
    public int weight() {
        if (overturned) {
            return 0;
        }
        int base = switch (kind) {
            case WARNING -> 10;
            case SUSPENSION -> 30;
            case REMOVAL -> 60;
            case SAFEGUARDING_REMOVAL -> 90;
        };
        if (ground == Ground.SAFEGUARDING_CONCERN) {
            base = Math.min(100, base + 10);
        } else if (ground == Ground.OTHER) {
            base = base / 2; // an uncategorised reason is barely a reason to another hub
        }
        return underAppeal ? base / 2 : base;
    }

    /** Only the subject can appeal, and only while the outcome stands. */
    public boolean lodgeAppeal(String bySubjectKeyFingerprint) {
        if (overturned || underAppeal || subjectKeyFingerprint == null
                || !subjectKeyFingerprint.equals(bySubjectKeyFingerprint)) {
            return false;
        }
        this.underAppeal = true;
        return true;
    }

    /** A moderator overturns it. Not the one who decided it: appeals go to someone else. */
    public boolean overturn(String byModeratorUserId, String justification) {
        if (overturned || justification == null || justification.isBlank()
                || byModeratorUserId == null || byModeratorUserId.equals(decidedByUserId)) {
            return false;
        }
        this.overturned = true;
        this.underAppeal = false;
        this.overturnedByUserId = byModeratorUserId;
        this.overturnJustification = justification;
        return true;
    }

    /** An appeal that failed. The outcome stands at full weight. */
    public boolean dismissAppeal(String byModeratorUserId) {
        if (!underAppeal || byModeratorUserId == null || byModeratorUserId.equals(decidedByUserId)) {
            return false;
        }
        this.underAppeal = false;
        return true;
    }

    public Instant getDecidedAt() {
        return decidedAt;
    }

    public String getDecidedByUserId() {
        return decidedByUserId;
    }

    public java.util.List<String> getEvidenceEntryHashes() {
        return java.util.List.copyOf(evidenceEntryHashes);
    }

    public String getOverturnedByUserId() {
        return overturnedByUserId;
    }

    public String getOverturnJustification() {
        return overturnJustification;
    }

    /** Restores persisted state. Persistence only. */
    public static ModerationOutcome restore(String outcomeId, String subject, String issuer, Kind kind, Ground ground,
                                            Instant decidedAt, Instant expiresAt, String decidedBy,
                                            java.util.List<String> evidence, boolean underAppeal, boolean overturned,
                                            boolean federatable, String overturnedBy, String overturnJustification) {
        ModerationOutcome o = new ModerationOutcome();
        o.outcomeId = outcomeId;
        o.subjectKeyFingerprint = subject;
        o.issuerKeyFingerprint = issuer;
        o.kind = kind;
        o.ground = ground;
        o.decidedAt = decidedAt;
        o.expiresAt = expiresAt;
        o.decidedByUserId = decidedBy;
        o.evidenceEntryHashes = new java.util.ArrayList<>(evidence);
        o.underAppeal = underAppeal;
        o.overturned = overturned;
        o.federatable = federatable;
        o.overturnedByUserId = overturnedBy;
        o.overturnJustification = overturnJustification;
        return o;
    }

    // --- accessors --------------------------------------------------------

    public String getOutcomeId() {
        return outcomeId;
    }

    public Kind getKind() {
        return kind;
    }

    public Ground getGround() {
        return ground;
    }

    public String getSubjectKeyFingerprint() {
        return subjectKeyFingerprint;
    }

    public String getIssuerKeyFingerprint() {
        return issuerKeyFingerprint;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public boolean isUnderAppeal() {
        return underAppeal;
    }

    public boolean isOverturned() {
        return overturned;
    }

    public boolean isFederatable() {
        return federatable;
    }
}

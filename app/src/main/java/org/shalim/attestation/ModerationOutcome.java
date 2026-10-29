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

    public ModerationOutcome() {
        // TODO: pseudo-code
    }

    public boolean isActive(Instant now) {
        // TODO: pseudo-code
        return false;
    }

    /**
     * How much a receiving hub should weigh this. Deliberately not a boolean:
     * a warning from an unknown hub and a safeguarding removal from a trusted
     * one should not have the same effect.
     */
    public int weight() {
        // TODO: pseudo-code
        return 0;
    }

    public boolean lodgeAppeal(String bySubjectKeyFingerprint) {
        // TODO: pseudo-code
        return false;
    }

    public boolean overturn(String byModeratorUserId, String justification) {
        // TODO: pseudo-code
        return false;
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

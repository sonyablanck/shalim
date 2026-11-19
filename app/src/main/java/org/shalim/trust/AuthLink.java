package org.shalim.trust;

import java.time.Instant;

/**
 * One direction of authentication: this hub has been checking a peer hub —
 * by replaying its committed censor decisions and, in {@link AuditSchedule.Mode#FULL},
 * through an admin's anonymous membership there — and currently accepts that
 * the peer is running the censor it claims to.
 *
 * <p>The same class describes both ends, and they hold different things. The
 * authenticating hub's copy names its own admin in {@link #probingAdminUserId}.
 * The target's copy never does: it holds only {@link #linkPseudonym}, because
 * since the September 30 revision the target is not told who the prober is.
 *
 * <p>Replaces the earlier private {@code TrustVouch}. The difference is not
 * cosmetic. A vouch was a courtesy that never left the device and changed
 * nothing for anyone. An authentication link now has consequences: it counts
 * toward the peer's {@link AuthBond}s, bonds decide whether a hub appears in
 * search, and whether a hub has any authentication at all decides whether its
 * members can use QwenMatchmaker. That makes revocation a sanction, so it is
 * guarded accordingly — see {@link WebOfTrust#assess}.
 *
 * <h2>Lifecycle</h2>
 * <ol>
 *   <li>{@link State#PENDING} — an admin here set it up. Probing starts. The
 *       link does not count for anything until it has passed a first window.</li>
 *   <li>{@link State#ACTIVE} — the rolling window passed. Counts toward bonds.</li>
 *   <li>{@link State#SUSPENDED} — a window failed with the evidence pointing
 *       at the peer, but has not yet met the bar for revocation. Still counts;
 *       the admin here is shown the findings.</li>
 *   <li>{@link State#REVOKED} — a conclusive, attributed failure over the
 *       window. Stops counting. Appealable while the evidence is retained.</li>
 *   <li>{@link State#DORMANT} — no scoreable probes for a while, usually a
 *       blackout. Stops counting toward search, <em>does not</em> count as a
 *       revocation for {@link org.shalim.hub.HubStanding}.</li>
 * </ol>
 */
public class AuthLink {

    public enum State {
        PENDING,
        ACTIVE,
        SUSPENDED,
        REVOKED,
        DORMANT,
        /**
         * The prober stopped being eligible — could not present today's
         * credential (promoted to admin in the target, left, or moved to an
         * unattested device), or the hubs came to share an admin. Not a
         * finding about either hub's censor. Stops counting at once; another
         * eligible admin can set up a fresh link.
         */
        INELIGIBLE
    }

    private String linkId;

    /** This hub's issuer key fingerprint. */
    private String authenticatorKeyFingerprint;

    /** The peer's issuer key fingerprint. Never a hub id. */
    private String subjectKeyFingerprint;

    /**
     * Admin whose membership in the peer carries organic and synthetic
     * probes. Held on the authenticating side only; null on the target's
     * copy. Their probes spend their ordinary quota there, which is why
     * setting up a link requires their explicit consent.
     */
    private String probingAdminUserId;

    /**
     * Target's handle for this link: a pseudonym derived from the prober's
     * hidden credential secret, stable for this pair of hubs, unlinkable to
     * the member. See {@link EligibilityProof}.
     */
    private String linkPseudonym;

    /** How this link is probed; see {@link AuditSchedule#modeFor}. */
    private AuditSchedule.Mode mode;

    /** Last eligibility result, which can move a link into or out of REPLAY_ONLY. */
    private ProberEligibility.Result eligibility;

    /**
     * Authenticating side: secret from which each day's replay nonce is
     * derived. Target side: null; it holds {@link #nonceCommitment}.
     */
    private byte[] nonceSecret;

    /**
     * Anchor of the nonce hash chain, {@code HashChain.anchor(nonceSecret,
     * NONCE_CHAIN_DAYS)}, sent at setup so the auditor cannot pick nonces after
     * seeing a root. Both sides hold it.
     */
    private byte[] nonceCommitment;

    /** Day the nonce chain counts from: its anchor belongs to this day; nonces start the day after. */
    private java.time.LocalDate nonceChainStart;

    /** Length of a link's nonce chain. Re-anchored before it runs out. */
    public static final int NONCE_CHAIN_DAYS = org.shalim.crypto.HashChain.DEFAULT_LENGTH_DAYS;

    private State state;
    private Instant establishedAt;
    private Instant lastPassedAt;
    private Instant stateChangedAt;

    /** Set when REVOKED; points at the ledger evidence. */
    private String revocationId;

    /** Last time {@link ProberEligibility} passed for this link, on both sides. */
    private Instant eligibilityCheckedAt;

    /** Whether the revoked hub's admins have lodged an appeal. */
    private boolean underAppeal;

    /** Authenticating side: the peer's issuer public key, for heads and receipts. */
    private byte[] subjectPublicKey;

    /** Target side: the auditor's issuer key (statements) and encryption key (openings). */
    private byte[] authenticatorPublicKey;
    private byte[] authenticatorEncryptionKey;

    /** Target side: the latest statement the auditor sent about this link. */
    private LinkStatement latestStatement;

    /** Last time scoreable evidence arrived. Dormancy counts from here. */
    private Instant lastEvidenceAt;

    /** Replay budget bookkeeping for the current fortnight of the nonce chain. */
    private long fortnightIndex = -1;
    private int realScoredThisFortnight;
    private long openedReal;
    private long openedTotal;

    public AuthLink() {
        this.linkId = org.shalim.crypto.Bytes.randomId();
        this.state = State.PENDING;
    }

    public AuthLink(String authenticatorKeyFingerprint, String subjectKeyFingerprint,
                    String probingAdminUserId, AuditSchedule.Mode mode, Instant now) {
        this();
        this.authenticatorKeyFingerprint = authenticatorKeyFingerprint;
        this.subjectKeyFingerprint = subjectKeyFingerprint;
        this.probingAdminUserId = probingAdminUserId;
        this.mode = mode;
        this.establishedAt = now;
        this.stateChangedAt = now;
    }

    /** Target side: an inbound link, known only by pseudonym. */
    public static AuthLink inbound(String authenticatorKeyFingerprint, String ownKeyFingerprint,
                                   String linkPseudonym, byte[] nonceCommitment,
                                   AuditSchedule.Mode mode, Instant now) {
        AuthLink link = new AuthLink(authenticatorKeyFingerprint, ownKeyFingerprint, null, mode, now);
        link.linkPseudonym = linkPseudonym;
        link.nonceCommitment = nonceCommitment == null ? null : nonceCommitment.clone();
        return link;
    }

    /** Whether this link currently counts toward bonds and search. */
    public boolean counts(Instant now) {
        // INELIGIBLE never counts, however well the peer was behaving.
        // SUSPENDED still counts: one bad window is evidence to look at, not
        // yet a verdict to act on.
        return state == State.ACTIVE || state == State.SUSPENDED;
    }

    /** Whether this link has been positively revoked, as distinct from lapsing. */
    public boolean isRevoked() {
        return state == State.REVOKED;
    }

    public void transition(State to, Instant now, String reasonRef) {
        if (to == null || to == state) {
            return;
        }
        if (state == State.REVOKED && to != State.ACTIVE) {
            return; // only an upheld appeal brings a revoked link back
        }
        this.state = to;
        this.stateChangedAt = now;
        if (to == State.REVOKED) {
            this.revocationId = reasonRef;
        } else if (to == State.ACTIVE) {
            this.revocationId = null;
            this.underAppeal = false;
        }
    }

    /**
     * Target side: applies a statement from the authenticating hub, if it is
     * signed by that hub and about this link. The target's copy then mirrors
     * the auditor's decision; it never decides anything itself.
     */
    public boolean applyStatement(LinkStatement s, Instant now) {
        if (s == null || authenticatorPublicKey == null || !s.verify(authenticatorPublicKey)
                || !authenticatorKeyFingerprint.equals(s.getAuthenticatorKeyFingerprint())
                || !subjectKeyFingerprint.equals(s.getSubjectKeyFingerprint())
                || (linkPseudonym != null && !linkPseudonym.equals(s.getLinkPseudonym()))
                || (latestStatement != null && !s.getIssuedAt().isAfter(latestStatement.getIssuedAt()))) {
            return false;
        }
        latestStatement = s;
        state = s.getState();
        stateChangedAt = now;
        if (state == State.REVOKED) {
            revocationId = "statement:" + s.getIssuedAt();
        }
        return true;
    }

    /**
     * Target side: whether this inbound link counts now. Only on a current
     * statement: an expired one means nothing heard, which stops it counting
     * without making it a revocation.
     */
    public boolean countsInbound(Instant now) {
        return latestStatement != null && latestStatement.isCurrent(now) && counts(now);
    }

    void markPassed(Instant now) {
        this.lastPassedAt = now;
    }

    void markEvidence(Instant now) {
        this.lastEvidenceAt = now;
    }

    void setMode(AuditSchedule.Mode mode) {
        this.mode = mode;
    }

    void setEligibility(ProberEligibility.Result result, Instant now) {
        this.eligibility = result;
        this.eligibilityCheckedAt = now;
    }

    void setLinkPseudonym(String pseudonym) {
        this.linkPseudonym = pseudonym;
    }

    void setSubjectPublicKey(byte[] key) {
        this.subjectPublicKey = key == null ? null : key.clone();
    }

    void setAuthenticatorKeys(byte[] signingKey, byte[] encryptionKey) {
        this.authenticatorPublicKey = signingKey == null ? null : signingKey.clone();
        this.authenticatorEncryptionKey = encryptionKey == null ? null : encryptionKey.clone();
    }

    void openAppeal() {
        this.underAppeal = true;
    }

    void closeAppeal() {
        this.underAppeal = false;
    }

    /** Replay budget: real leaves scored this fortnight, rolling over at fortnight boundaries. */
    int realScoredThisFortnight(java.time.LocalDate day) {
        rollFortnight(day);
        return realScoredThisFortnight;
    }

    int dayInFortnight(java.time.LocalDate day) {
        if (nonceChainStart == null) {
            return 0;
        }
        long d = java.time.temporal.ChronoUnit.DAYS.between(nonceChainStart, day);
        return Math.floorMod(d, AuditSchedule.FORTNIGHT_DAYS);
    }

    /** Share of real leaves among those opened so far; 1.0 before anything is opened. */
    double realFraction() {
        return openedTotal == 0 ? 1.0 : openedReal / (double) openedTotal;
    }

    void countOpened(java.time.LocalDate day, int real, int pads, int scored) {
        rollFortnight(day);
        openedReal += real;
        openedTotal += real + pads;
        realScoredThisFortnight += scored;
    }

    private void rollFortnight(java.time.LocalDate day) {
        if (nonceChainStart == null) {
            return;
        }
        long f = Math.floorDiv(java.time.temporal.ChronoUnit.DAYS.between(nonceChainStart, day),
                (long) AuditSchedule.FORTNIGHT_DAYS);
        if (f != fortnightIndex) {
            fortnightIndex = f;
            realScoredThisFortnight = 0;
        }
    }

    public Instant getStateChangedAt() {
        return stateChangedAt;
    }

    public Instant getLastEvidenceAt() {
        return lastEvidenceAt;
    }

    public byte[] getSubjectPublicKey() {
        return subjectPublicKey == null ? null : subjectPublicKey.clone();
    }

    public byte[] getAuthenticatorPublicKey() {
        return authenticatorPublicKey == null ? null : authenticatorPublicKey.clone();
    }

    public byte[] getAuthenticatorEncryptionKey() {
        return authenticatorEncryptionKey == null ? null : authenticatorEncryptionKey.clone();
    }

    public LinkStatement getLatestStatement() {
        return latestStatement;
    }

    // --- accessors --------------------------------------------------------

    public String getLinkId() {
        return linkId;
    }

    public String getAuthenticatorKeyFingerprint() {
        return authenticatorKeyFingerprint;
    }

    public String getSubjectKeyFingerprint() {
        return subjectKeyFingerprint;
    }

    public String getProbingAdminUserId() {
        return probingAdminUserId;
    }

    public String getLinkPseudonym() {
        return linkPseudonym;
    }

    public AuditSchedule.Mode getMode() {
        return mode;
    }

    public ProberEligibility.Result getEligibility() {
        return eligibility;
    }

    public byte[] getNonceCommitment() {
        return nonceCommitment;
    }

    /** Authenticating side only. Package-private: the seed never leaves the trust package. */
    byte[] nonceSecret() {
        return nonceSecret;
    }

    public java.time.LocalDate nonceChainStart() {
        return nonceChainStart;
    }

    /** Authenticating side, at setup: makes a fresh chain and returns the anchor to send to the target. */
    byte[] startNonceChain(java.time.LocalDate startDay) {
        org.shalim.crypto.Bytes.wipe(nonceSecret);
        this.nonceSecret = org.shalim.crypto.Bytes.random(32);
        this.nonceChainStart = startDay;
        this.nonceCommitment = org.shalim.crypto.HashChain.anchor(nonceSecret, NONCE_CHAIN_DAYS);
        return nonceCommitment.clone();
    }

    /** Target side, at setup: records the anchor received. */
    void acceptNonceAnchor(byte[] anchor, java.time.LocalDate startDay) {
        this.nonceCommitment = anchor.clone();
        this.nonceChainStart = startDay;
    }

    public Instant getEligibilityCheckedAt() {
        return eligibilityCheckedAt;
    }

    public State getState() {
        return state;
    }

    public Instant getEstablishedAt() {
        return establishedAt;
    }

    public Instant getLastPassedAt() {
        return lastPassedAt;
    }

    public String getRevocationId() {
        return revocationId;
    }

    public boolean isUnderAppeal() {
        return underAppeal;
    }
}

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

    /** H(nonceSecret), sent at setup so the auditor cannot pick nonces after seeing a root. */
    private byte[] nonceCommitment;

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

    public AuthLink() {
        // TODO: pseudo-code
    }

    public AuthLink(String authenticatorKeyFingerprint, String subjectKeyFingerprint,
                    String probingAdminUserId, AuditSchedule.Mode mode, Instant now) {
        // TODO: pseudo-code
    }

    /** Target side: an inbound link, known only by pseudonym. */
    public static AuthLink inbound(String authenticatorKeyFingerprint, String ownKeyFingerprint,
                                   String linkPseudonym, byte[] nonceCommitment,
                                   AuditSchedule.Mode mode, Instant now) {
        // PSEUDO-CODE
        // link = new AuthLink(authenticator, own, probingAdminUserId = null, mode, now)
        // link.linkPseudonym = linkPseudonym; link.nonceCommitment = nonceCommitment
        // RETURN link
        return null;
    }

    /** Whether this link currently counts toward bonds and search. */
    public boolean counts(Instant now) {
        // PSEUDO-CODE
        // RETURN state IN (ACTIVE, SUSPENDED)
        //    // INELIGIBLE never counts, however well the peer was behaving.
        //    // SUSPENDED still counts: a single bad window is evidence to look
        //    // at, not yet a verdict to act on.
        return false;
    }

    /** Whether this link has been positively revoked, as distinct from lapsing. */
    public boolean isRevoked() {
        // TODO: pseudo-code
        return false;
    }

    public void transition(State to, Instant now, String reasonRef) {
        // TODO: pseudo-code
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

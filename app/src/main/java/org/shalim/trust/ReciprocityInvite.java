package org.shalim.trust;

import java.time.Instant;

/**
 * An admin's request to a hub they authenticate: "authenticate us back".
 *
 * <p>The fix for the zero-bond problem. A new hub whose admin authenticates
 * one peer has one outbound link and no bonds, so it is invisible to search.
 * For the peer to authenticate it back, one of the peer's admins must be a
 * member of the new hub — probes travel through ordinary membership, and there
 * is no other route in. So the invite carries two things: a membership
 * invitation to the new hub, and a request to set up an {@link AuthLink} once
 * joined.
 *
 * <p>Sent through the peer's ordinary channels by the inviting admin, who is
 * already a member there, and addressed to the peer's admins only. It is a
 * request, never an obligation: declining is silent and costs nothing, as
 * with every other request in Shalim.
 */
public class ReciprocityInvite {

    public enum Status {
        SENT,
        /** A peer admin joined the new hub and set up a link. */
        ACCEPTED,
        /** Expired unanswered, or declined. Indistinguishable by design. */
        LAPSED
    }

    private String inviteId;

    /** The hub asking to be authenticated. */
    private String fromHubKeyFingerprint;

    /** The hub being asked. */
    private String toHubKeyFingerprint;

    private String invitingAdminUserId;

    /** Single-use membership invitation into the inviting hub, at MEMBER role. */
    private String membershipInvitationId;

    /** Optional note, 150 characters, screened at MEETING_REQUEST thresholds. */
    private String note;

    private Status status;
    private Instant sentAt;
    private Instant expiresAt;

    public ReciprocityInvite() {
        this.inviteId = org.shalim.crypto.Bytes.randomId();
        this.status = Status.SENT;
    }

    /** Unanswered invites lapse after this, silently. */
    public static final java.time.Duration TTL = java.time.Duration.ofDays(30);

    public ReciprocityInvite(String fromHubKeyFingerprint, String toHubKeyFingerprint,
                             String invitingAdminUserId, String membershipInvitationId, Instant now) {
        this();
        this.fromHubKeyFingerprint = fromHubKeyFingerprint;
        this.toHubKeyFingerprint = toHubKeyFingerprint;
        this.invitingAdminUserId = invitingAdminUserId;
        this.membershipInvitationId = membershipInvitationId;
        this.sentAt = now;
        this.expiresAt = now.plus(TTL);
    }

    public boolean isOpen(Instant now) {
        if (status == Status.SENT && !now.isBefore(expiresAt)) {
            status = Status.LAPSED; // declined and expired look the same, by design
        }
        return status == Status.SENT;
    }

    /** A peer admin joined and set up a link back. */
    public void accepted() {
        if (status == Status.SENT) {
            status = Status.ACCEPTED;
        }
    }

    public String getMembershipInvitationId() {
        return membershipInvitationId;
    }

    // --- accessors --------------------------------------------------------

    public String getInviteId() {
        return inviteId;
    }

    public String getFromHubKeyFingerprint() {
        return fromHubKeyFingerprint;
    }

    public String getToHubKeyFingerprint() {
        return toHubKeyFingerprint;
    }

    public String getInvitingAdminUserId() {
        return invitingAdminUserId;
    }

    public Status getStatus() {
        return status;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }
}

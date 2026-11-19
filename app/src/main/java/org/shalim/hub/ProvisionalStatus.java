package org.shalim.hub;

import java.time.Duration;
import java.time.Instant;

/**
 * The clocks behind {@link HubStanding.State#PROVISIONAL}, decided 18 and 19
 * November 2026. The same rules run in two places: on the hub, which computes
 * its own standing, and on each member's device, which knows the hub's
 * position and sees nearby hubs' cards for itself. A hub running modified code
 * could ignore its neighbours and claim to be provisional forever; members'
 * devices do not take its word for it ({@link #enforce}).
 *
 * <ul>
 *   <li>A hub created where a certified hub is already within 20 miles is never
 *       provisional: it is guest-only until it gains an inbound link.</li>
 *   <li>Otherwise it is provisional until the earlier of 90 days from creation
 *       (the absolute cap) and 30 days from first learning of a certified hub
 *       within 20 miles. Only a certified peer starts that clock, and a
 *       newcomer arriving never re-locks an existing hub.</li>
 *   <li>A hub whose inbound links have all been revoked is provisional for 30
 *       days from the latest revocation.</li>
 *   <li>Any inbound link ends provisional status, from any state.</li>
 * </ul>
 *
 * <p>"Already within 20 miles at creation" is read as a certified hub seen
 * within the first day after creation, since cards arrive by gossip and a hub
 * cannot see its whole region at the moment it is made.
 */
public final class ProvisionalStatus {

    /** 20 miles. */
    public static final double RADIUS_METRES = 32_187;
    public static final Duration PEER_CLOCK = Duration.ofDays(30);
    public static final Duration ABSOLUTE_CAP = Duration.ofDays(90);
    public static final Duration REVOCATION_CLOCK = Duration.ofDays(30);
    public static final Duration AT_CREATION_GRACE = Duration.ofDays(1);

    /** A hub seen on a card: where, whether it is certified, and when it was seen. */
    public record NearbyHub(String keyFingerprint, double latitude, double longitude, boolean certified,
                            Instant seenAt) {
    }

    private final Instant createdAt;
    private final Double latitude;
    private final Double longitude;
    private Instant certifiedPeerFirstSeenAt;
    private boolean certifiedPeerAtCreation;
    private Instant lastAllInboundRevokedAt;

    public ProvisionalStatus(Instant createdAt, Double latitude, Double longitude) {
        this.createdAt = createdAt;
        this.latitude = latitude;
        this.longitude = longitude;
    }

    /** From a hub's own record. Uses its approximate position. */
    public static ProvisionalStatus forHub(Hub hub) {
        HubLocation l = hub.getLocation();
        return new ProvisionalStatus(hub.getCreatedAt(), l == null ? null : l.getApproxLatitude(),
                l == null ? null : l.getApproxLongitude());
    }

    /**
     * Records a hub seen nearby. Returns true if this started the peer clock.
     * Hubs without a position never count: an unplaced hub cannot be within
     * 20 miles of anything, which errs toward the 90-day cap.
     */
    public boolean observe(NearbyHub seen) {
        if (seen == null || !seen.certified() || latitude == null || longitude == null
                || certifiedPeerFirstSeenAt != null) {
            return false;
        }
        if (HubLocation.haversineMetres(latitude, longitude, seen.latitude(), seen.longitude()) > RADIUS_METRES) {
            return false;
        }
        certifiedPeerFirstSeenAt = seen.seenAt();
        certifiedPeerAtCreation = createdAt != null && !seen.seenAt().isAfter(createdAt.plus(AT_CREATION_GRACE));
        return true;
    }

    /** Records that the last counting inbound link was revoked. */
    public void inboundRevoked(Instant at) {
        this.lastAllInboundRevokedAt = at;
    }

    /**
     * When provisional status ends, or null if the hub is not provisional at
     * all in this situation.
     *
     * @param afterRevocation the hub was unlocked and all its inbound links are revoked
     */
    public Instant deadline(boolean afterRevocation) {
        if (afterRevocation) {
            return lastAllInboundRevokedAt == null ? null : lastAllInboundRevokedAt.plus(REVOCATION_CLOCK);
        }
        if (createdAt == null || certifiedPeerAtCreation) {
            return null;
        }
        Instant cap = createdAt.plus(ABSOLUTE_CAP);
        if (certifiedPeerFirstSeenAt == null) {
            return cap;
        }
        Instant peer = certifiedPeerFirstSeenAt.plus(PEER_CLOCK);
        return peer.isBefore(cap) ? peer : cap;
    }

    /**
     * Device side: the standing this device will honour. A hub reporting
     * PROVISIONAL past the deadline this device computes from its own
     * observations is treated as guest-only. The device never loosens what
     * the hub reports; it only refuses a provisional period it cannot see a
     * reason for.
     */
    public static HubStanding enforce(HubStanding reported, ProvisionalStatus deviceView, Instant now) {
        if (reported == null || reported.getState() != HubStanding.State.PROVISIONAL || deviceView == null) {
            return reported;
        }
        boolean afterRevocation = reported.getEverUnlockedAt() != null;
        Instant until = deviceView.deadline(afterRevocation);
        if (afterRevocation && until == null) {
            // The device has no record of the revocation; it can still hold
            // the hub to the hub's own claimed deadline.
            until = reported.getProvisionalUntil();
        }
        if (until != null && now.isBefore(until)
                && (reported.getProvisionalUntil() == null || !reported.getProvisionalUntil().isAfter(until))) {
            return reported;
        }
        if (until != null && now.isBefore(until)) {
            // The hub claims a later deadline than the device allows: honour the earlier.
            return HubStanding.restore(HubStanding.State.PROVISIONAL, reported.getOutboundCounting(),
                    reported.getInboundCounting(), reported.getBonds(), reported.getEverUnlockedAt(), now, until);
        }
        return HubStanding.restore(afterRevocation ? HubStanding.State.REVOKED : HubStanding.State.UNAUTHENTICATED,
                reported.getOutboundCounting(), reported.getInboundCounting(), reported.getBonds(),
                reported.getEverUnlockedAt(), now, null);
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getCertifiedPeerFirstSeenAt() {
        return certifiedPeerFirstSeenAt;
    }

    public boolean isCertifiedPeerAtCreation() {
        return certifiedPeerAtCreation;
    }
}

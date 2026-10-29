package org.shalim.transport;

import java.time.Instant;

/**
 * A reachable device, and what we know about how to talk to it.
 *
 * <p>Created by a transport when a frame arrives from somewhere new, or when
 * a peer is configured by address. Everything learnt from frames is advisory
 * until {@link #isAuthenticated()}: only a completed {@link SecureChannel}
 * handshake sets the peer's key, and only frames sealed to that session are
 * believed.
 */
public class PeerEndpoint {

    private String endpointId;

    /**
     * Peer's key fingerprint, once verified. Null while unauthenticated. For a
     * hub replica this is the hub key; for a member's device, their account key.
     */
    private String peerUserId;

    /** The hub this endpoint was recognised as, from a beacon. Null if unknown. */
    private String hubId;
    private Transport.Kind via;

    /** Transport-specific address: IP and port, MAC, LoRa node id. */
    private String address;

    private Instant lastContactAt;

    /** Peer's log head, so we can tell whether sync is needed before spending airtime. */
    private String advertisedLogHead;

    /** Peer's censor artefact hash, checked before trusting anything it sends. */
    private String advertisedCensorPin;

    private boolean authenticated;
    private Instant authenticatedAt;

    public PeerEndpoint() {
    }

    public PeerEndpoint(Transport.Kind via, String address) {
        this.via = via;
        this.address = address;
        this.endpointId = via + "|" + address;
    }

    /**
     * Records the outcome of a completed {@link SecureChannel} handshake. This
     * replaces the pseudo-code's {@code authenticate(challenge, response)}: a
     * bare challenge-response proves key possession once, but does not bind
     * the frames that follow to that key. A session does.
     */
    public synchronized void authenticated(SecureChannel.Session session, Instant now) {
        this.peerUserId = session.remoteFingerprint();
        this.authenticated = true;
        this.authenticatedAt = now;
        this.lastContactAt = now;
    }

    /** The session ended or failed. What was learnt about the peer stays, unverified. */
    public synchronized void deauthenticated() {
        this.authenticated = false;
    }

    public synchronized void contact(Instant now) {
        this.lastContactAt = now;
    }

    /** From a beacon or a HELLO. Unverified for a beacon; session-verified for a HELLO. */
    public synchronized void advertised(String logHead, String censorPin) {
        this.advertisedLogHead = logHead;
        if (censorPin != null) {
            this.advertisedCensorPin = censorPin;
        }
    }

    public synchronized void recognisedAs(String hubId) {
        this.hubId = hubId;
    }

    /**
     * Whether this peer's censor matches ours; drives the compromised-hub flag.
     * False when the peer has advertised nothing: an unknown censor is not a
     * matching one.
     */
    public boolean censorMatches(org.shalim.ml.ModelPin ourPin) {
        return ourPin != null && advertisedCensorPin != null && ourPin.getArtefactHash() != null
                && org.shalim.crypto.Bytes.equalHex(advertisedCensorPin, ourPin.getArtefactHash());
    }

    // --- accessors --------------------------------------------------------

    public String getEndpointId() {
        return endpointId;
    }

    public String getPeerUserId() {
        return peerUserId;
    }

    public String getHubId() {
        return hubId;
    }

    public Transport.Kind getVia() {
        return via;
    }

    public String getAddress() {
        return address;
    }

    public synchronized boolean isAuthenticated() {
        return authenticated;
    }

    public synchronized Instant getAuthenticatedAt() {
        return authenticatedAt;
    }

    public synchronized String getAdvertisedLogHead() {
        return advertisedLogHead;
    }

    public synchronized String getAdvertisedCensorPin() {
        return advertisedCensorPin;
    }

    public synchronized Instant getLastContactAt() {
        return lastContactAt;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof PeerEndpoint p && endpointId != null && endpointId.equals(p.endpointId);
    }

    @Override
    public int hashCode() {
        return endpointId == null ? 0 : endpointId.hashCode();
    }
}

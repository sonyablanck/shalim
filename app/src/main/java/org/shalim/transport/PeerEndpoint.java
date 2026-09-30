package org.shalim.transport;

import java.time.Instant;

/** A reachable device, and what we know about how to talk to it. */
public class PeerEndpoint {

    private String endpointId;

    /** Peer's key fingerprint, once verified. Null while unauthenticated. */
    private String peerUserId;

    private String hubId;
    private Transport.Kind via;

    /** Transport-specific address: IP, MAC, LoRa node id. */
    private String address;

    private Instant lastContactAt;

    /** Peer's log head, so we can tell whether sync is needed before spending airtime. */
    private String advertisedLogHead;

    /** Peer's censor artefact hash, checked before trusting anything it sends. */
    private String advertisedCensorPin;

    private boolean authenticated;

    public PeerEndpoint() {
        // TODO: pseudo-code
    }

    /** Mutual key authentication. Must pass before any hub data is exchanged. */
    public boolean authenticate(byte[] challenge, byte[] response) {
        // TODO: pseudo-code
        return false;
    }

    /** Whether this peer's censor matches ours; drives the compromised-hub flag. */
    public boolean censorMatches(org.shalim.ml.ModelPin ourPin) {
        // TODO: pseudo-code
        return false;
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

    public boolean isAuthenticated() {
        return authenticated;
    }

    public String getAdvertisedLogHead() {
        return advertisedLogHead;
    }

    public String getAdvertisedCensorPin() {
        return advertisedCensorPin;
    }

    public Instant getLastContactAt() {
        return lastContactAt;
    }
}

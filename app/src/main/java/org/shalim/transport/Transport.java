package org.shalim.transport;

import java.util.List;

/**
 * A way of reaching a hub. Implementations differ enormously in capacity, so
 * capability is queryable rather than assumed — code must ask whether a payload
 * fits before sending, because what works over Wi-Fi silently fails over LoRa.
 */
public interface Transport {

    enum Kind {
        /** Hub's verified local network. Full capability; required for guest access. */
        WIFI,
        /** Mobile data. Full capability, but traceable and killable by an operator. */
        CELLULAR,
        /** Phone-to-phone, no infrastructure. Good for local sync during an outage. */
        BLUETOOTH_MESH,
        /** Long range, tiny bandwidth, duty-cycle limited. Beacons only. */
        LORA
    }

    Kind kind();

    boolean isAvailable();

    /** Largest single payload in bytes. LoRa is on the order of a few hundred. */
    int maxPayloadBytes();

    /**
     * Fraction of wall-clock time this transport may legally transmit.
     * 1.0 for Wi-Fi; about 0.01 for LoRa in EU ISM bands.
     */
    double dutyCycle();

    /** Whether full log/skill sync is realistic, as opposed to beacons only. */
    boolean supportsBulkSync();

    /** Whether traffic reveals participation to a network operator. */
    boolean isObservable();

    /** Reachable peers, discovered however the transport allows. */
    List<PeerEndpoint> discoverPeers();

    /** Sends a frame. Fails rather than fragmenting past {@link #maxPayloadBytes()}. */
    boolean send(PeerEndpoint peer, byte[] payload);

    /**
     * Largest frame {@link #broadcast} will carry. On Wi-Fi this is one UDP
     * datagram, far smaller than a unicast frame. Zero means the transport
     * cannot broadcast at all (cellular).
     */
    default int maxBroadcastBytes() {
        return maxPayloadBytes();
    }

    /**
     * Sends a frame to whoever is in range on this transport: the local network
     * segment, Bluetooth neighbours, or the LoRa channel. For claim queries,
     * beacons and card gossip only. Fails past {@link #maxBroadcastBytes()}.
     */
    boolean broadcast(byte[] payload);

    void setListener(FrameListener listener);

    /** Stops listening and releases sockets or radios. Idempotent. */
    default void close() {
    }

    interface FrameListener {
        void onFrame(PeerEndpoint from, byte[] payload);
    }
}

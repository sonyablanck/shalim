package org.shalim.hub;

import java.time.Instant;
import java.util.List;

/**
 * A hub's claim to the network it runs on. One network, one hub.
 *
 * <h2>Why</h2>
 *
 * <p>Guest access is granted by presence on a hub's network, so every hub has
 * one. Requiring that no two hubs share a network means one device, attached
 * to one network, can host one hub — which closes the "one desktop running
 * several hubs to bond them together" route. Extra networks still cost only a
 * cheap router, so this raises the price of fake hubs; it does not set it
 * high. See the README.
 *
 * <h2>What "network" means</h2>
 *
 * <p>A set of BSSIDs — the access points physically in the hub's space — not
 * an SSID. SSIDs are trivially copied, and one SSID can span a building, a
 * campus or, for eduroam, the world. Two hubs on different access points of
 * the same building's Wi-Fi are on different networks for this purpose. A
 * phone hotspot that randomises its BSSID every session cannot hold a claim.
 *
 * <h2>Where the claim lives</h2>
 *
 * <p>Nowhere global. Replicating network identifiers to other devices would
 * publish a list of BSSIDs, and BSSIDs geolocate to a building through public
 * Wi-Fi maps — defeating the hub's chosen location precision. So a claim is
 * held in three places only:
 * <ul>
 *   <li>by the hub instance, which answers claim queries on its own network
 *       (see {@link NetworkClaimService#answer});</li>
 *   <li>by each member's device, pinned when they joined — the same
 *       trust-on-first-use idea as an SSH known-hosts file;</li>
 *   <li>as a timestamp witnessed by bonded peers, which sign the claim id and
 *       its date but never see the BSSIDs.</li>
 * </ul>
 */
public class NetworkClaim {

    private String claimId;

    /** Issuer key fingerprint of the claiming hub. */
    private String hubKeyFingerprint;

    /**
     * BSSIDs claimed, hashed with a per-hub salt as elsewhere in
     * {@link HubNetwork}. Comparison with a live network is done by the hub
     * instance, which knows the salt; nobody else can test a list of BSSIDs
     * against it.
     */
    private List<String> saltedBssidHashes;

    private Instant claimedAt;

    /**
     * Signatures by bonded peers over (claimId, claimedAt), gathered at bond
     * time. Evidence of age that the claiming hub cannot backdate alone.
     */
    private List<byte[]> peerWitnesses;

    /**
     * Previous claim this one replaces, signed by the same hub key. How a hub
     * moves after its router is replaced or its premises are lost.
     */
    private String supersedesClaimId;

    private byte[] hubSignature;

    public NetworkClaim() {
        // TODO: pseudo-code
    }

    public NetworkClaim(String hubKeyFingerprint, List<String> saltedBssidHashes, Instant now) {
        // TODO: pseudo-code
    }

    /** Whether this claim covers an observed access point. Hub instance only. */
    public boolean covers(String observedBssid, byte[] hubSalt) {
        // TODO: pseudo-code
        return false;
    }

    /**
     * Which of two claims to the same access point is the older, judged on the
     * device doing the judging. Returns null when it cannot tell.
     */
    public static NetworkClaim older(NetworkClaim a, NetworkClaim b,
                                     List<String> peerKeysThisDeviceTrusts) {
        // PSEUDO-CODE
        // countA = a.peerWitnesses WHERE signer IN peerKeysThisDeviceTrusts
        // countB = likewise for b
        // IF only one has trusted witnesses -> RETURN that one
        // IF both -> RETURN the earlier claimedAt among trusted witnesses
        // RETURN null
        //    // Only witnesses the judging device already trusts count. A
        //    // displacing hub backed by colluding sock-puppet peers can have its
        //    // claim "witnessed" as years old; those witnesses mean nothing to a
        //    // device that has never trusted them.
        return null;
    }

    /** A signed move to a new network, for members' devices to follow. */
    public NetworkClaim migrate(List<String> newSaltedBssidHashes, byte[] hubPrivateKey, Instant now) {
        // TODO: pseudo-code
        return null;
    }

    // --- accessors --------------------------------------------------------

    public String getClaimId() {
        return claimId;
    }

    public String getHubKeyFingerprint() {
        return hubKeyFingerprint;
    }

    public Instant getClaimedAt() {
        return claimedAt;
    }

    public String getSupersedesClaimId() {
        return supersedesClaimId;
    }
}

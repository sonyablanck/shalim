package org.shalim.hub;

import java.time.Instant;
import java.util.List;

/**
 * Enforces one hub per network, without a registry.
 *
 * <p>Three moments:
 * <ol>
 *   <li><strong>Creation.</strong> A new hub may not be created on a network
 *       another hub already claims. The creating device asks the network and
 *       checks its own pinned claims before anything is signed.</li>
 *   <li><strong>Operation.</strong> A running hub instance answers claim
 *       queries on its network, so the creation check has something to find.
 *       A hub instance must therefore be attached to the network it claims,
 *       which also means one device can host at most one hub per network it
 *       is attached to.</li>
 *   <li><strong>Dispute.</strong> If a hub was created while the rightful hub
 *       was offline — powered down overnight, seized, or jammed — both will
 *       answer once it returns. Members' devices keep following the hub they
 *       pinned. Walk-ins see both marked as disputed and get guest access from
 *       neither until an admin resolves it.</li>
 * </ol>
 *
 * <p>The displacement attack this answers: an adversary takes a hub's device
 * offline and starts a lookalike hub on its network to capture walk-ins and
 * lapsed members. Creation refusal stops it while the hub is live. Pinning
 * stops it from taking existing members at any time. What it cannot stop is an
 * adversary who controls the network itself: replacing the router changes
 * every BSSID, and the rightful hub has to {@link NetworkClaim#migrate} to
 * whatever network it can get.
 */
public class NetworkClaimService {

    /** How long a creating device listens for existing claims before proceeding. */
    public static final int CREATION_LISTEN_MINUTES = 10;

    private final Hub hub;

    public NetworkClaimService(Hub hub) {
        this.hub = hub;
    }

    /**
     * Whether a hub may be created on the network the creating device is
     * attached to. Runs before the hub's keys are made.
     */
    public static CreationCheck mayCreateHubHere(List<String> observedBssids,
                                                 List<NetworkClaim> claimsPinnedOnThisDevice,
                                                 Instant now) {
        // PSEUDO-CODE
        //
        // 1. STABLE NETWORK
        //    IF any observed BSSID is locally administered (randomised hotspot)
        //       RETURN REFUSED_UNSTABLE_NETWORK
        //
        // 2. WHAT THIS DEVICE ALREADY KNOWS
        //    IF any pinned claim on this device matches the network
        //       RETURN REFUSED_CLAIMED
        //    // The creator is, or was, a member of a hub here.
        //
        // 3. ASK THE NETWORK
        //    FOR CREATION_LISTEN_MINUTES
        //       send claim query (fresh nonce) on the local network
        //       collect signed answers
        //    IF any answer verifies and covers an observed BSSID
        //       RETURN REFUSED_CLAIMED
        //    // Refused, with the answering hub's card if it has one, so the
        //    // would-be admin can join it instead.
        //
        // 4. RETURN ALLOWED
        //    // Allowed means "no hub answered", not "no hub exists". An offline
        //    // hub is invisible here; see resolveDispute.
        return null;
    }

    /**
     * Answers a claim query on this hub's network. Every running hub must do
     * this, including hubs that do not grant guest access.
     */
    public byte[] answer(byte[] nonce, String observedBssid, Instant now) {
        // PSEUDO-CODE
        // IF NOT hub's current claim covers observedBssid -> RETURN null
        // RETURN sign(hub key, (nonce, claimId, "claimed"))
        //    // Proves a hub claims this access point, without saying which BSSIDs
        //    // it claims or anything else about the hub. It does reveal to anyone
        //    // on the network that a Shalim hub is here — which walk-in guest
        //    // access already reveals, but for a hub that admits by invitation
        //    // only, it is new.
        return null;
    }

    /**
     * Two hubs answer for the same access point. Resolved on each device
     * separately; there is nowhere to resolve it centrally.
     */
    public static DisputeOutcome resolveDispute(NetworkClaim a, NetworkClaim b,
                                                NetworkClaim pinnedOnThisDevice,
                                                List<String> peerKeysThisDeviceTrusts) {
        // PSEUDO-CODE
        //
        // 1. IF this device pinned one of them -> RETURN FOLLOW_PINNED
        //    // Existing members are never moved by a newcomer's claim, however
        //    // it is witnessed.
        //
        // 2. older = NetworkClaim.older(a, b, peerKeysThisDeviceTrusts)
        //    IF older != null -> RETURN FAVOUR_OLDER, with both shown as disputed
        //
        // 3. RETURN DISPUTED
        //    // Neither hub issues presence proofs this device will accept on
        //    // this network. A walk-in gets no guest access from either rather
        //    // than guest access from the wrong one.
        //
        // In every case: log NETWORK_CLAIM_DISPUTED on each hub that learns of
        // it, and show its admins. A disputed hub is not viable for listing
        // (Hub.isViable) until it migrates or the other hub stops answering.
        return null;
    }

    public enum CreationCheck {
        ALLOWED,
        REFUSED_CLAIMED,
        REFUSED_UNSTABLE_NETWORK
    }

    public enum DisputeOutcome {
        FOLLOW_PINNED,
        FAVOUR_OLDER,
        DISPUTED
    }

    public Hub getHub() {
        return hub;
    }
}

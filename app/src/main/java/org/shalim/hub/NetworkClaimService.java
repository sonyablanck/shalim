package org.shalim.hub;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.shalim.crypto.Signer;

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
     * Asks the local network whether any hub claims an access point. The
     * transport layer implements this ({@code org.shalim.transport.ClaimQueryClient}),
     * so this package stays free of transports.
     */
    public interface ClaimProbe {
        /**
         * Broadcasts claim queries for {@code bssid} with {@code nonce} for
         * the whole of {@code listen}, and returns every answer received.
         * Answers are not verified here; the caller does that.
         */
        List<ClaimAnswer> ask(byte[] nonce, String bssid, Duration listen);
    }

    /** The result of a creation check, with the answering hubs if refused for that reason. */
    public record CreationResult(CreationCheck check, List<ClaimAnswer> answers) {
        public CreationResult {
            answers = List.copyOf(answers);
        }
    }

    /**
     * Whether a hub may be created on the network the creating device is
     * attached to. Runs before the hub's keys are made.
     *
     * @param attachedBssid the access point the device is associated with now,
     *                      which is the one the claim query names
     */
    public static CreationResult mayCreateHubHere(List<String> observedBssids, String attachedBssid,
                                                  ClaimPins pinsOnThisDevice, ClaimProbe probe,
                                                  Duration listen) {
        // 1. STABLE NETWORK
        if (observedBssids == null || observedBssids.isEmpty() || attachedBssid == null) {
            return new CreationResult(CreationCheck.REFUSED_UNSTABLE_NETWORK, List.of());
        }
        for (String bssid : observedBssids) {
            if (!Bssid.isStable(bssid)) {
                return new CreationResult(CreationCheck.REFUSED_UNSTABLE_NETWORK, List.of());
            }
        }
        if (!Bssid.isStable(attachedBssid)) {
            return new CreationResult(CreationCheck.REFUSED_UNSTABLE_NETWORK, List.of());
        }

        // 2. WHAT THIS DEVICE ALREADY KNOWS
        //    The creator is, or was, a member of a hub here.
        List<String> all = new ArrayList<>(observedBssids);
        all.add(attachedBssid);
        if (pinsOnThisDevice != null && pinsOnThisDevice.matching(all).isPresent()) {
            return new CreationResult(CreationCheck.REFUSED_CLAIMED, List.of());
        }

        // 3. ASK THE NETWORK
        byte[] nonce = org.shalim.crypto.Bytes.random(32);
        List<ClaimAnswer> verified = new ArrayList<>();
        for (ClaimAnswer answer : probe.ask(nonce, attachedBssid, listen)) {
            if (answer.verify(nonce, attachedBssid)) {
                verified.add(answer);
            }
        }
        if (!verified.isEmpty()) {
            // Refused, with the answering hubs, so the would-be admin can join
            // one instead.
            return new CreationResult(CreationCheck.REFUSED_CLAIMED, verified);
        }

        // 4. Allowed means "no hub answered", not "no hub exists". An offline
        //    hub is invisible here; see resolveDispute.
        return new CreationResult(CreationCheck.ALLOWED, List.of());
    }

    /** With the default ten-minute listen. */
    public static CreationResult mayCreateHubHere(List<String> observedBssids, String attachedBssid,
                                                  ClaimPins pinsOnThisDevice, ClaimProbe probe) {
        return mayCreateHubHere(observedBssids, attachedBssid, pinsOnThisDevice, probe,
                Duration.ofMinutes(CREATION_LISTEN_MINUTES));
    }

    /**
     * Makes and signs a new hub's claim over every access point in its space,
     * once {@link #mayCreateHubHere} has allowed it.
     */
    public static NetworkClaim createClaim(List<String> bssids, byte[] hubSalt, Signer hubKey, Instant now) {
        List<String> hashes = new ArrayList<>();
        for (String bssid : bssids) {
            if (!Bssid.isStable(bssid)) {
                throw new IllegalArgumentException("unstable access point cannot be claimed");
            }
            hashes.add(NetworkClaim.saltedBssidHash(bssid, hubSalt));
        }
        return new NetworkClaim(hubKey.fingerprint(), hashes, now).sign(hubKey);
    }

    /**
     * Answers a claim query on this hub's network. Every running hub must do
     * this, including hubs that do not grant guest access. Returns null when
     * the hub does not claim the access point asked about, and then sends
     * nothing at all.
     *
     * <p>Proves a hub claims this access point, without saying which BSSIDs it
     * claims or anything else about the hub. It does reveal to anyone on the
     * network that a Shalim hub is here, and its key. Walk-in guest access
     * already reveals that; for a hub that admits by invitation only, it is
     * new (open question 13).
     */
    public ClaimAnswer answer(byte[] nonce, String observedBssid, Signer hubKey, byte[] hubSalt) {
        HubNetwork network = hub.getNetwork();
        NetworkClaim claim = network == null ? null : network.getClaim();
        if (claim == null || nonce == null || nonce.length < 16
                || !claim.getHubKeyFingerprint().equals(hubKey.fingerprint())
                || !claim.covers(observedBssid, hubSalt)) {
            return null;
        }
        return ClaimAnswer.sign(claim, hubKey, nonce, observedBssid);
    }

    /** How a device should treat two hubs answering for one access point. */
    public record Resolution(DisputeOutcome outcome, NetworkClaim follow) {
    }

    /**
     * Two hubs answer for the same access point. Resolved on each device
     * separately; there is nowhere to resolve it centrally.
     *
     * <p>In every case the caller logs NETWORK_CLAIM_DISPUTED on each hub that
     * learns of it and shows its admins. A disputed hub is not viable for
     * listing ({@link Hub#isViable}) until it migrates or the other hub stops
     * answering.
     */
    public static Resolution resolveDispute(NetworkClaim a, NetworkClaim b,
                                            NetworkClaim pinnedOnThisDevice,
                                            Map<String, byte[]> peerKeysThisDeviceTrusts) {
        // 1. Existing members are never moved by a newcomer's claim, however it
        //    is witnessed. The pin is by hub key, so a hub that has migrated
        //    since the device pinned it is still recognised.
        if (pinnedOnThisDevice != null) {
            String pinnedHub = pinnedOnThisDevice.getHubKeyFingerprint();
            if (a != null && pinnedHub.equals(a.getHubKeyFingerprint())) {
                return new Resolution(DisputeOutcome.FOLLOW_PINNED, a);
            }
            if (b != null && pinnedHub.equals(b.getHubKeyFingerprint())) {
                return new Resolution(DisputeOutcome.FOLLOW_PINNED, b);
            }
        }
        // 2. Older by witnesses this device trusts; both are still shown as disputed.
        NetworkClaim older = NetworkClaim.older(a, b, peerKeysThisDeviceTrusts);
        if (older != null) {
            return new Resolution(DisputeOutcome.FAVOUR_OLDER, older);
        }
        // 3. Neither hub issues presence proofs this device will accept on this
        //    network. A walk-in gets no guest access from either rather than
        //    guest access from the wrong one.
        return new Resolution(DisputeOutcome.DISPUTED, null);
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

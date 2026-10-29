package org.shalim.transport;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.shalim.crypto.Bytes;
import org.shalim.crypto.SoftwareSigner;
import org.shalim.hub.Bssid;
import org.shalim.hub.ClaimAnswer;
import org.shalim.hub.ClaimPins;
import org.shalim.hub.Hub;
import org.shalim.hub.HubNetwork;
import org.shalim.hub.NetworkClaim;
import org.shalim.hub.NetworkClaimService;
import org.shalim.hub.PremisesCode;
import org.shalim.hub.PresenceProof;
import org.shalim.testing.Check;

/** Creation checks, claim answers, pins, disputes and presence. */
public final class NetworkClaimsOverTheAirTest {

    private static final Instant NOW = Instant.parse("2026-10-29T09:00:00Z");
    private static final String AP1 = "00:11:22:33:44:01";
    private static final String AP2 = "00:11:22:33:44:02";
    private static final String OTHER_AP = "00:11:22:99:99:99";
    private static final Duration LISTEN = Duration.ofMillis(300);

    private NetworkClaimsOverTheAirTest() {
    }

    /** A running hub instance answering claim queries on an in-memory Wi-Fi. */
    private static final class LiveHub {
        final SoftwareSigner key = SoftwareSigner.generate();
        final byte[] salt = Bytes.random(32);
        final Hub hub;
        final InMemoryNetwork.InMemoryTransport transport;

        LiveHub(InMemoryNetwork net, String address, List<String> aps) {
            NetworkClaim claim = NetworkClaimService.createClaim(aps, salt, key, NOW);
            HubNetwork network = new HubNetwork("hub", "Library", claim.getSaltedBssidHashes(), true, true, true);
            network.setClaim(claim);
            hub = new Hub("hub", "Library", null, null, network, null);
            transport = net.join(address, TransportProfile.wifi(false));
            new SyncService("hub", List.of(transport), key, null, Clock.systemUTC())
                    .answeringClaims(new NetworkClaimService(hub), key, salt).attach();
        }
    }

    private static ClaimQueryClient device(InMemoryNetwork net, String address) {
        InMemoryNetwork.InMemoryTransport t = net.join(address, TransportProfile.wifi(false));
        ClaimQueryClient client = new ClaimQueryClient(t);
        t.setListener(client);
        return client;
    }

    public static void testBssidStability() {
        Check.isTrue(Bssid.isStable(AP1), "vendor address");
        Check.isFalse(Bssid.isStable("02:11:22:33:44:55"), "locally administered (hotspot)");
        Check.isFalse(Bssid.isStable("01:00:5e:00:00:01"), "multicast");
        Check.isFalse(Bssid.isStable("ff:ff:ff:ff:ff:ff"), "broadcast");
        Check.isFalse(Bssid.isStable("not a mac"), "malformed");
        Check.equal(AP1, Bssid.normalise("00-11-22-33-44-01"), "normalised");
    }

    public static void testCreationRefusedOnALiveHubsNetworkAndAllowedElsewhere() {
        InMemoryNetwork net = new InMemoryNetwork();
        LiveHub live = new LiveHub(net, "hub", List.of(AP1, AP2));
        ClaimQueryClient creator = device(net, "creator");
        ClaimPins noPins = new ClaimPins(Bytes.random(32));

        NetworkClaimService.CreationResult onClaimed = NetworkClaimService.mayCreateHubHere(
                List.of(AP1, AP2), AP2, noPins, creator, LISTEN);
        Check.equal(NetworkClaimService.CreationCheck.REFUSED_CLAIMED, onClaimed.check(), "refused");
        Check.equal(live.key.fingerprint(), onClaimed.answers().get(0).hubKeyFingerprint(),
                "and told which hub to join instead");

        NetworkClaimService.CreationResult elsewhere = NetworkClaimService.mayCreateHubHere(
                List.of(OTHER_AP), OTHER_AP, noPins, creator, LISTEN);
        Check.equal(NetworkClaimService.CreationCheck.ALLOWED, elsewhere.check(), "unclaimed access point");

        NetworkClaimService.CreationResult hotspot = NetworkClaimService.mayCreateHubHere(
                List.of("06:11:22:33:44:55"), "06:11:22:33:44:55", noPins, creator, LISTEN);
        Check.equal(NetworkClaimService.CreationCheck.REFUSED_UNSTABLE_NETWORK, hotspot.check(), "hotspot");
    }

    public static void testPinsRefuseCreationEvenWhenTheHubIsOffline() {
        InMemoryNetwork net = new InMemoryNetwork();
        LiveHub live = new LiveHub(net, "hub", List.of(AP1));
        ClaimQueryClient member = device(net, "member");
        ClaimPins pins = new ClaimPins(Bytes.random(32));
        byte[] nonce = Bytes.random(32);
        List<ClaimAnswer> answers = member.ask(nonce, AP1, LISTEN);
        Check.notNull(pins.pin(answers.get(0), nonce, AP1, NOW), "pinned at join");
        live.transport.setAvailable(false); // seized, switched off, jammed
        NetworkClaimService.CreationResult r = NetworkClaimService.mayCreateHubHere(List.of(AP1), AP1, pins,
                member, LISTEN);
        Check.equal(NetworkClaimService.CreationCheck.REFUSED_CLAIMED, r.check(),
                "a member's device still refuses to found a lookalike on its hub's network");
        Check.isTrue(member.confirmAttached(live.key.fingerprint(), AP1, LISTEN) == false,
                "and cannot confirm attachment to a hub that is not answering");
    }

    public static void testDeviceConfirmsAttachmentAndAnswersAreFreshAndBound() {
        InMemoryNetwork net = new InMemoryNetwork();
        LiveHub live = new LiveHub(net, "hub", List.of(AP1));
        ClaimQueryClient guest = device(net, "guest");
        Check.isTrue(guest.confirmAttached(live.key.fingerprint(), AP1, LISTEN), "on the hub's network");
        Check.isFalse(guest.confirmAttached(live.key.fingerprint(), OTHER_AP, LISTEN), "not for another AP");
        byte[] nonce = Bytes.random(32);
        ClaimAnswer a = guest.ask(nonce, AP1, LISTEN).get(0);
        Check.isTrue(a.verify(nonce, AP1), "answers this query");
        Check.isFalse(a.verify(Bytes.random(32), AP1), "a recorded answer cannot be replayed to a new query");
        Check.isFalse(a.verify(nonce, AP2), "bound to the access point asked about");
        ClaimFrames.Answer decoded = ClaimFrames.readAnswer(ClaimFrames.answer(nonce, a));
        Check.isTrue(decoded.answer().verify(nonce, AP1), "wire round trip");
    }

    public static void testDisputeResolution() {
        SoftwareSigner rightful = SoftwareSigner.generate();
        SoftwareSigner lookalike = SoftwareSigner.generate();
        SoftwareSigner trustedPeer = SoftwareSigner.generate();
        SoftwareSigner sockPuppet = SoftwareSigner.generate();
        NetworkClaim old = new NetworkClaim(rightful.fingerprint(), List.of(), NOW.minus(Duration.ofDays(400)))
                .sign(rightful);
        old.addWitness(old.witness(trustedPeer, NOW.minus(Duration.ofDays(300))), trustedPeer.publicKey());
        NetworkClaim fresh = new NetworkClaim(lookalike.fingerprint(), List.of(), NOW.minus(Duration.ofDays(900)))
                .sign(lookalike); // backdated claimedAt
        fresh.addWitness(fresh.witness(sockPuppet, NOW.minus(Duration.ofDays(800))), sockPuppet.publicKey());

        Map<String, byte[]> trust = Map.of(trustedPeer.fingerprint(), trustedPeer.publicKey());
        NetworkClaimService.Resolution r = NetworkClaimService.resolveDispute(fresh, old, null, trust);
        Check.equal(NetworkClaimService.DisputeOutcome.FAVOUR_OLDER, r.outcome(), "older by trusted witness");
        Check.isTrue(r.follow() == old, "a backdated claim with untrusted witnesses does not win");

        NetworkClaimService.Resolution pinned = NetworkClaimService.resolveDispute(old, fresh, fresh, trust);
        Check.equal(NetworkClaimService.DisputeOutcome.FOLLOW_PINNED, pinned.outcome(), "pin beats age");
        Check.isTrue(pinned.follow() == fresh, "members follow the hub they joined");

        NetworkClaimService.Resolution neither = NetworkClaimService.resolveDispute(old, fresh, null, Map.of());
        Check.equal(NetworkClaimService.DisputeOutcome.DISPUTED, neither.outcome(), "walk-ins get neither");

        NetworkClaim.Witness forged = new NetworkClaim.Witness(trustedPeer.fingerprint(),
                NOW.minus(Duration.ofDays(999)), new byte[64]);
        NetworkClaim forgedClaim = NetworkClaim.summary("x", lookalike.fingerprint(), NOW, null, List.of(forged));
        Check.isNull(forgedClaim.earliestTrustedWitness(trust), "a forged witness signature counts for nothing");
    }

    public static void testPinsFollowMigration() {
        SoftwareSigner key = SoftwareSigner.generate();
        byte[] salt = Bytes.random(32);
        NetworkClaim claim = NetworkClaimService.createClaim(List.of(AP1), salt, key, NOW);
        HubNetwork network = new HubNetwork("hub", "Library", claim.getSaltedBssidHashes(), true, true, true);
        network.setClaim(claim);
        NetworkClaimService service = new NetworkClaimService(new Hub("hub", "L", null, null, network, null));
        byte[] nonce = Bytes.random(32);
        ClaimPins pins = new ClaimPins(Bytes.random(32));
        pins.pin(service.answer(nonce, AP1, key, salt), nonce, AP1, NOW);
        NetworkClaim moved = claim.migrate(List.of(NetworkClaim.saltedBssidHash(OTHER_AP, salt)), key,
                NOW.plusSeconds(60));
        Check.isTrue(pins.follow(moved, OTHER_AP), "followed");
        Check.isTrue(pins.matching(List.of(OTHER_AP)).isPresent(), "new access point recognised");
        Check.isFalse(pins.matching(List.of(AP1)).isPresent(), "old one forgotten");
        Check.isNull(service.answer(nonce, OTHER_AP, key, salt), "hub does not answer for unclaimed APs");
    }

    public static void testPresenceProofsAndCodes() {
        SoftwareSigner key = SoftwareSigner.generate();
        byte[] salt = Bytes.random(32);
        HubNetwork network = new HubNetwork("hub", "Library",
                List.of(NetworkClaim.saltedBssidHash(AP1, salt)), true, true, true);
        Check.isTrue(network.isAttached(NetworkClaim.saltedBssidHash(AP1, salt), HubNetwork.Attachment.WIFI),
                "attached by BSSID");
        Check.isFalse(network.isAttached(NetworkClaim.saltedBssidHash(OTHER_AP, salt), HubNetwork.Attachment.WIFI),
                "not by another");
        Check.isFalse(network.isAttached(NetworkClaim.saltedBssidHash(AP1, salt),
                HubNetwork.Attachment.BLUETOOTH_PROXIMITY), "Bluetooth fails closed until built");
        String device = SoftwareSigner.generate().fingerprint();
        PresenceProof proof = network.issuePresenceProof(device, true, 30, key, NOW);
        Check.isTrue(proof.verify(key.publicKey(), device, NOW.plusSeconds(60)), "valid for this device");
        Check.isFalse(proof.verify(key.publicKey(), device, NOW.plus(Duration.ofMinutes(31))), "expires in minutes");
        Check.isFalse(proof.verify(key.publicKey(), "other", NOW), "bound to the device");
        Check.isTrue(network.canRefresh(proof, device, true), "still in the building");
        Check.isFalse(network.canRefresh(proof, device, false), "gone home");
        network.markDisputed();
        Check.isFalse(network.isAttached(NetworkClaim.saltedBssidHash(AP1, salt), HubNetwork.Attachment.WIFI),
                "no guest access while disputed");
        Check.isNull(network.issuePresenceProof(device, true, 30, key, NOW), "and no proofs");
        Check.isFalse(new HubNetwork("h", "Cafe", List.of(), false, true, true).isTrustworthyPresenceSignal(),
                "a cafe's Wi-Fi is not presence");

        PremisesCode codes = new PremisesCode(Bytes.random(32));
        HubNetwork codeNet = new HubNetwork("h", "Cafe", List.of(), false, true, true);
        String code = codes.current(NOW);
        Check.isTrue(codeNet.isAttachedByCode(code, codes, NOW.plusSeconds(10)), "code admits");
        Check.isFalse(codeNet.isAttachedByCode(code, codes, NOW.plusSeconds(20)), "once");
        Check.isFalse(codes.redeem(codes.current(NOW), NOW.plus(Duration.ofMinutes(15))), "stale code refused");
    }
}

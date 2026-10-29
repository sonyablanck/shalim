package org.shalim.hub;

import java.time.Instant;
import java.util.List;
import org.shalim.crypto.Bytes;
import org.shalim.crypto.SoftwareSigner;
import org.shalim.testing.Check;

public final class NetworkClaimTest {

    private static final Instant NOW = Instant.parse("2026-10-29T09:00:00Z");

    private NetworkClaimTest() {
    }

    public static void testCoversOnlyClaimedAccessPointsAndNormalises() {
        byte[] salt = Bytes.random(32);
        SoftwareSigner hub = SoftwareSigner.generate();
        NetworkClaim claim = new NetworkClaim(hub.fingerprint(),
                List.of(NetworkClaim.saltedBssidHash("aa:bb:cc:dd:ee:01", salt)), NOW).sign(hub);
        Check.isTrue(claim.covers("AA-BB-CC-DD-EE-01", salt), "same BSSID, different notation");
        Check.isFalse(claim.covers("aa:bb:cc:dd:ee:02", salt), "neighbouring access point");
        Check.isFalse(claim.covers("aa:bb:cc:dd:ee:01", Bytes.random(32)), "useless without the salt");
    }

    public static void testSignatureWitnessAndMigration() {
        byte[] salt = Bytes.random(32);
        SoftwareSigner hub = SoftwareSigner.generate();
        SoftwareSigner peer = SoftwareSigner.generate();
        NetworkClaim claim = new NetworkClaim(hub.fingerprint(),
                List.of(NetworkClaim.saltedBssidHash("aa:bb:cc:dd:ee:01", salt)), NOW).sign(hub);
        Check.isTrue(claim.verify(hub.publicKey()), "claim verifies");
        Check.isFalse(claim.verify(peer.publicKey()), "not under another key");
        Check.throwsA(IllegalArgumentException.class, () -> new NetworkClaim(hub.fingerprint(), List.of(), NOW)
                .sign(peer), "only the named hub can sign");

        NetworkClaim.Witness w = claim.witness(peer, NOW);
        Check.isTrue(claim.addWitness(w, peer.publicKey()), "witness accepted");
        Check.isFalse(claim.addWitness(w, hub.publicKey()), "witness under the wrong key refused");
        Check.equal(1, claim.getPeerWitnesses().size(), "one witness");

        NetworkClaim moved = claim.migrate(List.of(NetworkClaim.saltedBssidHash("11:22:33:44:55:66", salt)),
                hub, NOW.plusSeconds(86400));
        Check.isTrue(claim.isMigrationTo(moved, hub.publicKey()), "members follow a signed move");
        NetworkClaim impostor = new NetworkClaim(peer.fingerprint(), List.of(), NOW).sign(peer);
        Check.isFalse(claim.isMigrationTo(impostor, peer.publicKey()), "not a move by someone else");
    }
}

package org.shalim.hub;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import org.shalim.crypto.Bytes;
import org.shalim.crypto.Canonical;
import org.shalim.crypto.Ed25519;
import org.shalim.crypto.Fingerprints;
import org.shalim.crypto.Prf;
import org.shalim.crypto.Signer;

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
     *
     * <p>The "salted hash" is HMAC-SHA256 keyed by the salt (see
     * {@link #saltedBssidHash}), and the salt must stay secret. A BSSID is only
     * 48 bits, and vendor prefixes cut that further, so anyone holding the salt
     * can brute-force every hash in minutes. The salt is therefore a key, not
     * merely a salt.
     */
    private List<String> saltedBssidHashes;

    private Instant claimedAt;

    /**
     * Signatures by bonded peers, gathered at bond time. Evidence of age that
     * the claiming hub cannot backdate alone. Each carries its signer's key
     * fingerprint, which {@link #older} needs in order to count only witnesses
     * the judging device trusts.
     *
     * <p>Changed in stage 2: a witness now signs its <em>own</em> time,
     * {@code witnessedAt}, as well as the claim's. {@code claimedAt} is
     * whatever the claiming hub says, and a witness signing it proves nothing
     * about when the claim existed. A witness's own date is an upper bound
     * the claimer cannot move: the claim existed no later than then.
     */
    private List<Witness> peerWitnesses;

    /** One bonded peer's signature over {@link #witnessPayload(Instant)}. */
    public record Witness(String peerKeyFingerprint, Instant witnessedAt, byte[] signature) {
        public Witness {
            signature = signature.clone();
        }

        @Override
        public byte[] signature() {
            return signature.clone();
        }
    }

    /**
     * Previous claim this one replaces, signed by the same hub key. How a hub
     * moves after its router is replaced or its premises are lost.
     */
    private String supersedesClaimId;

    private byte[] hubSignature;

    public NetworkClaim() {
        this.saltedBssidHashes = new ArrayList<>();
        this.peerWitnesses = new ArrayList<>();
    }

    /**
     * A new, unsigned claim. {@link #sign} it with the hub key before it is
     * pinned or answered with. The id is random, so it says nothing about the
     * BSSIDs, the hub, or the time.
     */
    public NetworkClaim(String hubKeyFingerprint, List<String> saltedBssidHashes, Instant now) {
        this();
        this.claimId = Bytes.randomId();
        this.hubKeyFingerprint = hubKeyFingerprint;
        this.saltedBssidHashes = List.copyOf(saltedBssidHashes);
        this.claimedAt = now;
    }

    /**
     * {@code HMAC-SHA256(salt, normalised BSSID)}, as hex. Normalised means
     * lower case with colon separators, so {@code AA-BB-CC-...} and
     * {@code aa:bb:cc:...} hash the same.
     */
    public static String saltedBssidHash(String bssid, byte[] hubSalt) {
        String normalised = bssid.trim().toLowerCase(Locale.ROOT).replace('-', ':');
        return Bytes.hex(Prf.hmac(hubSalt, Canonical.of("shalim.bssid.v1").string(normalised).encode()));
    }

    /** Whether this claim covers an observed access point. Hub instance only. */
    public boolean covers(String observedBssid, byte[] hubSalt) {
        if (observedBssid == null || hubSalt == null) {
            return false;
        }
        String observed = saltedBssidHash(observedBssid, hubSalt);
        boolean found = false;
        for (String claimed : saltedBssidHashes) {
            found |= Bytes.equalHex(claimed, observed);
        }
        return found;
    }

    /**
     * What the hub key signs: {@code ("shalim.netclaim.v1", claimId, hub,
     * {salted BSSID hashes}, claimedAt, supersedesClaimId)}.
     */
    public byte[] signingPayload() {
        return Canonical.of("shalim.netclaim.v1").string(claimId).hex(hubKeyFingerprint)
                .strings(saltedBssidHashes).instant(claimedAt).string(supersedesClaimId).encode();
    }

    /** Signs the claim with the hub key it names. */
    public NetworkClaim sign(Signer hubKey) {
        if (!hubKey.fingerprint().equals(hubKeyFingerprint)) {
            throw new IllegalArgumentException("a claim is signed by the hub it names");
        }
        this.hubSignature = hubKey.sign(signingPayload());
        return this;
    }

    /** Whether the claim is intact and signed by the key it names. */
    public boolean verify(byte[] hubPublicKey) {
        return Fingerprints.matchesSigningKey(hubKeyFingerprint, hubPublicKey)
                && Ed25519.verify(hubPublicKey, signingPayload(), hubSignature);
    }

    /**
     * What a bonded peer witnesses: {@code ("shalim.netclaim.witness.v2",
     * claimId, hub, claimedAt, witnessedAt)}. Never the BSSID hashes.
     */
    public byte[] witnessPayload(Instant witnessedAt) {
        return Canonical.of("shalim.netclaim.witness.v2").string(claimId).hex(hubKeyFingerprint)
                .instant(claimedAt).instant(witnessedAt).encode();
    }

    /** Peer side, at bond formation: witness this claim as existing now. */
    public Witness witness(Signer peerKey, Instant now) {
        return new Witness(peerKey.fingerprint(), now, peerKey.sign(witnessPayload(now)));
    }

    /** Whether a witness's signature verifies against the key it names. */
    public boolean verifyWitness(Witness witness, byte[] peerPublicKey) {
        return witness != null && witness.witnessedAt() != null
                && Fingerprints.matchesSigningKey(witness.peerKeyFingerprint(), peerPublicKey)
                && Ed25519.verify(peerPublicKey, witnessPayload(witness.witnessedAt()), witness.signature());
    }

    /** Adds a witness if its signature verifies against the key it names. */
    public boolean addWitness(Witness witness, byte[] peerPublicKey) {
        if (!verifyWitness(witness, peerPublicKey)) {
            return false;
        }
        peerWitnesses.add(witness);
        return true;
    }

    /**
     * A claim as a device learns it from a {@link ClaimAnswer}: identity,
     * date, lineage and witnesses, but no BSSID hashes, which never leave the
     * premises. It carries no hub signature of its own: the answer's
     * signature, made by the same key over a fresh nonce, stands in for it.
     */
    public static NetworkClaim summary(String claimId, String hubKeyFingerprint, Instant claimedAt,
                                       String supersedesClaimId, List<Witness> witnesses) {
        NetworkClaim c = new NetworkClaim();
        c.claimId = claimId;
        c.hubKeyFingerprint = hubKeyFingerprint;
        c.claimedAt = claimedAt;
        c.supersedesClaimId = supersedesClaimId;
        c.peerWitnesses = new ArrayList<>(witnesses == null ? List.of() : witnesses);
        return c;
    }

    /**
     * Earliest time a witness this device trusts vouched for the claim.
     * Witnesses are checked here, not trusted from {@link #getPeerWitnesses},
     * because a summary arrives over the network. Null if none.
     */
    public Instant earliestTrustedWitness(java.util.Map<String, byte[]> trustedPeerKeys) {
        Instant earliest = null;
        for (Witness w : peerWitnesses) {
            byte[] key = trustedPeerKeys.get(w.peerKeyFingerprint());
            if (key != null && verifyWitness(w, key)
                    && (earliest == null || w.witnessedAt().isBefore(earliest))) {
                earliest = w.witnessedAt();
            }
        }
        return earliest;
    }

    public List<Witness> getPeerWitnesses() {
        return List.copyOf(peerWitnesses);
    }

    /**
     * Which of two claims to the same access point is the older, judged on the
     * device doing the judging. Returns null when it cannot tell.
     */
    public static NetworkClaim older(NetworkClaim a, NetworkClaim b,
                                     java.util.Map<String, byte[]> peerKeysThisDeviceTrusts) {
        // Only witnesses the judging device already trusts count. A displacing
        // hub backed by colluding sock-puppet peers can have its claim
        // "witnessed" as years old; those witnesses mean nothing to a device
        // that has never trusted them.
        Instant ta = a == null ? null : a.earliestTrustedWitness(peerKeysThisDeviceTrusts);
        Instant tb = b == null ? null : b.earliestTrustedWitness(peerKeysThisDeviceTrusts);
        if (ta == null && tb == null) {
            return null;
        }
        if (ta == null) {
            return b;
        }
        if (tb == null) {
            return a;
        }
        if (ta.equals(tb)) {
            return null;
        }
        return ta.isBefore(tb) ? a : b;
    }

    /** A signed move to a new network, for members' devices to follow. */
    public NetworkClaim migrate(List<String> newSaltedBssidHashes, Signer hubKey, Instant now) {
        NetworkClaim next = new NetworkClaim(hubKeyFingerprint, newSaltedBssidHashes, now);
        next.supersedesClaimId = claimId;
        return next.sign(hubKey);
        // Members' devices follow a migration only if it verifies against the
        // hub key they pinned at join and names the claim they pinned as the one
        // it supersedes. Witnesses do not carry over: the new claim's age starts
        // now, and the chain of supersedes ids is what links it to the old one.
    }

    /** Device side: whether {@code next} is a valid move from this pinned claim. */
    public boolean isMigrationTo(NetworkClaim next, byte[] hubPublicKey) {
        return next != null && claimId != null && claimId.equals(next.supersedesClaimId)
                && hubKeyFingerprint.equals(next.hubKeyFingerprint) && next.verify(hubPublicKey);
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

    public List<String> getSaltedBssidHashes() {
        return List.copyOf(saltedBssidHashes);
    }
}

package org.shalim.hub;

import java.time.Instant;
import java.util.List;
import org.shalim.crypto.Canonical;
import org.shalim.crypto.Ed25519;
import org.shalim.crypto.Fingerprints;
import org.shalim.crypto.Signer;

/**
 * A running hub's answer to "does a hub claim this access point?", asked by a
 * device on the network with a fresh nonce.
 *
 * <p>Signed by the hub key over {@code ("shalim.claim.answer.v1", nonce,
 * bssid, claimId, claimedAt, supersedesClaimId)}. The nonce stops replay: a
 * recording of yesterday's answer cannot block today's creation or fake a
 * hub's presence. The BSSID in the signature is the one the asker named,
 * which it already knows, because it is attached to it. The claim's hashed
 * BSSID list is never sent.
 *
 * <p>An answer proves that the holder of this key says it claims this access
 * point, now. It does not prove the claim is legitimate. Anyone can run a hub
 * key and answer "claimed" to block creation on a network. That only refuses
 * creation, which is the safe direction, and it is exactly the dispute that
 * {@link NetworkClaimService#resolveDispute} handles.
 */
public final class ClaimAnswer {

    private final byte[] hubPublicKey;
    private final String claimId;
    private final Instant claimedAt;
    private final String supersedesClaimId;
    private final List<NetworkClaim.Witness> witnesses;
    private final byte[] signature;

    public ClaimAnswer(byte[] hubPublicKey, String claimId, Instant claimedAt, String supersedesClaimId,
                       List<NetworkClaim.Witness> witnesses, byte[] signature) {
        this.hubPublicKey = hubPublicKey.clone();
        this.claimId = claimId;
        this.claimedAt = claimedAt;
        this.supersedesClaimId = supersedesClaimId;
        this.witnesses = List.copyOf(witnesses);
        this.signature = signature.clone();
    }

    static ClaimAnswer sign(NetworkClaim claim, Signer hubKey, byte[] nonce, String bssid) {
        byte[] sig = hubKey.sign(payload(nonce, bssid, claim.getClaimId(), claim.getClaimedAt(),
                claim.getSupersedesClaimId()));
        return new ClaimAnswer(hubKey.publicKey(), claim.getClaimId(), claim.getClaimedAt(),
                claim.getSupersedesClaimId(), claim.getPeerWitnesses(), sig);
    }

    private static byte[] payload(byte[] nonce, String bssid, String claimId, Instant claimedAt,
                                  String supersedes) {
        return Canonical.of("shalim.claim.answer.v1").bytes(nonce).string(Bssid.normalise(bssid))
                .string(claimId).instant(claimedAt).string(supersedes).encode();
    }

    /** Whether this answers <em>our</em> question about <em>this</em> access point. */
    public boolean verify(byte[] nonce, String bssid) {
        return Bssid.normalise(bssid) != null
                && Ed25519.verify(hubPublicKey, payload(nonce, bssid, claimId, claimedAt, supersedesClaimId),
                        signature);
    }

    /** The claim as a device may hold it: no BSSID hashes. */
    public NetworkClaim toClaim() {
        return NetworkClaim.summary(claimId, hubKeyFingerprint(), claimedAt, supersedesClaimId, witnesses);
    }

    public String hubKeyFingerprint() {
        return Fingerprints.signingKey(hubPublicKey);
    }

    public byte[] getHubPublicKey() {
        return hubPublicKey.clone();
    }

    public String getClaimId() {
        return claimId;
    }

    public Instant getClaimedAt() {
        return claimedAt;
    }

    public String getSupersedesClaimId() {
        return supersedesClaimId;
    }

    public List<NetworkClaim.Witness> getWitnesses() {
        return witnesses;
    }

    public byte[] getSignature() {
        return signature.clone();
    }
}

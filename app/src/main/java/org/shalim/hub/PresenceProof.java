package org.shalim.hub;

import java.time.Instant;
import org.shalim.crypto.Canonical;
import org.shalim.crypto.Ed25519;
import org.shalim.crypto.Fingerprints;
import org.shalim.crypto.Signer;

/**
 * "This key was on this hub's network at this time." Signed by the hub key
 * over {@code ("shalim.presence.v1", hub, device, issuedAt, expiresAt)}.
 * There is no location and no network identifier in it, and it lasts minutes.
 */
public final class PresenceProof {

    private final String hubKeyFingerprint;
    private final String deviceKeyFingerprint;
    private final Instant issuedAt;
    private final Instant expiresAt;
    private final byte[] signature;

    private PresenceProof(String hubKeyFingerprint, String deviceKeyFingerprint, Instant issuedAt,
                          Instant expiresAt, byte[] signature) {
        this.hubKeyFingerprint = hubKeyFingerprint;
        this.deviceKeyFingerprint = deviceKeyFingerprint;
        this.issuedAt = issuedAt;
        this.expiresAt = expiresAt;
        this.signature = signature.clone();
    }

    static PresenceProof issue(Signer hubKey, String deviceKeyFingerprint, Instant issuedAt, Instant expiresAt) {
        String hubFp = hubKey.fingerprint();
        return new PresenceProof(hubFp, deviceKeyFingerprint, issuedAt, expiresAt,
                hubKey.sign(payload(hubFp, deviceKeyFingerprint, issuedAt, expiresAt)));
    }

    public static PresenceProof received(String hubKeyFingerprint, String deviceKeyFingerprint, Instant issuedAt,
                                         Instant expiresAt, byte[] signature) {
        return new PresenceProof(hubKeyFingerprint, deviceKeyFingerprint, issuedAt, expiresAt, signature);
    }

    private static byte[] payload(String hub, String device, Instant issuedAt, Instant expiresAt) {
        return Canonical.of("shalim.presence.v1").hex(hub).hex(device).instant(issuedAt).instant(expiresAt)
                .encode();
    }

    /** Signed by the named hub, for this device, and current. */
    public boolean verify(byte[] hubPublicKey, String deviceKeyFingerprint, Instant now) {
        return Fingerprints.matchesSigningKey(hubKeyFingerprint, hubPublicKey)
                && this.deviceKeyFingerprint.equals(deviceKeyFingerprint)
                && !now.isBefore(issuedAt) && now.isBefore(expiresAt)
                && Ed25519.verify(hubPublicKey, payload(hubKeyFingerprint, this.deviceKeyFingerprint, issuedAt,
                        expiresAt), signature);
    }

    /** What {@code Membership.presenceProofId} records. */
    public String proofId() {
        return Canonical.of("shalim.presence.id.v1").bytes(signature).digestHex();
    }

    public String getHubKeyFingerprint() {
        return hubKeyFingerprint;
    }

    public String getDeviceKeyFingerprint() {
        return deviceKeyFingerprint;
    }

    public Instant getIssuedAt() {
        return issuedAt;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public byte[] getSignature() {
        return signature.clone();
    }
}

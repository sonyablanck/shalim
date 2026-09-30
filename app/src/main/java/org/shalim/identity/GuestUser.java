package org.shalim.identity;

import java.time.Instant;

/**
 * An ephemeral, device-bound identity for someone using a hub's resources
 * without joining it — the walk-in at the library.
 *
 * <p>Created only on a device with an empty account slot. Someone who already
 * has a registered account walks in under that account, at GUEST role in the
 * hub; they do not get a second, guest identity, because that would be a
 * second account on one device. See {@link DeviceBinding}.
 *
 * <p>Guests can accrue skills but cannot query Matchmaker, and their access
 * lapses when they leave the hub's verified network. Keeping this a separate
 * class from {@link RegisteredUser} means guest limits cannot be lifted by a
 * role change alone.
 */
public class GuestUser extends User {

    /** Guest identities are disposable and expire by design. */
    private Instant expiresAt;

    /** The hub whose network vouched for this guest. */
    private String vouchingHubId;

    public GuestUser() {
        // TODO: pseudo-code
    }

    public GuestUser(String userId, String displayName, String vouchingHubId, Instant expiresAt) {
        // TODO: pseudo-code
    }

    @Override
    public boolean isProvisional() {
        // TODO: pseudo-code
        return true;
    }

    public boolean isExpired(Instant now) {
        // TODO: pseudo-code
        return false;
    }

    /**
     * Promotes to a durable identity, carrying earned skills across. Skill
     * credentials are bound to the guest key, so the upgrade re-binds each to
     * the new key with a signature from the old one.
     */
    public RegisteredUser upgrade(String newUserId) {
        // TODO: pseudo-code
        return null;
    }

    public String getVouchingHubId() {
        return vouchingHubId;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }
}

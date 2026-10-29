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
        super();
    }

    /** Someone else's guest identity, by fingerprint. */
    public GuestUser(String userId, String displayName, String vouchingHubId, Instant expiresAt) {
        super(userId, displayName);
        this.vouchingHubId = vouchingHubId;
        this.expiresAt = expiresAt;
    }

    /** This device's guest identity, from the key {@link DeviceBinding#bind} made. */
    public GuestUser(org.shalim.crypto.Signer accountKey, String displayName, String vouchingHubId,
                     Instant expiresAt) {
        super(accountKey, displayName);
        this.vouchingHubId = vouchingHubId;
        this.expiresAt = expiresAt;
    }

    @Override
    public boolean isProvisional() {
        return true;
    }

    /** Expired at or after {@link #expiresAt}. A guest with no expiry set is treated as expired. */
    public boolean isExpired(Instant now) {
        return expiresAt == null || !now.isBefore(expiresAt);
    }

    /**
     * Promotes to a durable identity, carrying earned skills across.
     *
     * <p>Implemented as {@link DeviceBinding#bind} describes it: the slot
     * moves from GUEST to REGISTERED and <em>keeps the same key</em>. The user
     * id therefore stays the same, and skill credentials bound to it need no
     * re-binding. The earlier note here, which re-bound credentials to a new
     * key with a signature from the old one, contradicted that and has been
     * dropped. The cost: a guest's earlier visits can be linked to the account
     * they become. Upgrading means the person chose to carry those skills
     * across, so that link is the point. Memberships, wallet and skill
     * profile copying is still pseudo-code, because those classes are.
     *
     * @param binding this device's binding, whose slot must hold this guest's key
     */
    public RegisteredUser upgrade(DeviceBinding binding, Instant now) {
        if (!canSign() || !userId.equals(binding.getAccountKeyFingerprint())) {
            return null;
        }
        org.shalim.crypto.Signer key = binding.bind(DeviceBinding.Slot.REGISTERED, now);
        if (key == null) {
            return null;
        }
        RegisteredUser upgraded = new RegisteredUser(key, displayName);
        // PSEUDO-CODE: upgraded.memberships = memberships; wallet; skillProfile
        return upgraded;
    }

    public String getVouchingHubId() {
        return vouchingHubId;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }
}

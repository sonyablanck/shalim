package org.shalim.identity;

/**
 * A person with a durable keypair held in the device keystore. Can hold any
 * {@link Role} in any hub, and retains membership across blackouts.
 *
 * <p>The keypair lives under {@link DeviceBinding#ACCOUNT_KEY_ALIAS}, the one
 * account slot a device has. Recovery shares restore it onto another device's
 * empty slot; they never add it alongside an existing account.
 */
public class RegisteredUser extends User {

    /** Backup material so a lost device does not mean a lost identity. */
    private boolean hasRecoveryShare;

    public RegisteredUser() {
        // TODO: pseudo-code
    }

    public RegisteredUser(String userId, String displayName) {
        // TODO: pseudo-code
    }

    @Override
    public boolean isProvisional() {
        // TODO: pseudo-code
        return false;
    }

    /** Splits recovery material so trusted peers can help restore the identity. */
    public boolean enrolRecoveryShares(int threshold, int shares) {
        // TODO: pseudo-code
        return false;
    }
}

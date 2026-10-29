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
        super();
    }

    /** Someone else's account, by fingerprint. */
    public RegisteredUser(String userId, String displayName) {
        super(userId, displayName);
    }

    /** This device's account, from the key {@link DeviceBinding#bind} made. */
    public RegisteredUser(org.shalim.crypto.Signer accountKey, String displayName) {
        super(accountKey, displayName);
    }

    @Override
    public boolean isProvisional() {
        return false;
    }

    /**
     * Splits recovery material so trusted peers can help restore the identity.
     *
     * <p>STILL PSEUDO-CODE, blocked on a design decision rather than on code.
     * {@link org.shalim.crypto.Shamir} is ready, but the account key is made
     * non-exportable in the hardware keystore ({@link DeviceBinding}), and a key
     * that cannot be exported cannot be split. The options are:
     * <ol>
     *   <li>Generate the account seed in software, split it, then import it.
     *       Recovery works, but the key is no longer provably hardware-born,
     *       which weakens the attestation that one-device-one-account rests on.</li>
     *   <li>Keep the key in hardware and recover the <em>identity</em> instead:
     *       shareholders co-sign a statement moving the old fingerprint to a
     *       new key. Every hub has to accept such moves.</li>
     * </ol>
     * See README open question 21.
     */
    public boolean enrolRecoveryShares(int threshold, int shares) {
        // PSEUDO-CODE (option 1 shown; option 2 needs protocol work)
        // seed = random 32 bytes
        // parts = Shamir.split(seed, threshold, shares)
        // FOR EACH part -> SealedBox.seal(shareholder encryption key, part, aad = (userId, index))
        // wipe seed
        return false;
    }
}

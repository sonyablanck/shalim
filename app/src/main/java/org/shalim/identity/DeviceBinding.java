package org.shalim.identity;

import java.time.Instant;
import java.util.List;

/**
 * The rule that one device holds at most one user account.
 *
 * <p>Exists to stop self-authentication. Without it, one person who admins
 * two hubs could keep a second account on the same phone, join each hub as an
 * ordinary member under the other account, and bond their own hubs together.
 * With it, a second account needs a second device. That does not stop someone
 * with several phones, or an organisation with many, but it makes the cheap
 * version of the attack cost hardware.
 *
 * <h2>What a device may hold</h2>
 * <ul>
 *   <li>At most one user account — a {@link RegisteredUser}, or a
 *       {@link GuestUser} that occupies the same slot until it upgrades or
 *       expires. A guest is not a second account; walking into a hub with a
 *       registered account means using that account at GUEST role there.</li>
 *   <li>Hub instances, at most one per network the device is attached to. A
 *       hub instance holds the hub's issuer key, not a user account, so an
 *       admin can keep their account on a phone and run their hub on a
 *       desktop, or both on one device. The one-per-network limit comes from
 *       {@code org.shalim.hub.NetworkClaimService}: a hub must answer claim
 *       queries on its own network, and no two hubs may claim one.</li>
 * </ul>
 *
 * <h2>How it is enforced</h2>
 *
 * <p>Locally, by the app: the account key is created in the device's hardware
 * keystore (StrongBox or TEE on Android, Secure Enclave on iOS) under a single
 * fixed alias, and the app refuses to create a second. Leaving an account
 * means destroying its key first.
 *
 * <p>Remotely, at join: when a device joins a hub as a member, its app
 * offers a <em>key attestation</em> for the account key if the platform
 * supports it. The target verifies the chain offline against bundled platform
 * roots — hardware-backed key, verified boot, genuine Shalim release, which is
 * the build that enforces one slot — and records only "attested" as a hidden
 * attribute of the member's {@link org.shalim.trust.MemberCredential}. It
 * carries no device identifier, so it cannot be used to recognise the same
 * phone across hubs.
 *
 * <p>This moved on 30 September 2026. Attestation used to be requested when
 * an admin set up authentication of another hub, which meant the attestation
 * named the prober to the target. Now every member who can attest does so,
 * routinely, at join; a prober later proves "attested" inside an anonymous
 * credential presentation. The cost: the platform dependency now touches
 * every member whose device offers attestation, not only probers. Members
 * whose devices cannot attest — custom ROMs, modified AGPL builds — are
 * members exactly as before, and simply cannot act as probers.
 */
public class DeviceBinding {

    /** Fixed keystore alias. One alias, one account. */
    public static final String ACCOUNT_KEY_ALIAS = "shalim.account.v1";

    public enum Slot {
        EMPTY,
        GUEST,
        REGISTERED
    }

    private Slot slot;

    /** Fingerprint of the key in the slot. Null when empty. */
    private String accountKeyFingerprint;

    /** Hub instances this device runs. Not accounts; one per attached network. */
    private List<String> hostedHubIssuerKeyFingerprints;

    private Instant boundAt;

    /** Where the account key lives. Not state: a handle to the platform keystore. */
    private final transient org.shalim.crypto.AccountKeyStore keyStore;

    /** Software keystore. For desktop development and tests. */
    public DeviceBinding() {
        this(new org.shalim.crypto.SoftwareAccountKeyStore());
    }

    public DeviceBinding(org.shalim.crypto.AccountKeyStore keyStore) {
        this.keyStore = keyStore;
        this.hostedHubIssuerKeyFingerprints = new java.util.ArrayList<>();
        org.shalim.crypto.Signer existing = keyStore.load(ACCOUNT_KEY_ALIAS).orElse(null);
        this.slot = existing == null ? Slot.EMPTY : Slot.REGISTERED;
        // A key surviving a restart is treated as REGISTERED until persistence
        // records the slot kind alongside it (stage 3). Guests are ephemeral, so
        // the conservative reading is the one that refuses a second account.
        this.accountKeyFingerprint = existing == null ? null : existing.fingerprint();
    }

    /**
     * Claims the device's one account slot and returns the key to build the
     * {@link User} from. The user id is that key's fingerprint, so the key is
     * made first and the user second.
     *
     * <ul>
     *   <li>EMPTY: a fresh key is generated under {@link #ACCOUNT_KEY_ALIAS}
     *       and the slot becomes {@code kind}.</li>
     *   <li>GUEST, asked for REGISTERED: the guest is upgraded in place, keeping
     *       its key, as {@link GuestUser#upgrade} requires.</li>
     *   <li>Anything else returns null. "Sign out and sign in as someone else"
     *       is not offered. Leaving means {@link #release()}, which destroys
     *       the key.</li>
     * </ul>
     */
    public org.shalim.crypto.Signer bind(Slot kind, Instant now) {
        if (kind == null || kind == Slot.EMPTY) {
            return null;
        }
        if (slot == Slot.EMPTY) {
            if (keyStore.contains(ACCOUNT_KEY_ALIAS)) {
                return null; // the store disagrees with our state; refuse rather than guess
            }
            org.shalim.crypto.Signer key = keyStore.generate(ACCOUNT_KEY_ALIAS);
            // PLATFORM: on Android, generate with setIsStrongBoxBacked where
            // available, non-exportable, and an attestation challenge, so that
            // attest() can later prove where the key was made.
            slot = kind;
            accountKeyFingerprint = key.fingerprint();
            boundAt = now;
            return key;
        }
        if (slot == Slot.GUEST && kind == Slot.REGISTERED) {
            org.shalim.crypto.Signer key = keyStore.load(ACCOUNT_KEY_ALIAS).orElse(null);
            if (key == null) {
                return null;
            }
            slot = Slot.REGISTERED;
            boundAt = now;
            return key;
        }
        return null;
    }

    /** The key in the slot, if there is one. */
    public java.util.Optional<org.shalim.crypto.Signer> accountKey() {
        return slot == Slot.EMPTY ? java.util.Optional.empty() : keyStore.load(ACCOUNT_KEY_ALIAS);
    }

    /**
     * Destroys the account key and empties the slot. Irreversible except via
     * the user's recovery shares, which restore the identity onto whichever
     * device's empty slot they are used on.
     */
    public void release() {
        keyStore.destroy(ACCOUNT_KEY_ALIAS);
        slot = Slot.EMPTY;
        accountKeyFingerprint = null;
        boundAt = null;
    }

    /**
     * Restores the slot kind recorded in the device store at the last run. Only
     * GUEST may be restored over the REGISTERED reading the constructor takes,
     * and only while the key is still there.
     */
    public boolean restoreSlot(Slot kind) {
        if (kind == Slot.GUEST && slot == Slot.REGISTERED && keyStore.contains(ACCOUNT_KEY_ALIAS)) {
            slot = Slot.GUEST;
            return true;
        }
        return kind == slot;
    }

    /** Whether the account key can produce a hardware key attestation at all. */
    public boolean canAttest() {
        return slot != Slot.EMPTY && keyStore.isHardwareBacked();
    }

    /**
     * Produces a key attestation for the account key over a verifier's
     * challenge. Offered at join to every hub, never at link setup.
     */
    public List<byte[]> attest(byte[] challenge) {
        // STILL PSEUDO-CODE: platform-specific, and only testable on real devices.
        // Android: KeyStore.getCertificateChain(ACCOUNT_KEY_ALIAS) after
        //          generating with setAttestationChallenge(challenge)
        // iOS:     App Attest (DCAppAttestService.attestKey)
        // A software key (canAttest() == false) has nothing to attest.
        return null;
    }

    /**
     * Verifies another device's attestation. Offline: checks the chain against
     * bundled platform roots, the challenge, hardware backing, verified boot,
     * and that the attesting app's signing certificate is a Shalim release key.
     */
    public static boolean verifyAttestation(List<byte[]> chain, byte[] challenge,
                                            String expectedKeyFingerprint,
                                            List<byte[]> platformRoots,
                                            List<byte[]> shalimReleaseCerts) {
        // STILL PSEUDO-CODE, and fails closed: always false until implemented.
        // Needs a DER parser for the Android KeyDescription extension
        // (OID 1.3.6.1.4.1.11129.2.1.17) and Apple's App Attest format, tested
        // against real device chains. Until then no member counts as attested,
        // so nobody can act as a prober. That is the safe failure.
        //
        // IF chain does not verify to a platform root -> false
        // IF attested key fingerprint != expectedKeyFingerprint -> false
        // IF challenge mismatch -> false
        // IF security level is SOFTWARE -> false
        // IF verified boot state != VERIFIED -> false
        // IF attesting app signing cert NOT IN shalimReleaseCerts -> false
        //    // Also excludes modified AGPL builds from acting as probers.
        //    // Deliberate: a modified build is exactly one that could skip the
        //    // one-slot check. They can still do everything else.
        // RETURN true
        //    // Revocation lists for attestation roots need a network. Checked
        //    // opportunistically when online, never required, so a blackout
        //    // does not stop authentication.
        return false;
    }

    public Slot getSlot() {
        return slot;
    }

    public String getAccountKeyFingerprint() {
        return accountKeyFingerprint;
    }

    public List<String> getHostedHubIssuerKeyFingerprints() {
        return hostedHubIssuerKeyFingerprints;
    }

    public Instant getBoundAt() {
        return boundAt;
    }
}

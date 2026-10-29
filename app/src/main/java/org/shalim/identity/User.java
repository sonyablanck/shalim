package org.shalim.identity;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * A person, independent of any hub. Identity is a locally generated keypair so
 * accounts work with no server and no personal data.
 *
 * <p>Role is <em>not</em> modelled by subclassing: the same person is commonly
 * an admin in one hub and a guest in another, and promotion must not require
 * replacing the object. Roles live on {@link Membership}.
 */
public abstract class User {

    /** Fingerprint of the user's signing key. The only stable identifier. */
    protected String userId;

    /** Chosen per-device, not verified, not required to be unique. */
    protected String displayName;

    protected Instant createdAt;

    /** One entry per hub this person belongs to. */
    protected List<Membership> memberships;

    /**
     * Whether the person has been age-assured, and how. Deliberately coarse:
     * see {@link AgeAssurance} for why we never store a date of birth.
     */
    protected AgeAssurance ageAssurance;

    /** Proofs of good standing this user holds. Device-local; never pooled by a hub. */
    protected org.shalim.attestation.AttestationWallet wallet;

    /**
     * The device slot this account occupies. One account per device; see
     * {@link DeviceBinding}.
     */
    protected DeviceBinding deviceBinding;

    /**
     * Skills this person has earned by using resources at any hub, each backed
     * by a credential. Held on the user's device and travels with them, so a
     * skill earned at the library can be matched on at the makerspace.
     */
    protected org.shalim.skills.SkillProfile skillProfile;

    /**
     * Handle to the account key in this device's keystore. Null for a record
     * of someone else, such as a roster entry, which can be verified against
     * but not signed with.
     */
    protected transient org.shalim.crypto.Signer accountKey;

    /** Public half of the account key, so anyone holding this record can verify. */
    protected byte[] accountPublicKey;

    protected User() {
        this.memberships = new java.util.ArrayList<>();
        this.createdAt = Instant.now();
    }

    /**
     * Someone else's account, known by fingerprint only. Cannot sign or
     * verify until {@link #withPublicKey} supplies the key.
     */
    protected User(String userId, String displayName) {
        this();
        this.userId = userId;
        this.displayName = displayName;
    }

    /**
     * This device's own account. The user id is the fingerprint of the
     * account key, so it can never be chosen, only derived.
     */
    protected User(org.shalim.crypto.Signer accountKey, String displayName) {
        this();
        this.accountKey = accountKey;
        this.accountPublicKey = accountKey.publicKey();
        this.userId = accountKey.fingerprint();
        this.displayName = displayName;
    }

    /** Distinguishes a full account from a device-bound guest. */
    public abstract boolean isProvisional();

    // --- memberships ------------------------------------------------------

    public Optional<Membership> membershipIn(String hubId) {
        // TODO: pseudo-code
        return Optional.empty();
    }

    public List<Membership> getMemberships() {
        // TODO: pseudo-code
        return memberships;
    }

    public Membership join(String hubId, Role initialRole) {
        // TODO: pseudo-code
        return null;
    }

    public boolean leave(String hubId) {
        // PSEUDO-CODE
        //
        // 1. membership = membershipIn(hubId); IF absent RETURN false
        // 2. remove membership from the list
        // 3. wallet.forgetIssuer(that hub's issuer fingerprint)
        //    // Earned skill credentials are NOT dropped. A skill earned at a hub
        //    // is the person's, and leaving the hub does not unlearn it.
        //       // Drops the proof the departed hub issued. If that hub was
        //       // flagged, the stale proof goes with it; if it was healthy,
        //       // the user simply re-proves elsewhere.
        // 4. FOR EACH remaining membership
        //       re-evaluate restrictions with discharge == LEAVE_ORIGIN_HUB
        //       // This is where leaving a flagged hub lifts the cap. The check
        //       // is local: the user's own device knows which hubs it is in,
        //       // so no other hub has to be told anything.
        // 5. RETURN true
        return false;
    }

    /**
     * Effective permission check, scoped to one hub. Combines the membership's
     * role, any active {@link Restriction}, and the hub's deployment policy.
     * This is the single seam every caller should use.
     */
    public boolean can(Permission permission, String hubId) {
        // PSEUDO-CODE
        // membership = membershipIn(hubId); IF absent RETURN false
        // RETURN membership.can(permission)
        //    // Membership.activeRestrictions() evaluates discharge conditions
        //    // against this user's current hub set, so a cap from a hub they
        //    // have left stops applying without anyone republishing anything.
        return false;
    }

    // --- keys -------------------------------------------------------------

    /** Signs with the account key. Only the device that holds the account can. */
    public byte[] sign(byte[] payload) {
        if (accountKey == null) {
            throw new IllegalStateException("no account key on this device for " + userId);
        }
        return accountKey.sign(payload);
    }

    /** Raw Ed25519 public key, or null when only the fingerprint is known. */
    public byte[] publicKey() {
        return accountPublicKey == null ? null : accountPublicKey.clone();
    }

    /**
     * Attaches a public key learnt later, such as at join. Refused unless it
     * is the key the user id names, so a record cannot be pointed at a key
     * someone else holds.
     */
    public boolean withPublicKey(byte[] rawPublicKey) {
        if (!org.shalim.crypto.Fingerprints.matchesSigningKey(userId, rawPublicKey)) {
            return false;
        }
        this.accountPublicKey = rawPublicKey.clone();
        return true;
    }

    /** Verifies a signature by this user. False when the key is not known. */
    public boolean verify(byte[] payload, byte[] signature) {
        return accountPublicKey != null
                && org.shalim.crypto.Ed25519.verify(accountPublicKey, payload, signature);
    }

    /** Whether this device holds the private half. */
    public boolean canSign() {
        return accountKey != null;
    }

    // --- accessors --------------------------------------------------------

    public String getUserId() {
        return userId;
    }

    public String getDisplayName() {
        return displayName;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public AgeAssurance getAgeAssurance() {
        return ageAssurance;
    }

    public org.shalim.attestation.AttestationWallet getWallet() {
        return wallet;
    }

    public org.shalim.skills.SkillProfile getSkillProfile() {
        return skillProfile;
    }
}

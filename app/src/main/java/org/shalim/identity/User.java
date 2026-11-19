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
        this.ageAssurance = new AgeAssurance();
        this.wallet = new org.shalim.attestation.AttestationWallet();
        this.skillProfile = new org.shalim.skills.SkillProfile();
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
        this.wallet = new org.shalim.attestation.AttestationWallet(userId);
        this.skillProfile = new org.shalim.skills.SkillProfile(userId);
    }

    /** Distinguishes a full account from a device-bound guest. */
    public abstract boolean isProvisional();

    // --- memberships ------------------------------------------------------

    public Optional<Membership> membershipIn(String hubId) {
        if (hubId == null) {
            return Optional.empty();
        }
        return memberships.stream().filter(m -> hubId.equals(m.getHubId())).findFirst();
    }

    public List<Membership> getMemberships() {
        return List.copyOf(memberships);
    }

    /** The hubs this person belongs to, as this device knows them. */
    public java.util.Set<String> hubIds() {
        java.util.Set<String> ids = new java.util.HashSet<>();
        for (Membership m : memberships) {
            ids.add(m.getHubId());
        }
        return ids;
    }

    /**
     * Records a membership on this device. The hub records its own copy in its
     * roster; see {@code HubAdministration.admit}. Joining twice returns the
     * existing membership unchanged.
     */
    public Membership join(String hubId, Role initialRole) {
        Optional<Membership> existing = membershipIn(hubId);
        if (existing.isPresent()) {
            return existing.get();
        }
        Membership m = new Membership(userId, hubId, initialRole);
        m.bindHubSet(this::hubIds);
        memberships.add(m);
        return m;
    }

    /** Adopts a membership record (from persistence or an upgrade), binding it to this user's hub set. */
    public void adopt(Membership membership) {
        if (membership != null && membershipIn(membership.getHubId()).isEmpty()) {
            membership.bindHubSet(this::hubIds);
            memberships.add(membership);
        }
    }

    /**
     * Leaves a hub on this device.
     *
     * @param hubIssuerKeyFingerprint the departed hub's issuer key, whose proofs
     *                                the wallet drops; null if unknown
     */
    public boolean leave(String hubId, String hubIssuerKeyFingerprint) {
        Optional<Membership> membership = membershipIn(hubId);
        if (membership.isEmpty()) {
            return false;
        }
        memberships.remove(membership.get());
        if (hubIssuerKeyFingerprint != null && wallet != null) {
            // Drops the proof the departed hub issued. If that hub was flagged,
            // the stale proof goes with it; if it was healthy, the user simply
            // re-proves elsewhere.
            wallet.forgetIssuer(hubIssuerKeyFingerprint);
        }
        // Earned skill credentials are NOT dropped. A skill earned at a hub is
        // the person's, and leaving the hub does not unlearn it.
        //
        // Restrictions with discharge LEAVE_ORIGIN_HUB on the remaining
        // memberships re-evaluate by themselves: activeRestrictions() reads
        // hubIds() each time. The check is local, so no other hub is told.
        return true;
    }

    public boolean leave(String hubId) {
        return leave(hubId, null);
    }

    /**
     * Effective permission check, scoped to one hub. Combines the membership's
     * role and any active {@link Restriction}. The hub-level standing cap is
     * applied hub-side ({@code Membership.can(permission, standing)}); this
     * device-side check reflects what the person may attempt.
     */
    public boolean can(Permission permission, String hubId) {
        return membershipIn(hubId).map(m -> m.can(permission)).orElse(false);
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

    public void setAgeAssurance(AgeAssurance assurance) {
        this.ageAssurance = assurance == null ? new AgeAssurance() : assurance;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    public void setDeviceBinding(DeviceBinding binding) {
        this.deviceBinding = binding;
    }

    public DeviceBinding getDeviceBinding() {
        return deviceBinding;
    }

    public org.shalim.skills.SkillProfile getSkillProfile() {
        return skillProfile;
    }
}

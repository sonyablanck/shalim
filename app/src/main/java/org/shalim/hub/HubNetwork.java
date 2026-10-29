package org.shalim.hub;

import java.time.Instant;

/**
 * The hub's local network — normally its Wi-Fi — and the rule that being on it
 * is what makes someone a guest.
 *
 * <p>Every hub has one, because the network is how a hub works at all when
 * there is no internet, and because it is the only membership test that needs
 * no identity. Walking into a library and joining its Wi-Fi is a claim that can
 * be checked by the building: you are either in it or you are not. That is a
 * weaker claim than a signed attestation and a much better one than a form,
 * and it is exactly the right strength for a guest.
 *
 * <p><strong>Presence is the credential, and presence expires.</strong> A guest
 * is someone currently on the network, not someone who was on it once. When the
 * proof lapses ({@code HubPolicy.guestPresenceTtlMinutes}) the privileges go
 * with it. The alternative — a lasting account issued to anyone who ever passed
 * through — would turn a public Wi-Fi into a permanent roster of strangers.
 *
 * <p><strong>What a guest gets is deliberately small.</strong>
 * {@code Permission} grants guests {@code EDIT_OWN_SKILLS},
 * {@code RECORD_RESOURCE_USE}, {@code VIEW_HUB_PROFILE} and
 * {@code VIEW_HUB_RESOURCES} — and not
 * {@code RUN_HUB_QUERY}, the permission guests never get. Anyone on the café
 * Wi-Fi can see what the hub is and earn skills from what it holds; nobody on the café
 * Wi-Fi can ask the hub who its members are. If joining a network granted
 * querying, the member list would be readable by anyone who sat outside with a
 * laptop, and every safety control downstream would be decoration.
 */
public class HubNetwork {

    /** How presence on the network is established. */
    public enum Attachment {
        /** Associated with the hub's Wi-Fi BSSID. The default and the common case. */
        WIFI,
        /** In Bluetooth range of a hub beacon. Weaker: range leaks past the walls. */
        BLUETOOTH_PROXIMITY,
        /** Scanned a code on the premises. For hubs whose Wi-Fi is not theirs to run. */
        PREMISES_CODE,
        /** An existing member vouched for someone present. Leaves a named trail. */
        MEMBER_VOUCHED
    }

    private String networkId;
    private String hubId;

    /** Human-readable network name. Advisory only — an SSID is trivially spoofed. */
    private String ssid;

    /**
     * Hash of the BSSID, salted per hub. Hashed because a stored BSSID is a
     * geolocatable identifier for the premises, and a device carrying a list of
     * hub BSSIDs is carrying a list of the buildings its owner has been in.
     */
    private String bssidHash;

    /**
     * Every access point in the hub's space, hashed the same way. A library
     * with five access points claims all five; the claim is per access point,
     * so another hub elsewhere in the building on other access points is
     * allowed.
     */
    private java.util.List<String> bssidHashes;

    /**
     * Whether the hub actually runs this network. False for a hub sitting on a
     * café's or a landlord's Wi-Fi, where anyone on it is not necessarily on the
     * premises and the presence claim is correspondingly weaker.
     */
    private boolean hubOperated;

    /**
     * Whether presence on this network grants guest privileges at all. A hub can
     * turn this off and admit by invitation only, and a hub whose Wi-Fi is
     * shared with an unrelated business probably should.
     */
    private boolean grantsGuestAccess;

    /** Set when the network is open. Guests over open Wi-Fi are treated as observable. */
    private boolean encrypted;

    private Instant lastSeenAt;

    /**
     * This hub's claim to the network. No other hub may be created on it; see
     * {@link NetworkClaimService}. Required for a viable hub.
     */
    private NetworkClaim claim;

    /** Set when another hub has answered for the same access point. */
    private boolean disputed;

    public HubNetwork() {
        this.networkId = org.shalim.crypto.Bytes.randomId();
        this.bssidHashes = new java.util.ArrayList<>();
    }

    public HubNetwork(String hubId, String ssid, String bssidHash) {
        this();
        this.hubId = hubId;
        this.ssid = ssid;
        this.bssidHash = bssidHash;
        if (bssidHash != null) {
            this.bssidHashes.add(bssidHash);
        }
    }

    /** A network with every access point in the hub's space, hashed with the hub's salt. */
    public HubNetwork(String hubId, String ssid, java.util.List<String> bssidHashes, boolean hubOperated,
                      boolean grantsGuestAccess, boolean encrypted) {
        this();
        this.hubId = hubId;
        this.ssid = ssid;
        this.bssidHashes = new java.util.ArrayList<>(bssidHashes);
        this.bssidHash = bssidHashes.isEmpty() ? null : bssidHashes.get(0);
        this.hubOperated = hubOperated;
        this.grantsGuestAccess = grantsGuestAccess;
        this.encrypted = encrypted;
    }

    // --- presence ---------------------------------------------------------

    /**
     * Whether a device is attached to this network, judged by the hub
     * instance from the access point the device reports and the hub's own salt.
     *
     * <p>Stage 2 settled who checks. The pseudo-code said "checked locally
     * against the device's own connection state", but the device cannot hash
     * a BSSID with the hub's salt, and must not be given it. The device-local
     * check is a claim query: the device asks the network with a fresh nonce,
     * and a verified {@link ClaimAnswer} from the hub's key for the access
     * point it is on <em>is</em> its proof of being attached
     * ({@code org.shalim.transport.ClaimQueryClient.confirmAttached}). Hub-side, this method answers the
     * same question for the presence proof the hub then issues. Third parties
     * still cannot ask the hub whether a person is here: there is no message
     * for it.
     *
     * <p>Only {@link Attachment#WIFI} is decided here. PREMISES_CODE goes
     * through {@link #isAttachedByCode}. BLUETOOTH_PROXIMITY needs a BLE
     * beacon, which is platform code (stage 7). MEMBER_VOUCHED needs signed
     * vouches, which belong to membership (stage 3). Both fail closed until
     * they are built.
     */
    public boolean isAttached(String bssidHashObserved, Attachment via) {
        if (!grantsGuestAccess || disputed) {
            // A walk-in gets guest access from neither of two disputing hubs.
            // Members are not guests and do not come through here.
            return false;
        }
        if (via != Attachment.WIFI || bssidHashObserved == null) {
            return false;
        }
        boolean found = false;
        for (String h : bssidHashes) {
            // BSSID, not SSID. Anyone can name their hotspot after the library.
            found |= org.shalim.crypto.Bytes.equalHex(h, bssidHashObserved);
        }
        return found;
    }

    /** Presence by a code shown on the premises. Spends the code. */
    public boolean isAttachedByCode(String code, PremisesCode codes, Instant now) {
        return grantsGuestAccess && !disputed && codes != null && codes.redeem(code, now);
    }

    /**
     * Issues a presence proof for a device on the network. Short-lived, bound to
     * the device key, and holding no location: it says "this key was on this
     * hub's network at this time", which is the least that will do the job.
     */
    public PresenceProof issuePresenceProof(String deviceKeyFingerprint, HubPolicy policy,
                                            org.shalim.crypto.Signer hubKey, Instant now) {
        return issuePresenceProof(deviceKeyFingerprint, policy.isAllowGuests(),
                policy.getGuestPresenceTtlMinutes(), hubKey, now);
    }

    /** As above, with the two policy values given directly. */
    public PresenceProof issuePresenceProof(String deviceKeyFingerprint, boolean allowGuests,
                                            int presenceTtlMinutes, org.shalim.crypto.Signer hubKey,
                                            Instant now) {
        if (!grantsGuestAccess || !allowGuests || disputed || presenceTtlMinutes <= 0) {
            return null;
        }
        // Deliberately minutes, not days. The privilege should not outlast the
        // visit, or the hub accumulates guests it has never met. The proof id
        // is recorded on the Membership as presenceProofId.
        lastSeenAt = now;
        return PresenceProof.issue(hubKey, deviceKeyFingerprint, now,
                now.plus(java.time.Duration.ofMinutes(presenceTtlMinutes)));
    }

    /**
     * Whether a lapsed proof may be silently renewed because the device is still
     * attached. True for a guest sitting in the building all afternoon; false
     * once they have left, which is the whole distinction.
     *
     * @param stillAttached from the hub's transport: the device has reached
     *                      the hub over this network within the presence window
     *                      ({@code SyncService.verifyPresence})
     */
    public boolean canRefresh(PresenceProof current, String deviceKeyFingerprint, boolean stillAttached) {
        return stillAttached && grantsGuestAccess && !disputed && current != null
                && deviceKeyFingerprint != null
                && deviceKeyFingerprint.equals(current.getDeviceKeyFingerprint());
    }

    /**
     * Whether this network is a strong enough presence claim to grant guest
     * privileges without anything else. False when the hub does not run the
     * network: a café's Wi-Fi reaches the street, the flat upstairs and the bus
     * stop, and "on the same Wi-Fi" then means considerably less than "here".
     */
    public boolean isTrustworthyPresenceSignal() {
        // On an open network anyone in range can associate, and association is
        // passively observable by everyone else on it.
        return hubOperated && encrypted && grantsGuestAccess;
    }

    /**
     * Whether traffic on this network reveals participation to whoever runs it.
     * True for any network the hub does not operate, and for any open network.
     * Feeds the same judgement {@code Transport.isObservable()} feeds: on an
     * observable network the hub does less, not the same thing more carefully.
     */
    public boolean isObservable() {
        return !hubOperated || !encrypted;
    }

    // --- claim ------------------------------------------------------------

    public void setClaim(NetworkClaim claim) {
        this.claim = claim;
    }

    /** Another hub answered for one of this hub's access points. */
    public void markDisputed() {
        this.disputed = true;
    }

    /** The other claimant stopped answering, or this hub migrated. */
    public void clearDispute() {
        this.disputed = false;
    }

    public java.util.List<String> getBssidHashes() {
        return java.util.List.copyOf(bssidHashes);
    }

    // --- accessors --------------------------------------------------------

    public String getNetworkId() {
        return networkId;
    }

    public String getHubId() {
        return hubId;
    }

    public String getSsid() {
        return ssid;
    }

    public boolean isHubOperated() {
        return hubOperated;
    }

    public boolean isGrantsGuestAccess() {
        return grantsGuestAccess;
    }

    public boolean isEncrypted() {
        return encrypted;
    }

    public Instant getLastSeenAt() {
        return lastSeenAt;
    }

    public NetworkClaim getClaim() {
        return claim;
    }

    public boolean isDisputed() {
        return disputed;
    }
}

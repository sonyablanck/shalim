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
        // TODO: pseudo-code
    }

    public HubNetwork(String hubId, String ssid, String bssidHash) {
        // TODO: pseudo-code
    }

    // --- presence ---------------------------------------------------------

    /**
     * Whether a device is on this network now. Checked locally against the
     * device's own connection state; the hub is never asked to confirm it,
     * because a hub that could be asked "is this person here?" is a hub that can
     * be asked to track attendance.
     */
    public boolean isAttached(String bssidHashObserved, Attachment via) {
        // PSEUDO-CODE
        // IF NOT grantsGuestAccess -> RETURN false
        // SWITCH via
        // IF disputed AND this device has not pinned this hub -> RETURN false
        //    // A walk-in gets guest access from neither of two disputing hubs.
        //    WIFI                -> RETURN bssidHashObserved IN bssidHashes
        //                           // BSSID, not SSID. Anyone can name their
        //                           // hotspot after the library.
        //    BLUETOOTH_PROXIMITY -> RETURN in range of a hub beacon
        //    PREMISES_CODE       -> RETURN code is current and unspent
        //    MEMBER_VOUCHED      -> RETURN a present member vouched, and is named
        return false;
    }

    /**
     * Issues a presence proof for a device on the network. Short-lived, bound to
     * the device key, and holding no location: it says "this key was on this
     * hub's network at this time", which is the least that will do the job.
     */
    public String issuePresenceProof(String deviceKeyFingerprint, HubPolicy policy, Instant now) {
        // PSEUDO-CODE
        //
        // 1. IF NOT grantsGuestAccess -> RETURN null
        // 2. IF NOT policy.allowGuests -> RETURN null
        // 3. proof valid for policy.guestPresenceTtlMinutes from now
        //    // Deliberately minutes, not days. The privilege should not outlast
        //    // the visit, or the hub accumulates guests it has never met.
        // 4. RETURN proof id, recorded on the Membership as presenceProofId
        return null;
    }

    /**
     * Whether a lapsed proof may be silently renewed because the device is still
     * attached. True for a guest sitting in the building all afternoon; false
     * once they have left, which is the whole distinction.
     */
    public boolean canRefresh(String deviceKeyFingerprint, Instant now) {
        // TODO: pseudo-code
        return false;
    }

    /**
     * Whether this network is a strong enough presence claim to grant guest
     * privileges without anything else. False when the hub does not run the
     * network: a café's Wi-Fi reaches the street, the flat upstairs and the bus
     * stop, and "on the same Wi-Fi" then means considerably less than "here".
     */
    public boolean isTrustworthyPresenceSignal() {
        // PSEUDO-CODE
        // RETURN hubOperated
        //    AND encrypted
        //        // On an open network anyone in range can associate, and
        //        // association is passively observable by everyone else on it.
        //    AND grantsGuestAccess
        return false;
    }

    /**
     * Whether traffic on this network reveals participation to whoever runs it.
     * True for any network the hub does not operate. Feeds the same judgement
     * {@code Transport.isObservable()} feeds: on an observable network the hub
     * does less, not the same thing more carefully.
     */
    public boolean isObservable() {
        // TODO: pseudo-code
        return false;
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

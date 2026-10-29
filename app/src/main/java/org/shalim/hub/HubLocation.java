package org.shalim.hub;

/**
 * The hub's physical premises — the only place Shalim will schedule a meeting,
 * and the thing a hub is found by.
 *
 * <p>Restricting meetings to a known, populated, third-party-observed location
 * is the main safeguarding control on first contact between members: it removes
 * the attacker's ability to choose the ground. It only works if the location is
 * genuinely public-ish, so hubs are asked to declare {@link #supervised} and
 * {@link #publiclyAccessible} honestly and members can see both before accepting.
 *
 * <p>Every hub has one of these. A hub with no premises cannot host a meeting,
 * cannot be found by anyone who is not already a member, and cannot offer the
 * Wi-Fi guest path — which is to say it is not really a hub, it is a chat room.
 * The address is therefore required, not optional.
 *
 * <p>That requirement has a cost, stated plainly: a searchable map of hubs is a
 * list of places where a community organises, and in a hostile setting that is
 * a target list. {@link Precision} exists so the cost is paid deliberately. A
 * library hub publishes its door number because it already has a sign outside;
 * a hub under surveillance publishes a district, or nothing, and accepts that
 * it can only be found by word of mouth. What a hub must never do is publish
 * more precision than its members have agreed to be found at.
 */
public class HubLocation {

    /** How precisely a hub consents to being findable by strangers. */
    public enum Precision {
        /** Full street address, shown on the map at the door. For premises with a sign outside already. */
        EXACT,
        /** Street or block only. Enough to find on arrival, not enough to stake out. */
        APPROXIMATE,
        /** District, neighbourhood or town. Enough to know a hub exists nearby. */
        AREA,
        /**
         * Not on the map at all. Found only by being told, or by walking into
         * the Wi-Fi. The correct setting under a hostile state, and the reason
         * the map is never the only way in.
         */
        UNLISTED
    }

    private String locationId;
    private String hubId;

    /** Human-readable address or description, e.g. "Peckham Library, 2nd floor". */
    private String label;

    /**
     * Postal address of the premises. Required — a hub without one cannot
     * schedule meetings — but only published at the precision below.
     */
    private String streetAddress;

    /** Coarse administrative area, e.g. "Southwark". Published at AREA and above. */
    private String locality;

    private String postalArea;
    private String countryCode;

    /** Optional coarse coordinates. Never precise enough to identify a home. */
    private Double approxLatitude;
    private Double approxLongitude;

    /**
     * How much of the above strangers see. Set by the hub's admins, disclosed to
     * members before they join, and never widened without telling them.
     */
    private Precision precision;

    /** Whether hub staff or volunteers are normally present. Shown before accepting. */
    private boolean supervised;

    /** Whether members of the public can freely enter. */
    private boolean publiclyAccessible;

    /** Free-text opening times. Meetings cannot be scheduled outside these. */
    private String openingHours;

    /** Named sub-areas within the premises, e.g. "study room 3". */
    private java.util.List<String> meetingSpaces;

    public HubLocation() {
        // TODO: pseudo-code
    }

    public HubLocation(String hubId, String label) {
        // TODO: pseudo-code
    }

    public HubLocation(String hubId, String label, String streetAddress, Precision precision) {
        // TODO: pseudo-code
    }

    /** Whether the premises are open at the proposed time. */
    public boolean isOpenAt(java.time.Instant when) {
        // TODO: pseudo-code
        return false;
    }

    /** Whether this location meets the policy's bar for hosting first meetings. */
    public boolean isSuitableForFirstMeeting(HubPolicy policy) {
        // TODO: pseudo-code
        return false;
    }

    // --- discovery --------------------------------------------------------

    /**
     * What a stranger searching the map is shown. Redacted to {@link #precision}
     * <em>here</em>, at the source, rather than by whatever is drawing the map —
     * a redaction applied by the display layer is one bug away from not being
     * applied at all, and the bug would publish addresses.
     */
    public String publicDescriptor() {
        // PSEUDO-CODE
        // SWITCH precision
        //    EXACT       -> label + streetAddress + locality
        //    APPROXIMATE -> label + street name only + locality
        //    AREA        -> label + locality
        //    UNLISTED    -> null    // not "hidden": absent. Callers must not
        //                           // render a pin with no detail, because a
        //                           // pin is itself the disclosure.
        return null;
    }

    /**
     * Coordinates for the map, fuzzed to {@link #precision}. Fuzzing is applied
     * to the stored value once and rounded, never jittered per call — a random
     * offset re-rolled on each request averages out to the true position for
     * anyone who asks enough times.
     */
    public Double[] mapPoint() {
        // TODO: pseudo-code
        return null;
    }

    /** Whether this hub appears in map search at all. */
    public boolean isListed() {
        // TODO: pseudo-code
        return false;
    }

    /**
     * Rough distance in metres, for "hubs near me". Computed on the searching
     * device against already-published points; no location ever leaves the
     * phone to ask a hub how far away it is.
     */
    public double approximateDistanceMetres(double latitude, double longitude) {
        // TODO: pseudo-code
        return 0;
    }

    /**
     * Whether a hub with this location may be created at all. Enforces the
     * invariant that every hub has premises: an address and a label, at some
     * precision, even if that precision is UNLISTED.
     */
    public boolean isComplete() {
        // PSEUDO-CODE
        // RETURN label non-blank
        //    AND streetAddress non-blank      // held even when UNLISTED, because
        //                                     // meetings still have to happen
        //                                     // somewhere and members are told
        //    AND precision != null
        return false;
    }

    // --- accessors --------------------------------------------------------

    public String getLocationId() {
        return locationId;
    }

    public String getHubId() {
        return hubId;
    }

    public String getLabel() {
        return label;
    }

    /** Members and admins only. Map search must call {@link #publicDescriptor()}. */
    public String getStreetAddress() {
        return streetAddress;
    }

    public String getLocality() {
        return locality;
    }

    public Precision getPrecision() {
        return precision;
    }

    public String getOpeningHours() {
        return openingHours;
    }

    public boolean isSupervised() {
        return supervised;
    }

    public boolean isPubliclyAccessible() {
        return publiclyAccessible;
    }

    public java.util.List<String> getMeetingSpaces() {
        return meetingSpaces;
    }
}

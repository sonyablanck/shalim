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

    /** Time zone the opening hours are in, e.g. "Europe/London". */
    private String zoneId;

    public HubLocation() {
        this.locationId = org.shalim.crypto.Bytes.randomId();
        this.meetingSpaces = new java.util.ArrayList<>();
        this.zoneId = "UTC";
    }

    public HubLocation(String hubId, String label) {
        this();
        this.hubId = hubId;
        this.label = label;
    }

    public HubLocation(String hubId, String label, String streetAddress, Precision precision) {
        this(hubId, label);
        this.streetAddress = streetAddress;
        this.precision = precision;
    }

    // --- opening hours ----------------------------------------------------

    /**
     * Whether the premises are open at the proposed time.
     *
     * <p>Opening hours were free text; meetings must not be scheduled outside
     * them, so they now have a small grammar:
     * {@code "Mon-Fri 09:00-17:00; Sat 10:00-14:00 18:00-20:00; Sun closed"}.
     * Days are Mon..Sun, a range ({@code Mon-Fri}) or {@code Daily}. A range
     * ending at or before it starts runs past midnight. Anything that does not
     * parse makes this return false: a hub whose hours cannot be read hosts no
     * meetings until an admin fixes them, rather than hosting them at 3 a.m.
     */
    public boolean isOpenAt(java.time.Instant when) {
        java.util.List<OpeningSlot> slots = OpeningSlot.parse(openingHours);
        if (slots == null || slots.isEmpty()) {
            return false;
        }
        java.time.ZonedDateTime local;
        try {
            local = when.atZone(java.time.ZoneId.of(zoneId));
        } catch (java.time.DateTimeException e) {
            return false;
        }
        for (OpeningSlot slot : slots) {
            if (slot.contains(local)) {
                return true;
            }
        }
        return false;
    }

    /** Whether {@link #openingHours} parses. Shown to admins when it does not. */
    public boolean hasValidOpeningHours() {
        java.util.List<OpeningSlot> slots = OpeningSlot.parse(openingHours);
        return slots != null && !slots.isEmpty();
    }

    /** One day-of-week range and one time range. */
    record OpeningSlot(java.time.DayOfWeek day, java.time.LocalTime from, java.time.LocalTime to) {

        boolean contains(java.time.ZonedDateTime t) {
            java.time.LocalTime time = t.toLocalTime();
            boolean overnight = !to.isAfter(from);
            if (!overnight) {
                return t.getDayOfWeek() == day && !time.isBefore(from) && time.isBefore(to);
            }
            // Opens on `day`, closes the next morning.
            return (t.getDayOfWeek() == day && !time.isBefore(from))
                    || (t.getDayOfWeek() == day.plus(1) && time.isBefore(to));
        }

        private static final java.util.Map<String, java.time.DayOfWeek> DAYS = java.util.Map.of(
                "mon", java.time.DayOfWeek.MONDAY, "tue", java.time.DayOfWeek.TUESDAY,
                "wed", java.time.DayOfWeek.WEDNESDAY, "thu", java.time.DayOfWeek.THURSDAY,
                "fri", java.time.DayOfWeek.FRIDAY, "sat", java.time.DayOfWeek.SATURDAY,
                "sun", java.time.DayOfWeek.SUNDAY);

        /** Null if anything fails to parse. */
        static java.util.List<OpeningSlot> parse(String text) {
            if (text == null || text.isBlank()) {
                return null;
            }
            java.util.List<OpeningSlot> out = new java.util.ArrayList<>();
            for (String clause : text.split(";")) {
                String[] parts = clause.trim().split("\\s+");
                if (parts.length < 2) {
                    return null;
                }
                java.util.List<java.time.DayOfWeek> days = days(parts[0].toLowerCase(java.util.Locale.ROOT));
                if (days == null) {
                    return null;
                }
                if (parts.length == 2 && parts[1].equalsIgnoreCase("closed")) {
                    continue;
                }
                for (int i = 1; i < parts.length; i++) {
                    String[] range = parts[i].split("-");
                    if (range.length != 2) {
                        return null;
                    }
                    try {
                        java.time.LocalTime from = java.time.LocalTime.parse(range[0]);
                        java.time.LocalTime to = range[1].equals("24:00") ? java.time.LocalTime.MIDNIGHT
                                : java.time.LocalTime.parse(range[1]);
                        if (from.equals(to)) {
                            return null;
                        }
                        for (java.time.DayOfWeek d : days) {
                            out.add(new OpeningSlot(d, from, to));
                        }
                    } catch (java.time.format.DateTimeParseException e) {
                        return null;
                    }
                }
            }
            return out;
        }

        private static java.util.List<java.time.DayOfWeek> days(String spec) {
            if (spec.equals("daily")) {
                return java.util.List.of(java.time.DayOfWeek.values());
            }
            String[] ends = spec.split("-");
            if (ends.length == 1) {
                java.time.DayOfWeek d = DAYS.get(ends[0]);
                return d == null ? null : java.util.List.of(d);
            }
            if (ends.length != 2 || !DAYS.containsKey(ends[0]) || !DAYS.containsKey(ends[1])) {
                return null;
            }
            java.util.List<java.time.DayOfWeek> out = new java.util.ArrayList<>();
            java.time.DayOfWeek d = DAYS.get(ends[0]);
            while (true) {
                out.add(d);
                if (d == DAYS.get(ends[1])) {
                    return out;
                }
                d = d.plus(1);
            }
        }
    }

    /**
     * Whether this location meets the policy's bar for hosting first meetings:
     * complete, with readable hours, and somewhere other people are. An
     * INSTITUTIONAL hub must be both supervised and open to the public.
     */
    public boolean isSuitableForFirstMeeting(HubPolicy policy) {
        if (!isComplete() || !hasValidOpeningHours()) {
            return false;
        }
        if (policy != null && policy.getPosture() == HubPolicy.Posture.INSTITUTIONAL) {
            return supervised && publiclyAccessible;
        }
        return supervised || publiclyAccessible;
    }

    // --- discovery --------------------------------------------------------

    /**
     * What a stranger searching the map is shown. Redacted to {@link #precision}
     * <em>here</em>, at the source, rather than by whatever is drawing the map —
     * a redaction applied by the display layer is one bug away from not being
     * applied at all, and the bug would publish addresses.
     */
    public String publicDescriptor() {
        if (precision == null || !isComplete()) {
            return null;
        }
        return switch (precision) {
            case EXACT -> join(label, streetAddress, locality);
            case APPROXIMATE -> join(label, streetNameOnly(streetAddress), locality);
            case AREA -> join(label, locality);
            // Not "hidden": absent. Callers must not render a pin with no
            // detail, because a pin is itself the disclosure.
            case UNLISTED -> null;
        };
    }

    /** First line of the address without its house number or flat. */
    static String streetNameOnly(String address) {
        if (address == null) {
            return null;
        }
        String[] lines = address.split(",");
        for (String line : lines) {
            String l = line.trim()
                    .replaceFirst("(?i)^(flat|apt|apartment|unit|suite)\\s*\\S+\\s*", "")
                    .replaceFirst("^[0-9]+[A-Za-z]?(\\s*[-/]\\s*[0-9]+[A-Za-z]?)?\\s+", "")
                    .trim();
            if (!l.isEmpty() && !l.matches(".*[0-9].*")) {
                return l;
            }
        }
        return null;
    }

    private static String join(String... parts) {
        StringBuilder b = new StringBuilder();
        for (String p : parts) {
            if (p != null && !p.isBlank()) {
                if (b.length() > 0) {
                    b.append(", ");
                }
                b.append(p.trim());
            }
        }
        return b.toString();
    }

    /**
     * Sets the coarse position, rounded once to the current precision and
     * stored rounded: about 11 m at EXACT, 110 m at APPROXIMATE, 1.1 km at
     * AREA, nothing at UNLISTED. Rounding is deterministic, so asking many
     * times reveals nothing more. Never jitter: a random offset re-rolled on
     * each request averages out to the true position.
     */
    public void setApproxPosition(double latitude, double longitude) {
        int places = decimalsFor(precision);
        if (places < 0) {
            this.approxLatitude = null;
            this.approxLongitude = null;
            return;
        }
        this.approxLatitude = round(latitude, places);
        this.approxLongitude = round(longitude, places);
    }

    /**
     * Changes precision. Narrowing re-rounds the stored position so the
     * finer value is gone from this device. Widening cannot recover precision
     * that was never stored; set the position again, and tell members first.
     */
    public void setPrecision(Precision precision) {
        this.precision = precision;
        if (approxLatitude != null) {
            setApproxPosition(approxLatitude, approxLongitude);
        }
    }

    private static int decimalsFor(Precision p) {
        if (p == null) {
            return -1;
        }
        return switch (p) {
            case EXACT -> 4;
            case APPROXIMATE -> 3;
            case AREA -> 2;
            case UNLISTED -> -1;
        };
    }

    private static double round(double v, int places) {
        return java.math.BigDecimal.valueOf(v).setScale(places, java.math.RoundingMode.HALF_EVEN).doubleValue();
    }

    /** Coordinates for the map, at precision. Null when unlisted or unset. */
    public Double[] mapPoint() {
        if (!isListed() || approxLatitude == null || approxLongitude == null) {
            return null;
        }
        int places = decimalsFor(precision);
        return new Double[] {round(approxLatitude, places), round(approxLongitude, places)};
    }

    /** Whether this hub appears in map search at all. */
    public boolean isListed() {
        return precision != null && precision != Precision.UNLISTED && isComplete();
    }

    /**
     * Rough distance in metres, for "hubs near me". Computed on the searching
     * device against already-published points; no location ever leaves the
     * phone to ask a hub how far away it is. Haversine, on a 6,371 km sphere.
     * Infinite when the hub publishes no point.
     */
    public double approximateDistanceMetres(double latitude, double longitude) {
        Double[] p = mapPoint();
        if (p == null) {
            return Double.POSITIVE_INFINITY;
        }
        return haversineMetres(latitude, longitude, p[0], p[1]);
    }

    /** Great-circle distance on a 6,371 km sphere. */
    public static double haversineMetres(double lat1, double lon1, double lat2, double lon2) {
        double r = 6_371_000;
        double dLat = Math.toRadians(lat2 - lat1);
        double dLon = Math.toRadians(lon2 - lon1);
        double a = Math.sin(dLat / 2) * Math.sin(dLat / 2)
                + Math.cos(Math.toRadians(lat1)) * Math.cos(Math.toRadians(lat2))
                * Math.sin(dLon / 2) * Math.sin(dLon / 2);
        return 2 * r * Math.asin(Math.min(1, Math.sqrt(a)));
    }

    /**
     * Whether a hub with this location may be created at all. Enforces the
     * invariant that every hub has premises: an address and a label, at some
     * precision, even if that precision is UNLISTED. The address is held even
     * when unlisted, because meetings still have to happen somewhere and
     * members are told.
     */
    public boolean isComplete() {
        return label != null && !label.isBlank()
                && streetAddress != null && !streetAddress.isBlank()
                && precision != null;
    }

    // --- setters ----------------------------------------------------------

    public void setLabel(String label) {
        this.label = label;
    }

    public void setStreetAddress(String streetAddress) {
        this.streetAddress = streetAddress;
    }

    public void setLocality(String locality) {
        this.locality = locality;
    }

    public void setPostalArea(String postalArea) {
        this.postalArea = postalArea;
    }

    public void setCountryCode(String countryCode) {
        this.countryCode = countryCode;
    }

    public void setSupervised(boolean supervised) {
        this.supervised = supervised;
    }

    public void setPubliclyAccessible(boolean publiclyAccessible) {
        this.publiclyAccessible = publiclyAccessible;
    }

    public void setOpeningHours(String openingHours, String zoneId) {
        this.openingHours = openingHours;
        this.zoneId = zoneId == null ? "UTC" : zoneId;
    }

    public void setMeetingSpaces(java.util.List<String> spaces) {
        this.meetingSpaces = new java.util.ArrayList<>(spaces);
    }

    public String getZoneId() {
        return zoneId;
    }

    public String getPostalArea() {
        return postalArea;
    }

    public String getCountryCode() {
        return countryCode;
    }

    public Double getApproxLatitude() {
        return approxLatitude;
    }

    public Double getApproxLongitude() {
        return approxLongitude;
    }

    /** Restores persisted state. Persistence only. */
    public static HubLocation restore(String locationId, String hubId, String label, String streetAddress,
                                      String locality, String postalArea, String countryCode, Double lat,
                                      Double lon, Precision precision, boolean supervised,
                                      boolean publiclyAccessible, String openingHours, String zoneId,
                                      java.util.List<String> spaces) {
        HubLocation l = new HubLocation(hubId, label, streetAddress, precision);
        l.locationId = locationId;
        l.locality = locality;
        l.postalArea = postalArea;
        l.countryCode = countryCode;
        l.approxLatitude = lat;
        l.approxLongitude = lon;
        l.supervised = supervised;
        l.publiclyAccessible = publiclyAccessible;
        l.openingHours = openingHours;
        l.zoneId = zoneId;
        l.meetingSpaces = new java.util.ArrayList<>(spaces);
        return l;
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
        return java.util.List.copyOf(meetingSpaces);
    }
}

package org.shalim.discovery;

import java.util.List;

/**
 * What a stranger sees about one hub on the discovery page: roughly where it
 * is, roughly what it does, and how to turn up.
 *
 * <p>This is the only surface in Shalim visible to someone with no membership
 * anywhere, which makes it the one place where a leak needs no account, no
 * query and no permission to exploit. Everything here is therefore built by
 * subtraction: the card starts from what a hub already displays on a poster in
 * its own window, and nothing is added unless it survives the question "what
 * does this tell someone hunting this community?"
 *
 * <p>What a card holds: a name, a public descriptor from
 * {@link org.shalim.hub.HubLocation#publicDescriptor()}, a fuzzed map point, an
 * approximate distance, opening hours, whether the premises are supervised and
 * publicly accessible, up to five {@link SkillTheme}s (hub skills, derived
 * from resources), and anonymised {@link org.shalim.trust.BondProof}s that let
 * search count the hub's mutual authentications.
 *
 * <p>What a card never holds, and what no future field may reintroduce:
 * <ul>
 *   <li><strong>Member count.</strong> A small hub is a vulnerable hub, and a
 *       number that tells you which hubs are small is a targeting aid. It also
 *       makes hubs compete on size when they should compete on usefulness.</li>
 *   <li><strong>Any member, or anything attributable to one.</strong> No names,
 *       no ids, no user skills — themes are hub skills only. There is no member directory,
 *       and a discovery page that leaks one by inference is a directory.</li>
 *   <li><strong>Activity signals.</strong> Last seen, query volume, whether the
 *       hub is "busy" — all of them say whether a community is currently
 *       meeting, which is exactly what someone planning a raid wants.</li>
 *   <li><strong>Who authenticates whom.</strong> Bond proofs show <em>how
 *       many</em> listed hubs are mutually authenticated with this one, never
 *       which. No audit results, no revocations, no standing. This is a
 *       narrowing of an earlier rule that put no trust state on the card at
 *       all; the count is now required for search, and the README records
 *       what it leaks.</li>
 *   <li><strong>Exact coordinates.</strong> Only what the hub's declared
 *       {@link org.shalim.hub.HubLocation.Precision} permits.</li>
 * </ul>
 */
public class HubCard {

    /** Themes shown per card. Five, per the design; fewer when the floor bites. */
    public static final int MAX_THEMES = 5;

    private String hubId;
    private String name;

    /** One line about the hub, written by its admins and screened at HUB_PROFILE. */
    private String description;

    /** Redacted at source by {@link org.shalim.hub.HubLocation#publicDescriptor()}. */
    private String locationDescriptor;

    /** Fuzzed to the hub's declared precision. Null for an unlisted hub. */
    private Double mapLatitude;
    private Double mapLongitude;

    /**
     * Metres from the searcher, computed on the searcher's own device. Rounded
     * hard — see {@link HubDirectory#search} — because a precise distance from
     * a known point is a coordinate, and three of them are an address.
     */
    private int approximateDistanceMetres;

    private String openingHours;

    private boolean supervised;
    private boolean publiclyAccessible;

    /** Up to {@link #MAX_THEMES}, each already past {@link SkillTheme#isPublishable()}. */
    private List<SkillTheme> themes;

    /** Hub's issuer key fingerprint; what bond proofs and the ring refer to. */
    private String issuerKeyFingerprint;

    /** Anonymised proofs of current mutual authentications. */
    private List<org.shalim.trust.BondProof> bondProofs;

    /**
     * Whether walk-ins can get guest access by joining the hub's network. The
     * single most useful thing on the card: it is the answer to "can I just
     * turn up?", and turning up is how someone joins without identifying
     * themselves to anything.
     */
    private boolean acceptsWalkIns;

    /**
     * Whether this card was built without a model — themes fall back to
     * keyword clustering, which is cruder and clusters worse. Marked so nobody
     * reads a thin card as a thin hub, in keeping with the rest of the design.
     */
    private boolean degraded;

    public HubCard() {
        // TODO: pseudo-code
    }

    public HubCard(String hubId, String name, String locationDescriptor) {
        // TODO: pseudo-code
    }

    /**
     * Whether this card is safe to render. Fails closed on every count: a card
     * that cannot be built correctly is omitted from results rather than shown
     * with gaps, because a partially-redacted card invites the reader to guess
     * at the rest.
     */
    public boolean isRenderable() {
        // PSEUDO-CODE
        // RETURN name non-blank
        //    AND locationDescriptor != null      // null means UNLISTED: not on the map
        //    AND description screened at HUB_PROFILE
        //    AND themes ALL satisfy isPublishable()
        //        // Not "filter the bad ones out" — if a theme that should not
        //        // be here got this far, the pipeline that built the card is
        //        // wrong and the rest of it should not be trusted either.
        return false;
    }

    /**
     * Mutual authentications this device can verify, counted on-device against
     * the ring of cards it holds. Distinct {@code linkTag}s only, so one peer
     * cannot be counted twice. May differ between devices holding different
     * card sets; that is accepted rather than resolved by asking anyone.
     */
    public int verifiedBondCount(List<byte[]> ringIssuerKeys, java.time.Instant now) {
        // PSEUDO-CODE
        // valid = bondProofs WHERE subject == issuerKeyFingerprint
        //                     AND verify(ringIssuerKeys, now)
        // RETURN count of distinct linkTag IN valid
        return 0;
    }

    /**
     * How to approach this hub, in the order the design prefers. Walk-in first,
     * deliberately: it is the only route that requires no account, no
     * attestation and no disclosure to anyone, and a discovery page that pushed
     * people toward registering first would undo that.
     */
    public List<String> waysIn() {
        // PSEUDO-CODE
        // IF acceptsWalkIns
        //    "Turn up during opening hours and join the hub's Wi-Fi"
        //       // Guest privileges from presence alone. No identity required,
        //       // and it lapses when they leave.
        // "Ask a member to invite you"
        // // Never a contact address, phone number or e-mail. Those are the
        // // off-app channels the rest of the design works to avoid, and a
        // // public page listing them for every hub would be a directory of
        // // organisers' contact details.
        return null;
    }

    // --- accessors --------------------------------------------------------

    public String getHubId() {
        return hubId;
    }

    public String getName() {
        return name;
    }

    public String getDescription() {
        return description;
    }

    public String getLocationDescriptor() {
        return locationDescriptor;
    }

    public Double getMapLatitude() {
        return mapLatitude;
    }

    public Double getMapLongitude() {
        return mapLongitude;
    }

    public int getApproximateDistanceMetres() {
        return approximateDistanceMetres;
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

    public List<SkillTheme> getThemes() {
        return themes;
    }

    public boolean isAcceptsWalkIns() {
        return acceptsWalkIns;
    }

    public boolean isDegraded() {
        return degraded;
    }

    public String getIssuerKeyFingerprint() {
        return issuerKeyFingerprint;
    }

    public List<org.shalim.trust.BondProof> getBondProofs() {
        return bondProofs;
    }
}

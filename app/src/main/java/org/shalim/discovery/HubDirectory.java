package org.shalim.discovery;

import java.time.Instant;
import java.util.List;

/**
 * The discovery landing page: hubs near you, and roughly what each one is for.
 *
 * <p>This is the front door. Someone who has never heard of Shalim opens it,
 * sees that there is a makerspace twenty minutes away that does bike repair and
 * a library down the road with a seed collection, and can walk into either
 * without telling anyone anything. That is the point of the whole application,
 * and it is worth stating plainly that a hub nobody can find is a hub that
 * helps nobody.
 *
 * <h2>Two things are exposed here, and they belong to different people</h2>
 *
 * <p><strong>The hubs' location</strong>, which each hub controls through
 * {@link org.shalim.hub.HubLocation.Precision} and which is redacted at source.
 * A hub that does not want to be found sets {@code UNLISTED} and does not
 * appear. This is a community's decision about itself, taken by its admins and
 * disclosed to its members.
 *
 * <p><strong>The searcher's location</strong>, which is nobody's decision but
 * theirs, and which they have not consented to sharing with anyone merely by
 * wondering what is nearby. This is the more dangerous of the two and the
 * easier to leak, because a conventional implementation leaks it by default:
 * send coordinates to a service, receive nearby results. Shalim cannot do that.
 * There is no service to send them to, and if there were, the request log would
 * be a record of who was looking for a mutual aid group and from where.
 *
 * <p>So the search runs entirely on the searcher's device, against hub cards
 * already replicated by ordinary sync. No coordinate leaves the phone.
 * {@link #search} takes a latitude and longitude and returns cards; it makes no
 * network call, and it cannot, because the class has no transport. A hub is
 * never told it was found, never told who was looking, and never told anyone
 * searched at all.
 *
 * <h2>What is still leaked, and to whom</h2>
 *
 * <p>The device holds a set of hub cards, which is a list of communities in the
 * area. On a seized phone that is a real disclosure, and pretending otherwise
 * would be dishonest — but it is the same list anyone could assemble by walking
 * around, and it says nothing about which of them the owner uses. Cards are
 * pruned on the log's retention schedule and cleared by the panic wipe for that
 * reason.
 */
public class HubDirectory {

    /**
     * Default search radius. Ten kilometres is a deliberate compromise: far
     * enough to reach the next town on a bike, close enough that the results
     * are places someone might actually turn up to, and the whole design rests
     * on turning up.
     */
    public static final int DEFAULT_RADIUS_METRES = 10_000;

    /**
     * Hardest cap on the radius. A search of the whole country is not
     * discovery, it is enumeration — and a device holding every hub in Britain
     * is a national map of organising, which is worth seizing a phone for.
     */
    public static final int MAX_RADIUS_METRES = 25_000;

    /**
     * Distances are rounded to this before display. An unrounded distance from
     * a known point is a circle; three of them intersect at an address, and the
     * searcher would be handing that to anyone who saw their screen.
     */
    public static final int DISTANCE_ROUNDING_METRES = 500;

    /**
     * Minimum mutual authentications a hub needs to appear, as chosen by the
     * searcher. Default {@link org.shalim.trust.WebOfTrust#DEFAULT_SEARCH_BONDS}
     * (2); may be set from 1 to 5. Never 0: a hub nobody has checked, including
     * one that checks others but is not checked back, does not appear in search
     * at any setting. It can still be reached by a link or a code on a poster
     * via {@link #cardFor}.
     */
    private int minBonds;

    /** Cards replicated by ordinary sync. Never fetched in response to a search. */
    private List<HubCard> cards;

    /** Cards past this are shown as possibly out of date, not silently trusted. */
    private int cardRetentionDays;

    public HubDirectory() {
        // TODO: pseudo-code
    }

    public HubDirectory(List<HubCard> cards) {
        // TODO: pseudo-code
    }

    // --- searching --------------------------------------------------------

    /**
     * Hubs within {@code radiusMetres}, nearest first. Runs on-device against
     * already-held cards; sends nothing, and could not send anything, because
     * nothing here holds a transport.
     */
    public List<HubCard> search(double latitude, double longitude, int radiusMetres, Instant now) {
        // PSEUDO-CODE
        //
        // 0. CLAMP THE BOND THRESHOLD
        //    minBonds = clamp(minBonds, WebOfTrust.MIN_SEARCH_BONDS,
        //                               WebOfTrust.MAX_SEARCH_BONDS)
        //       // Clamped, like the radius. 0 is not reachable from any setting.
        //
        // 1. CLAMP THE RADIUS
        //    radiusMetres = min(radiusMetres, MAX_RADIUS_METRES)
        //       // Clamped rather than refused: someone who asks for 200km gets
        //       // 25km of results, not an error telling them the app is broken.
        //
        // 2. FILTER TO LISTED HUBS
        //    candidates = cards WHERE the hub is listed and isRenderable()
        //       // Unlisted hubs have no map point and never reach here. There
        //       // is no "show hidden hubs" option and must not be one.
        //
        // 2a. FILTER TO AUTHENTICATED HUBS
        //    ring = issuer keys of all listed cards this device holds
        //    candidates = candidates WHERE verifiedBondCount(ring, now) >= minBonds
        //       // Verified here, on-device, against cards already held. No hub
        //       // is asked. A hub filtered out is shown nothing and told nothing.
        //
        // 3. MEASURE LOCALLY
        //    FOR EACH candidate
        //       distance = haversine(searcher point, card's already-fuzzed point)
        //          // Measured against the fuzzed point, not a real one — the
        //          // device does not hold a real one. So distances are already
        //          // approximate before rounding, which is the intended
        //          // accumulation of error rather than a compounding bug.
        //    DROP candidates beyond radiusMetres
        //
        // 4. ROUND BEFORE ANYTHING ELSE SEES IT
        //    card.approximateDistanceMetres = round to DISTANCE_ROUNDING_METRES
        //       // Rounded here, not at display. A precise value that exists
        //       // anywhere in memory is a precise value that ends up in a log
        //       // line, a crash report or a screenshot.
        //
        // 5. SORT AND CAP
        //    sort by rounded distance, then by name for stable ties
        //       // Ties broken by name, never by member count or activity —
        //       // ranking by size would make the busiest hubs the most visible
        //       // and the smallest ones invisible, and small hubs are the ones
        //       // that need walk-ins most.
        //    cap the result set
        //
        // 6. MARK STALE CARDS
        //    FOR EACH card older than cardRetentionDays -> mark possibly out of
        //    date rather than dropping it
        //       // A hub that has not synced in a fortnight is usually a hub in
        //       // a blackout, which is exactly when someone needs to know it is
        //       // there and where its door is.
        //
        // 7. RETURN cards
        //    // No network call has been made and no coordinate has left this
        //    // device. Nothing is logged: a local history of what someone
        //    // searched for is the same disclosure as a remote one, minus the
        //    // subpoena.
        return null;
    }

    /**
     * Free-text search over hub skills, e.g. "bike repair". Matches only the
     * published themes on cards already held — never a hub's member index,
     * which is not this device's to read.
     */
    public List<HubCard> searchByTheme(String terms, double latitude, double longitude, Instant now) {
        // PSEUDO-CODE
        // results = search(latitude, longitude, DEFAULT_RADIUS_METRES, now)
        //    // Same bond threshold, same rounding.
        // RETURN results WHERE any theme label or taxonomyTerm matches terms
        //    // Hub skills only. User skills are never on a card to match.
        return null;
    }

    /** Sets the searcher's bond threshold. Clamped to 1..5. */
    public void setMinBonds(int minBonds) {
        // PSEUDO-CODE
        // this.minBonds = clamp(minBonds, 1, 5)
    }

    public int getMinBonds() {
        return minBonds;
    }

    /**
     * One card by hub id, for opening a hub from a link or a code on a poster.
     * Not filtered by bonds: someone handed a poster has already been told the
     * hub exists, and a new hub has to be reachable somehow while it has no
     * bonds. The card is shown with a plain note that no other hub has
     * checked it yet.
     */
    public HubCard cardFor(String hubId) {
        // TODO: pseudo-code
        return null;
    }

    // --- maintenance ------------------------------------------------------

    /**
     * Accepts a card learned during sync. Cards travel as ordinary replicated
     * data and are not requested per-search, so holding one implies nothing
     * about interest in that hub.
     */
    public boolean accept(HubCard card, Instant now) {
        // PSEUDO-CODE
        // IF NOT card.isRenderable() -> RETURN false
        //    // Fails closed. A malformed card from a peer is dropped, not
        //    // repaired: a card is a hub's own statement about itself, and
        //    // filling in gaps on its behalf would publish something it did
        //    // not say.
        // replace any existing card for the same hubId
        // RETURN true
        return false;
    }

    /** Drops cards past retention. Expected to run, not optional. */
    public int prune(org.shalim.hub.HubPolicy policy, Instant now) {
        // TODO: pseudo-code
        return 0;
    }

    /**
     * Clears every card. Called by the duress path: a list of nearby
     * communities on a seized phone is a list of places worth visiting.
     */
    public void wipe() {
        // TODO: pseudo-code
    }

    // --- accessors --------------------------------------------------------

    public List<HubCard> getCards() {
        return cards;
    }

    public int getCardRetentionDays() {
        return cardRetentionDays;
    }
}

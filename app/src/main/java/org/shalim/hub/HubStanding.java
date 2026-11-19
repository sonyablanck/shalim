package org.shalim.hub;

import java.time.Instant;
import org.shalim.identity.Membership;
import org.shalim.identity.Role;

/**
 * Whether a hub is authenticated enough for its members to use QwenMatchmaker.
 * Observed state, like {@link CensorIntegrity}: computed by
 * {@code WebOfTrust.standing}, held here as plain data, read by
 * {@link QueryService} and {@link Membership}.
 *
 * <h2>The rule</h2>
 *
 * <p>A newly created hub authenticates nobody and is authenticated by nobody.
 * Until that changes, every member except its admins is capped at
 * {@link Role#GUEST}: they can use resources and earn skills, but cannot query
 * the Matchmaker or request meetings. Admins keep their role so they can set
 * up authentication. The hub leaves this state when an admin sets up an
 * authentication relationship with a hub they are a member of, and that
 * relationship passes its first window.
 *
 * <p>Which direction counts is {@link HubPolicy.UnlockBasis}. The requested
 * rule is {@link HubPolicy.UnlockBasis#ANY_DIRECTION}: this hub authenticating
 * a peer is enough. The README recommends
 * {@link HubPolicy.UnlockBasis#INBOUND_REQUIRED}, because an outbound link is
 * evidence about the <em>peer's</em> censor, not this hub's.
 *
 * <h2>Provisional status (decided 18 and 19 November 2026)</h2>
 *
 * <p>A hub with no certified peer within 20 miles is {@link State#PROVISIONAL}:
 * its members can query, it is shown as "not yet checked by another hub", it
 * issues no portable credentials, and it is not listed beyond its own area.
 * It ends at the earlier of 90 days from creation and 30 days from first
 * learning of a certified peer within 20 miles; the hub then falls to
 * guest-only until it gains an inbound link. A hub whose only inbound links
 * are all revoked is provisional for 30 days from the revocation. See
 * {@link ProvisionalStatus}, which members' devices also run, so a hub cannot
 * stay provisional by ignoring its neighbours.
 *
 * <h2>Failing open after unlock</h2>
 *
 * <p>Once unlocked, a hub re-locks only when every inbound link has been
 * positively <em>revoked</em>. Links going dormant — no probes getting
 * through, which is what a blackout looks like — never re-lock it. Otherwise
 * a hub's members would lose the Matchmaker exactly when the network is down
 * and the hub matters most, which is the failure the rest of the design
 * refuses.
 */
public class HubStanding {

    public enum State {
        /** Never unlocked. Non-admins capped at GUEST. */
        UNAUTHENTICATED,
        /** Unlocked. No cap. */
        AUTHENTICATED,
        /**
         * Not yet checked, but within its provisional period: no cap, shown as
         * "not yet checked by another hub", no portable credentials, not listed
         * beyond its own area. Ends at {@link #getProvisionalUntil()}.
         */
        PROVISIONAL,
        /**
         * Was unlocked; every inbound link has since been revoked on evidence.
         * Non-admins capped at GUEST again. Shown to admins with the evidence
         * route; shown to members only as "this hub is re-establishing
         * authentication".
         */
        REVOKED
    }

    private State state;
    private int outboundCounting;
    private int inboundCounting;
    private int bonds;
    private Instant everUnlockedAt;
    private Instant computedAt;
    private Instant provisionalUntil;

    private static final String UNAUTHENTICATED_TEXT = "This hub is new and hasn't been checked by another hub yet."
            + " Until it is, you can use its resources and earn skills, but not search for people.";
    private static final String PROVISIONAL_TEXT = "This hub hasn't been checked by another hub yet.";
    private static final String REVOKED_TEXT = "This hub is re-establishing its checks with other hubs."
            + " Until it does, you can use its resources and earn skills, but not search for people.";

    /** A new hub: never unlocked. */
    public HubStanding() {
        this.state = State.UNAUTHENTICATED;
        this.computedAt = Instant.now();
    }

    /** The derivation without provisional status: a hub with no clock is never provisional. */
    public static HubStanding compute(int outboundCounting, int inboundCounting, int bonds,
                                      Instant everUnlockedAt, boolean allInboundRevoked,
                                      HubPolicy.UnlockBasis basis, Instant now) {
        return compute(outboundCounting, inboundCounting, bonds, everUnlockedAt, allInboundRevoked, basis, null, now);
    }

    /** The derivation. Pure function of link counts, history, the provisional clock and policy. */
    public static HubStanding compute(int outboundCounting, int inboundCounting, int bonds,
                                      Instant everUnlockedAt, boolean allInboundRevoked,
                                      HubPolicy.UnlockBasis basis, ProvisionalStatus provisional, Instant now) {
        HubPolicy.UnlockBasis b = basis == null ? HubPolicy.UnlockBasis.INBOUND_REQUIRED : basis;
        boolean qualifies = b == HubPolicy.UnlockBasis.ANY_DIRECTION
                ? outboundCounting + inboundCounting >= 1
                : inboundCounting >= 1;
        HubStanding s = new HubStanding();
        s.outboundCounting = outboundCounting;
        s.inboundCounting = inboundCounting;
        s.bonds = bonds;
        s.computedAt = now;
        s.everUnlockedAt = everUnlockedAt;
        if (qualifies) {
            s.state = State.AUTHENTICATED;
            if (s.everUnlockedAt == null) {
                s.everUnlockedAt = now;
            }
        } else if (everUnlockedAt == null) {
            Instant until = provisional == null ? null : provisional.deadline(false);
            if (until != null && now.isBefore(until)) {
                s.state = State.PROVISIONAL;
                s.provisionalUntil = until;
            } else {
                s.state = State.UNAUTHENTICATED;
            }
        } else if (allInboundRevoked) {
            // Decided 18 November 2026: losing the only inbound link to
            // revocation makes a hub provisional for 30 days, so no single
            // peer can silence it, while a broken hub still loses access.
            Instant until = provisional == null ? null : provisional.deadline(true);
            if (until != null && now.isBefore(until)) {
                s.state = State.PROVISIONAL;
                s.provisionalUntil = until;
            } else {
                s.state = State.REVOKED;
            }
        } else {
            // Unlocked before and nothing revoked: links are merely dormant or
            // expired. Fail open.
            s.state = State.AUTHENTICATED;
        }
        return s;
    }

    /** The cap this standing puts on one membership. Null = no cap. */
    public Role roleCapFor(Membership membership) {
        if (state == State.AUTHENTICATED || state == State.PROVISIONAL) {
            return null;
        }
        if (membership != null && membership.getRole() == Role.ADMIN) {
            return null; // Admins must be able to fix it.
        }
        return Role.GUEST;
    }

    /**
     * Plain-language explanation for a capped member. Deliberately never says
     * "revoked": members are not told another hub found fault, only that the
     * hub is not currently checked.
     */
    public String explain() {
        return switch (state) {
            case AUTHENTICATED -> null;
            case UNAUTHENTICATED -> UNAUTHENTICATED_TEXT;
            case PROVISIONAL -> PROVISIONAL_TEXT;
            case REVOKED -> REVOKED_TEXT;
        };
    }

    /** What a member is told when a hub has never computed its standing. */
    public static String unauthenticatedExplanation() {
        return UNAUTHENTICATED_TEXT;
    }

    /** Restores persisted state. Persistence only. */
    public static HubStanding restore(State state, int outbound, int inbound, int bonds, Instant everUnlockedAt,
                                      Instant computedAt) {
        return restore(state, outbound, inbound, bonds, everUnlockedAt, computedAt, null);
    }

    /** Restores persisted state, with the provisional deadline. Persistence only. */
    public static HubStanding restore(State state, int outbound, int inbound, int bonds, Instant everUnlockedAt,
                                      Instant computedAt, Instant provisionalUntil) {
        HubStanding s = new HubStanding();
        s.state = state;
        s.outboundCounting = outbound;
        s.inboundCounting = inbound;
        s.bonds = bonds;
        s.everUnlockedAt = everUnlockedAt;
        s.computedAt = computedAt;
        s.provisionalUntil = provisionalUntil;
        return s;
    }

    /**
     * Whether the hub may issue anything portable: attestations, skill
     * credentials. Only once checked by another hub; never while provisional,
     * so an unchecked hub cannot vouch for anyone elsewhere.
     */
    public boolean issuesPortableCredentials() {
        return state == State.AUTHENTICATED;
    }

    /** Whether the hub may be listed in search beyond its own area. */
    public boolean listedBeyondOwnArea() {
        return state == State.AUTHENTICATED;
    }

    public Instant getProvisionalUntil() {
        return provisionalUntil;
    }

    public boolean isAuthenticated() {
        return state == State.AUTHENTICATED;
    }

    public State getState() {
        return state;
    }

    public int getOutboundCounting() {
        return outboundCounting;
    }

    public int getInboundCounting() {
        return inboundCounting;
    }

    public int getBonds() {
        return bonds;
    }

    public Instant getEverUnlockedAt() {
        return everUnlockedAt;
    }

    public Instant getComputedAt() {
        return computedAt;
    }
}

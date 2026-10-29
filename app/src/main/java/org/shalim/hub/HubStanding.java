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

    public HubStanding() {
        // TODO: pseudo-code
    }

    /** The derivation. Pure function of link counts, history and policy. */
    public static HubStanding compute(int outboundCounting, int inboundCounting, int bonds,
                                      Instant everUnlockedAt, boolean allInboundRevoked,
                                      HubPolicy.UnlockBasis basis, Instant now) {
        // PSEUDO-CODE
        //
        // qualifies = basis == ANY_DIRECTION  ? outboundCounting + inboundCounting >= 1
        //           : basis == INBOUND_REQUIRED ? inboundCounting >= 1
        //
        // IF qualifies                       -> AUTHENTICATED; everUnlockedAt ?= now
        // ELSE IF everUnlockedAt == null     -> UNAUTHENTICATED
        // ELSE IF allInboundRevoked          -> REVOKED
        // ELSE                               -> AUTHENTICATED
        //    // Unlocked before and nothing revoked: links are merely dormant or
        //    // expired. Fail open.
        return null;
    }

    /** The cap this standing puts on one membership. Null = no cap. */
    public Role roleCapFor(Membership membership) {
        // PSEUDO-CODE
        // IF state == AUTHENTICATED -> RETURN null
        // IF membership.role == ADMIN -> RETURN null
        //    // Admins must be able to fix it.
        // RETURN GUEST
        return null;
    }

    /** Plain-language explanation for a capped member. */
    public String explain() {
        // PSEUDO-CODE
        // UNAUTHENTICATED -> "This hub is new and hasn't been checked by another
        //    hub yet. Until it is, you can use its resources and earn skills,
        //    but not search for people."
        // REVOKED -> "This hub is re-establishing its checks with other hubs.
        //    Until it does, you can use its resources and earn skills, but not
        //    search for people."
        //    // Deliberately does not say "revoked". Members are not told another
        //    // hub found fault, only that the hub is not currently checked.
        return null;
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

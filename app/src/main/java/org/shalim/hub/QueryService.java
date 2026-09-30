package org.shalim.hub;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.shalim.identity.Membership;
import org.shalim.identity.Permission;
import org.shalim.ml.CensorEngine;
import org.shalim.ml.MatchmakerEngine;
import org.shalim.query.HubQuery;
import org.shalim.query.QueryContext;
import org.shalim.query.QueryGate;
import org.shalim.query.QueryResult;

/**
 * Query pipeline service: ordered gates run in sequence, and the first rejection
 * short-circuits the rest of the pipeline.
 */
public class QueryService {

    private final Hub hub;
    private final HubRuntime runtime;
    private final List<QueryGate> gates = new ArrayList<>();

    public QueryService(Hub hub, HubRuntime runtime) {
        this.hub = hub;
        this.runtime = runtime;
        this.gates.add(new WellFormedGate());
        this.gates.add(new CorrectHubGate());
        this.gates.add(new MembershipGate());
        this.gates.add(new HubStandingGate());
        this.gates.add(new PermissionGate());
        this.gates.add(new PresenceGate());
        this.gates.add(new RateLimitGate());
        this.gates.add(new CensorIntegrityGate());
        this.gates.add(new CensorScreenGate());
    }

    public QueryService(Hub hub, HubRuntime runtime, List<QueryGate> gates) {
        this.hub = hub;
        this.runtime = runtime;
        this.gates.addAll(gates);
    }

    public QueryResult ask(HubQuery query) {
        if (query == null) {
            return new QueryResult();
        }
        Instant now = Instant.now();
        Membership membership = hub.getRoster() == null ? null : hub.getRoster().membershipOf(query.getAskerUserId()).orElse(null);
        QueryContext ctx = new QueryContext(hub, runtime, query, membership, now);
        for (QueryGate gate : gates) {
            Optional<QueryResult> rejection = gate.check(ctx);
            if (rejection.isPresent()) {
                return rejection.get();
            }
        }
        MatchmakerEngine matchmaker = runtime == null ? null : runtime.getMatchmaker();
        if (matchmaker == null) {
            return new QueryResult();
        }
        QueryResult result = matchmaker.answer(query, hub.getSkillsLayer());
        return result == null ? new QueryResult() : result;
    }

    public List<QueryGate> getGates() {
        return List.copyOf(gates);
    }

    /** Gate that checks a query is well formed and belongs to this hub. */
    private static final class WellFormedGate implements QueryGate {
        @Override
        public Optional<QueryResult> check(QueryContext ctx) {
            if (ctx.getQuery() == null || !ctx.getQuery().isWellFormed()) {
                return Optional.of(new QueryResult());
            }
            if (ctx.getHub() != null && ctx.getQuery().getHubId() != null
                && !ctx.getQuery().getHubId().equals(ctx.getHub().getHubId())) {
                return Optional.of(new QueryResult());
            }
            return Optional.empty();
        }
    }

    private static final class CorrectHubGate implements QueryGate {
        @Override
        public Optional<QueryResult> check(QueryContext ctx) {
            return ctx.getHub() != null && ctx.getQuery().getHubId() != null
                && ctx.getQuery().getHubId().equals(ctx.getHub().getHubId())
                ? Optional.empty() : Optional.of(new QueryResult());
        }
    }

    private static final class MembershipGate implements QueryGate {
        @Override
        public Optional<QueryResult> check(QueryContext ctx) {
            if (ctx.getMembership() == null) {
                return Optional.of(new QueryResult());
            }
            return Optional.empty();
        }
    }

    /**
     * Hub-level cap. An unauthenticated or revoked hub caps every non-admin at
     * GUEST, and guests never get RUN_HUB_QUERY. Placed before the permission
     * gate so the member is told the hub-level reason, not "your role does
     * not include this". Membership.effectivePermissions applies the same cap,
     * so this is belt and braces rather than the only check.
     */
    private static final class HubStandingGate implements QueryGate {
        @Override
        public Optional<QueryResult> check(QueryContext ctx) {
            HubStanding standing = ctx.getHub() == null ? null : ctx.getHub().getStanding();
            if (standing == null) {
                // Missing standing is treated as UNAUTHENTICATED: fail closed
                // for a hub that has never computed it.
                return ctx.getMembership() != null && ctx.getMembership().isAdmin()
                    ? Optional.empty() : Optional.of(new QueryResult());
            }
            if (standing.roleCapFor(ctx.getMembership()) == null) {
                return Optional.empty();
            }
            // PSEUDO-CODE: RETURN QueryResult.refused(standing.explain())
            return Optional.of(new QueryResult());
        }
    }

    private static final class PermissionGate implements QueryGate {
        @Override
        public Optional<QueryResult> check(QueryContext ctx) {
            if (ctx.getMembership() != null && ctx.getMembership().can(Permission.RUN_HUB_QUERY)) {
                return Optional.empty();
            }
            return Optional.of(new QueryResult());
        }
    }

    private static final class PresenceGate implements QueryGate {
        @Override
        public Optional<QueryResult> check(QueryContext ctx) {
            if (ctx.getMembership() == null || !ctx.getMembership().isGuest()) {
                return Optional.empty();
            }
            if (ctx.getMembership().hasValidPresence(ctx.getNow())) {
                return Optional.empty();
            }
            return Optional.of(new QueryResult());
        }
    }

    private static final class RateLimitGate implements QueryGate {
        @Override
        public Optional<QueryResult> check(QueryContext ctx) {
            return Optional.empty();
        }
    }

    private static final class CensorIntegrityGate implements QueryGate {
        @Override
        public Optional<QueryResult> check(QueryContext ctx) {
            if (ctx.getRuntime() == null || ctx.getRuntime().getCensor() == null) {
                return Optional.of(new QueryResult());
            }
            return Optional.empty();
        }
    }

    /**
     * Screens the question and commits the decision to the hub's
     * {@link CensorDecisionLog} before anything is returned. Every exit from
     * this gate — refused, held or passed — carries a receipt, so no answer
     * leaves the hub without a leaf another hub could later replay.
     */
    private static final class CensorScreenGate implements QueryGate {
        @Override
        public Optional<QueryResult> check(QueryContext ctx) {
            CensorEngine censor = ctx.getRuntime() == null ? null : ctx.getRuntime().getCensor();
            if (censor == null) {
                return Optional.of(new QueryResult());
            }
            // PSEUDO-CODE
            // verdict = censor.assess(query.text, HUB_QUERY)
            // action  = BLOCK -> "refused"; REVIEW -> "held"; ALLOW -> "answered"
            // receipt = hub.censorLog.append(query.text, verdict, HUB_QUERY, action, now)
            //    // Append before acting on the verdict. If the append fails,
            //    // refuse the query: an unlogged screening is exactly what
            //    // OrganicProbe exists to catch, and the hub must not produce
            //    // one by accident.
            // ctx.censorReceipt = receipt   // attached to whichever result is returned
            // IF verdict BLOCK  -> RETURN refused(explanation, receipt)
            // IF verdict REVIEW -> RETURN held(receipt)
            return Optional.empty();
        }
    }
}

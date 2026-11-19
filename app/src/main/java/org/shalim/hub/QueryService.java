package org.shalim.hub;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.shalim.identity.Membership;
import org.shalim.identity.Permission;
import org.shalim.identity.Role;
import org.shalim.ml.CensorEngine;
import org.shalim.ml.Match;
import org.shalim.ml.MatchmakerEngine;
import org.shalim.ml.Verdict;
import org.shalim.query.HubQuery;
import org.shalim.query.QueryContext;
import org.shalim.query.QueryGate;
import org.shalim.query.QueryResult;

/**
 * Query pipeline service: ordered gates run in sequence, and the first rejection
 * short-circuits the rest of the pipeline. Every rejection says why, in words
 * safe to show the asker.
 *
 * <p>After the gates: the Matchmaker answers, its member matches are filtered
 * against the roster (hidden, guest, restricted and capped members never
 * appear, whatever the engine returned), the result is capped at the asker's
 * limit, any generated prose is screened at GENERATED_OUTPUT, the surfaced
 * members are recorded for the meeting-request provenance check, and the
 * screening receipt is attached.
 */
public class QueryService {

    /** Questions per member per rolling hour, and per rolling day. */
    public static final int HOURLY_LIMIT = 10;
    public static final int DAILY_LIMIT = 30;

    private final Hub hub;
    private final HubRuntime runtime;
    private final List<QueryGate> gates = new ArrayList<>();
    private final Map<String, Deque<Instant>> recentQueries = new HashMap<>();

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
            return QueryResult.refused(null, "There was no question.");
        }
        Instant now = runtime == null ? Instant.now() : runtime.now();
        Membership membership = hub.getRoster() == null ? null
                : hub.getRoster().membershipOf(query.getAskerUserId()).orElse(null);
        QueryContext ctx = new QueryContext(hub, runtime, query, membership, now);
        for (QueryGate gate : gates) {
            Optional<QueryResult> rejection = gate.check(ctx);
            if (rejection.isPresent()) {
                return attachReceipt(rejection.get(), ctx);
            }
        }
        if (membership != null) {
            membership.markSeen(now);
        }
        if (ctx.isHoldResults()) {
            // QUEUE_FOR_REVIEW with an unverified censor: answered later, by a
            // moderator's release, never straight to the asker.
            return QueryResult.held(query.getQueryId(), ctx.getCensorReceipt());
        }
        MatchmakerEngine matchmaker = runtime == null ? null : runtime.getMatchmaker();
        if (matchmaker == null) {
            return attachReceipt(QueryResult.refused(query.getQueryId(),
                    "Searching for people isn't available on this hub right now."), ctx);
        }
        QueryResult raw = matchmaker.answer(query, hub.getSkillsLayer());
        QueryResult result = raw == null ? QueryResult.answered(query.getQueryId(), List.of(), null, true, 0)
                : filter(raw, query, membership, now);
        log(HubLog.EventType.QUERY_RAISED, query.getAskerUserId(), null, null, now);
        return attachReceipt(result, ctx);
    }

    private static QueryResult attachReceipt(QueryResult r, QueryContext ctx) {
        return ctx.getCensorReceipt() == null || r.getCensorReceipt() != null ? r : r.withReceipt(ctx.getCensorReceipt());
    }

    /**
     * The roster's rule, applied whatever the engine returned: a member is
     * matchable here if they hold at least MEMBER after restrictions and the
     * hub cap, are not hidden (ADMINS_ONLY only for an admin asker), and are
     * not the asker.
     */
    private QueryResult filter(QueryResult raw, HubQuery query, Membership asker, Instant now) {
        HubStanding standing = hub.getStanding();
        boolean askerIsAdmin = asker != null && asker.isAdmin();
        List<Match> kept = new ArrayList<>();
        Set<String> surfaced = new HashSet<>();
        for (Match m : raw.getMatches() == null ? List.<Match>of() : raw.getMatches()) {
            if (kept.size() >= query.getMaxMatches()) {
                break;
            }
            if (m.getKind() == Match.Kind.MEMBER) {
                Membership target = hub.getRoster().membershipOf(m.getTargetId()).orElse(null);
                if (target == null || target.getUserId().equals(query.getAskerUserId())
                        || !target.effectiveRole(standing, now).atLeast(Role.MEMBER)
                        || target.getVisibility() == Membership.Visibility.HIDDEN
                        || (target.getVisibility() == Membership.Visibility.ADMINS_ONLY && !askerIsAdmin)) {
                    continue;
                }
                surfaced.add(target.getUserId());
            }
            kept.add(m);
        }
        hub.getMeetings().recordSurfaced(query.getQueryId(), query.getAskerUserId(), surfaced, now);
        QueryResult filtered = raw.withMatches(kept);
        if (raw.getAnswer() != null) {
            CensorEngine censor = runtime.getCensor();
            Verdict v = censor == null ? null : censor.assess(raw.getAnswer(), CensorEngine.Surface.GENERATED_OUTPUT);
            if (v == null || v.effectiveDecision() != CensorEngine.Decision.ALLOW) {
                filtered = QueryResult.answered(raw.getQueryId(), kept, null, raw.isDegraded(),
                        raw.getTotalCandidatesConsidered());
            }
        }
        return filtered;
    }

    private void log(HubLog.EventType type, String actor, String subject, String detail, Instant now) {
        if (runtime != null && runtime.getHubKey() != null && hub.getLog() != null) {
            hub.getLog().append(type, actor, subject, detail, runtime.getHubKey(), now);
        }
    }

    public List<QueryGate> getGates() {
        return List.copyOf(gates);
    }

    /** Gate that checks a query is well formed. */
    private static final class WellFormedGate implements QueryGate {
        @Override
        public Optional<QueryResult> check(QueryContext ctx) {
            if (ctx.getQuery() == null || !ctx.getQuery().isWellFormed()) {
                return Optional.of(QueryResult.refused(ctx.getQuery() == null ? null : ctx.getQuery().getQueryId(),
                        "Questions need to be between 1 and " + HubQuery.MAX_QUESTION_LENGTH + " characters."));
            }
            return Optional.empty();
        }
    }

    private static final class CorrectHubGate implements QueryGate {
        @Override
        public Optional<QueryResult> check(QueryContext ctx) {
            return ctx.getHub() != null && ctx.getQuery().getHubId() != null
                    && ctx.getQuery().getHubId().equals(ctx.getHub().getHubId())
                    ? Optional.empty()
                    : Optional.of(QueryResult.refused(ctx.getQuery().getQueryId(), "This question was for another hub."));
        }
    }

    private static final class MembershipGate implements QueryGate {
        @Override
        public Optional<QueryResult> check(QueryContext ctx) {
            if (ctx.getMembership() == null) {
                return Optional.of(QueryResult.refused(ctx.getQuery().getQueryId(),
                        "You need to be a member of this hub to search it."));
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
            HubStanding standing = ctx.getHub().getStanding();
            if (standing == null) {
                // Missing standing is treated as UNAUTHENTICATED: fail closed.
                return ctx.getMembership().isAdmin() ? Optional.empty()
                        : Optional.of(QueryResult.refused(ctx.getQuery().getQueryId(),
                                HubStanding.unauthenticatedExplanation()));
            }
            if (standing.roleCapFor(ctx.getMembership()) == null) {
                return Optional.empty();
            }
            // A guest is told what guests can do, below; a capped member is
            // told it is the hub, not them.
            if (ctx.getMembership().getRole() == Role.GUEST) {
                return Optional.empty();
            }
            return Optional.of(QueryResult.refused(ctx.getQuery().getQueryId(), standing.explain()));
        }
    }

    private static final class PermissionGate implements QueryGate {
        @Override
        public Optional<QueryResult> check(QueryContext ctx) {
            HubStanding standing = ctx.getHub().getStanding();
            if (ctx.getMembership().can(Permission.RUN_HUB_QUERY, standing)) {
                return Optional.empty();
            }
            String why = ctx.getMembership().explainDenial(Permission.RUN_HUB_QUERY, standing);
            return Optional.of(QueryResult.refused(ctx.getQuery().getQueryId(),
                    ctx.getMembership().isGuest()
                            ? "Guests can use the hub's resources and earn skills, but not search for people." : why));
        }
    }

    private static final class PresenceGate implements QueryGate {
        @Override
        public Optional<QueryResult> check(QueryContext ctx) {
            if (ctx.getMembership().hasValidPresence(ctx.getNow())) {
                return Optional.empty();
            }
            return Optional.of(QueryResult.refused(ctx.getQuery().getQueryId(),
                    "Guest access lasts while you are at the hub. Reconnect to its Wi-Fi to continue."));
        }
    }

    /**
     * Per member: {@link #HOURLY_LIMIT} an hour, {@link #DAILY_LIMIT} a day.
     * Enough for anyone looking for help; too few to enumerate a hub by
     * asking about every skill in turn.
     */
    private final class RateLimitGate implements QueryGate {
        @Override
        public Optional<QueryResult> check(QueryContext ctx) {
            String who = ctx.getMembership().getUserId();
            Instant now = ctx.getNow();
            synchronized (recentQueries) {
                Deque<Instant> times = recentQueries.computeIfAbsent(who, k -> new ArrayDeque<>());
                while (!times.isEmpty() && times.peekFirst().isBefore(now.minus(Duration.ofDays(1)))) {
                    times.removeFirst();
                }
                long lastHour = times.stream().filter(t -> t.isAfter(now.minus(Duration.ofHours(1)))).count();
                if (times.size() >= DAILY_LIMIT || lastHour >= HOURLY_LIMIT) {
                    return Optional.of(QueryResult.refused(ctx.getQuery().getQueryId(),
                            "You've asked a lot of questions recently. Try again a bit later."));
                }
                times.addLast(now);
            }
            return Optional.empty();
        }
    }

    /**
     * Never "carry on unscreened". With the censor verified: proceed. Flagged
     * as tampered: refuse, whatever the failure mode. Merely unavailable:
     * the policy decides between refusing, holding results for review, and
     * screening against the bundled blocklist.
     */
    private static final class CensorIntegrityGate implements QueryGate {
        @Override
        public Optional<QueryResult> check(QueryContext ctx) {
            CensorIntegrity integrity = ctx.getHub().getCensorIntegrity();
            HubPolicy policy = ctx.getHub().getPolicy();
            if (integrity == null || !integrity.permitsQuerying(policy)) {
                return Optional.of(QueryResult.refused(ctx.getQuery().getQueryId(),
                        "Searching is paused while this hub's safety check is restored."));
            }
            if (!integrity.isVerified() && policy != null
                    && policy.getCensorFailureMode() == HubPolicy.CensorFailureMode.QUEUE_FOR_REVIEW) {
                ctx.setHoldResults(true);
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
            HubRuntime rt = ctx.getRuntime();
            Hub hub = ctx.getHub();
            HubQuery query = ctx.getQuery();
            if (rt == null || rt.getHubKey() == null || rt.atRestKey() == null || hub.getCensorLog() == null) {
                return Optional.of(QueryResult.refused(query.getQueryId(),
                        "This hub can't screen questions right now, so it isn't taking them."));
            }
            CensorEngine censor = screeningEngine(rt, hub);
            Verdict verdict = censor == null
                    ? new Verdict() // unscreened placeholder: REVIEW, so the question is held, never passed
                    : censor.assess(query.getQuestion(), CensorEngine.Surface.HUB_QUERY);
            CensorEngine.Decision d = verdict.effectiveDecision();
            String action = d == CensorEngine.Decision.BLOCK ? "refused"
                    : d == CensorEngine.Decision.REVIEW ? "held" : "answered";
            CensorDecisionLog.Receipt receipt;
            try {
                // Append before acting on the verdict. If the append fails,
                // refuse: an unlogged screening is exactly what OrganicProbe
                // exists to catch, and the hub must not produce one by accident.
                receipt = hub.getCensorLog().append(query.getQuestion(), verdict, CensorEngine.Surface.HUB_QUERY,
                        action, rt.getHubKey(), rt.atRestKey(), ctx.getNow());
            } catch (RuntimeException e) {
                return Optional.of(QueryResult.refused(query.getQueryId(),
                        "This hub couldn't record the screening of your question, so it wasn't asked."));
            }
            query.recordScreening(verdict);
            ctx.setCensorReceipt(receipt);
            if (d == CensorEngine.Decision.BLOCK) {
                return Optional.of(QueryResult.refused(query.getQueryId(),
                        "This question can't be asked through the hub.").withReceipt(receipt));
            }
            if (d == CensorEngine.Decision.REVIEW) {
                return Optional.of(QueryResult.held(query.getQueryId(), receipt));
            }
            return Optional.empty();
        }

        /** The model if it verifies; the blocklist only where policy allows; else none. */
        private static CensorEngine screeningEngine(HubRuntime rt, Hub hub) {
            CensorIntegrity integrity = hub.getCensorIntegrity();
            if (rt.getCensor() != null && integrity != null && integrity.isVerified()) {
                return rt.getCensor();
            }
            HubPolicy policy = hub.getPolicy();
            if (policy != null && policy.getCensorFailureMode() == HubPolicy.CensorFailureMode.BLOCKLIST_ONLY) {
                return rt.getBlocklist();
            }
            return null;
        }
    }
}

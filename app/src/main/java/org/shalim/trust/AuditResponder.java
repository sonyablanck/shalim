package org.shalim.trust;

import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.shalim.hub.CensorDecisionLog;
import org.shalim.hub.Hub;
import org.shalim.hub.HubLog;
import org.shalim.hub.HubRuntime;
import org.shalim.identity.Membership;
import org.shalim.identity.Permission;
import org.shalim.identity.Role;

/**
 * The target hub's side of authentication: answers the hubs that check it.
 *
 * <p>It never learns who carries a link. It sees a hub key, an anonymous
 * proof, two pseudonyms and a nullifier. Its admins accept or decline the
 * <em>hub</em>. It opens its own committed decisions only for a nonce that
 * verifies against the chain the auditor committed to, at indices it derives
 * itself, and never more than the schedule's daily cap, so an auditor can
 * neither aim at one member's question nor read a quiet hub wholesale.
 */
public final class AuditResponder implements LinkPeer {

    private record Pending(LinkRequest request, ProberEligibility.Result result, Instant at) {
    }

    private final HubRuntime runtime;
    private final MemberCredentialIssuer issuer;
    private final NullifierRegistry registry;
    private final AuditSchedule schedule;
    private final WebOfTrust web;
    private final Runnable onStandingChange;

    private final Map<String, List<byte[]>> auditorDoubleBlinded = new HashMap<>();
    private final Map<String, Integer> overlap = new HashMap<>();
    private final Map<String, Pending> pending = new HashMap<>();

    AuditResponder(HubRuntime runtime, MemberCredentialIssuer issuer, NullifierRegistry registry,
                   AuditSchedule schedule, WebOfTrust web, Runnable onStandingChange) {
        this.runtime = runtime;
        this.issuer = issuer;
        this.registry = registry;
        this.schedule = schedule;
        this.web = web;
        this.onStandingChange = onStandingChange;
    }

    private Hub hub() {
        return runtime.getHub();
    }

    @Override
    public String keyFingerprint() {
        return runtime.getHubKey().fingerprint();
    }

    @Override
    public byte[] publicKey() {
        return runtime.getHubKey().publicKey();
    }

    @Override
    public byte[] newChallenge() {
        return org.shalim.crypto.Bytes.random(32);
    }

    @Override
    public synchronized List<byte[]> overlapRound1(String auditorKeyFingerprint, List<byte[]> auditorBlinded) {
        byte[] exp = AdminOverlapCheck.newExponent();
        auditorDoubleBlinded.put(auditorKeyFingerprint, AdminOverlapCheck.doubleBlind(auditorBlinded, exp));
        return AdminOverlapCheck.blindOwnAdmins(ownAdmins(), exp);
    }

    @Override
    public synchronized void overlapRound2(String auditorKeyFingerprint, List<byte[]> targetDoubleBlinded) {
        List<byte[]> theirs = auditorDoubleBlinded.remove(auditorKeyFingerprint);
        if (theirs != null) {
            overlap.put(auditorKeyFingerprint, AdminOverlapCheck.intersectionSize(targetDoubleBlinded, theirs));
        }
    }

    @Override
    public synchronized ProberEligibility.Result requestLink(LinkRequest request, Instant now) {
        Integer shared = overlap.remove(request.auditorKeyFingerprint());
        ProberEligibility.Result result;
        if (shared == null || request.proof() == null
                || !request.auditorKeyFingerprint().equals(request.proof().getAuditingHubKeyFingerprint())
                || !org.shalim.crypto.Fingerprints.matchesSigningKey(request.auditorKeyFingerprint(),
                        request.auditorPublicKey())) {
            result = ProberEligibility.Result.NO_VALID_CREDENTIAL;
        } else {
            result = check(request.proof(), shared, now);
        }
        if (!ProberEligibility.permitsLink(result)) {
            runtime.log(HubLog.EventType.PROBER_REFUSED, null, request.auditorKeyFingerprint(), result.name(), now);
            return result;
        }
        pending.put(request.auditorKeyFingerprint(), new Pending(request, result, now));
        return result;
    }

    /** Requests waiting for this hub's admins, by authenticating hub key. Never by person. */
    public synchronized List<String> pendingRequests() {
        return List.copyOf(pending.keySet());
    }

    /**
     * An admin here accepts checking by another hub. Records the inbound link
     * under its pseudonym and starts serving heads and openings to that hub.
     */
    public synchronized boolean approve(String auditorKeyFingerprint, String approvingAdminUserId, Instant now) {
        Membership m = hub().getRoster().membershipOf(approvingAdminUserId).orElse(null);
        if (m == null || !m.can(Permission.MANAGE_AUTHENTICATION, hub().getStanding())) {
            return false;
        }
        Pending p = pending.remove(auditorKeyFingerprint);
        if (p == null) {
            return false;
        }
        EligibilityProof proof = p.request().proof();
        AuditSchedule.Mode mode = p.result() == ProberEligibility.Result.ANONYMITY_SET_TOO_SMALL
                ? AuditSchedule.Mode.REPLAY_ONLY : AuditSchedule.Mode.FULL;
        AuthLink link = AuthLink.inbound(auditorKeyFingerprint, keyFingerprint(), proof.getLinkPseudonym(),
                p.request().nonceAnchor(), mode, now);
        link.acceptNonceAnchor(p.request().nonceAnchor(), p.request().chainStart());
        link.setAuthenticatorKeys(p.request().auditorPublicKey(), p.request().auditorEncryptionKey());
        web.recordInbound(link);
        registry.assign(proof.getProberPseudonym(), auditorKeyFingerprint);
        // Never a user id: there is none to log.
        runtime.log(HubLog.EventType.PROBER_ACCEPTED, approvingAdminUserId, auditorKeyFingerprint,
                proof.getLinkPseudonym(), now);
        return true;
    }

    /** Declining is silent and costs nothing, as with every request in Shalim. */
    public synchronized boolean decline(String auditorKeyFingerprint, String adminUserId) {
        Membership m = hub().getRoster().membershipOf(adminUserId).orElse(null);
        return m != null && m.can(Permission.MANAGE_AUTHENTICATION, hub().getStanding())
                && pending.remove(auditorKeyFingerprint) != null;
    }

    @Override
    public synchronized ProberEligibility.Result presentDaily(String auditorKeyFingerprint, EligibilityProof proof,
                                                             Instant now) {
        AuthLink link = web.inboundFrom(auditorKeyFingerprint);
        if (link == null || proof == null || !auditorKeyFingerprint.equals(proof.getAuditingHubKeyFingerprint())
                || !proof.getLinkPseudonym().equals(link.getLinkPseudonym())) {
            return ProberEligibility.Result.NO_VALID_CREDENTIAL;
        }
        ProberEligibility.Result r = check(proof, 0, now);
        if (!ProberEligibility.permitsLink(r)) {
            runtime.log(HubLog.EventType.PROBER_REFUSED, null, auditorKeyFingerprint, r.name(), now);
            registry.release(proof.getProberPseudonym(), auditorKeyFingerprint);
        }
        return r;
    }

    private ProberEligibility.Result check(EligibilityProof proof, int adminOverlap, Instant now) {
        LocalDate today = LocalDate.ofInstant(now, ZoneOffset.UTC);
        EpochNullifier first = proof.getNullifier() == null ? null
                : registry.firstSeen(proof.getNullifier().getNullifier());
        ProberEligibility.Result r = ProberEligibility.checkInbound(proof, hub(), publicKey(), keyFingerprint(),
                adminOverlap, registry, issuer, schedule, today);
        if (r == ProberEligibility.Result.NULLIFIER_DOUBLE_SPENT && first != null) {
            // The one path by which a prober's anonymity ends, reachable only
            // by their own client breaking the protocol.
            String membershipId = registry.trace(first, proof.getNullifier(), issuer);
            registry.bar(proof.getProberPseudonym());
            runtime.log(HubLog.EventType.NULLIFIER_DOUBLE_SPENT, null, membershipId, null, now);
        }
        return r;
    }

    @Override
    public synchronized CensorDecisionLog.SignedTreeHead head(LocalDate day, Instant now) {
        CensorDecisionLog log = hub().getCensorLog();
        if (log == null || !day.isBefore(LocalDate.ofInstant(now, ZoneOffset.UTC))) {
            return null; // only closed days have heads
        }
        CensorDecisionLog.SignedTreeHead h = log.headFor(day);
        return h != null ? h : log.closeThrough(day, runtime.getHubKey(), now);
    }

    @Override
    public synchronized List<CensorDecisionLog.Opening> open(String auditorKeyFingerprint, LocalDate day,
                                                             byte[] dayNonce, int size, Instant now) {
        AuthLink link = web.inboundFrom(auditorKeyFingerprint);
        if (link == null || link.isRevoked() || link.getAuthenticatorEncryptionKey() == null) {
            return null;
        }
        if (dayNonce == null || !ReplayAuditor.verifyRevealedNonce(link.getNonceCommitment(), link.nonceChainStart(),
                day, dayNonce)) {
            return null; // a nonce the auditor did not commit to opens nothing
        }
        CensorDecisionLog.SignedTreeHead head = hub().getCensorLog().headFor(day);
        if (head == null) {
            return null;
        }
        int n = Math.max(0, Math.min(size, schedule.getMaxReplayDrawPerDay()));
        List<Long> indices = ReplayAuditor.sampleIndices(head, dayNonce, n);
        List<CensorDecisionLog.Opening> out = runtime.openForAuditor(day, indices, link.getAuthenticatorEncryptionKey());
        // Count only. Which indices were opened is not logged: indices join to texts.
        runtime.log(HubLog.EventType.REPLAY_SAMPLE_OPENED, null, auditorKeyFingerprint,
                day + " " + out.size(), now);
        return out;
    }

    /** A member's own receipt check: the proof that their leaf is in the day's tree. */
    public CensorDecisionLog.InclusionProof proveInclusion(LocalDate day, long leafIndex) {
        return hub().getCensorLog().proveInclusion(day, leafIndex);
    }

    @Override
    public boolean deliverStatement(LinkStatement statement, Instant now) {
        boolean ok = web.applyStatement(statement, now);
        if (ok && onStandingChange != null) {
            onStandingChange.run();
        }
        return ok;
    }

    private List<String> ownAdmins() {
        return hub().getRoster().getMemberships().stream().filter(m -> m.getRole() == Role.ADMIN)
                .map(Membership::getUserId).toList();
    }

    public MemberCredentialIssuer getIssuer() {
        return issuer;
    }

    public NullifierRegistry getRegistry() {
        return registry;
    }
}

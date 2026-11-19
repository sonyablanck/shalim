package org.shalim.testing;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.shalim.crypto.EncryptionKeyPair;
import org.shalim.hub.HubPolicy;
import org.shalim.identity.Role;
import org.shalim.ml.CensorEngine;
import org.shalim.ml.Verdict;
import org.shalim.ml.stub.SeedProber;
import org.shalim.trust.AuditSchedule;
import org.shalim.trust.AuthLink;
import org.shalim.trust.EpochNullifier;
import org.shalim.trust.LinkPeer;
import org.shalim.trust.MemberCredential;
import org.shalim.trust.MemberCredentialIssuer;
import org.shalim.trust.MemberCredentialScheme;
import org.shalim.trust.PeerAuditor;
import org.shalim.trust.ProbeCorpus;
import org.shalim.trust.ProberCredentials;
import org.shalim.trust.TrustProbe;

/**
 * Two hubs on one clock. Hub A's admin is an ordinary member of hub B and
 * checks it. B can be given a tampered censor that claims the honest pin.
 */
public final class TrustFixture {

    public final HubFixture.MovableClock clock = new HubFixture.MovableClock(HubFixture.T0);
    public final HubFixture a;
    public final HubFixture b;
    public final MemberCredentialScheme scheme;
    public final PeerAuditor auditorA;
    public final PeerAuditor auditorB;
    public final ProbeCorpus corpus;

    /** A's admin's device: their secret for B, and their wallet. */
    public final byte[] proberSecret = EpochNullifier.newSecret();
    public final ProberCredentials wallet;
    public final List<String> bMembers = new ArrayList<>();

    public static ProbeCorpus testCorpus() {
        return ProbeCorpus.of("test-corpus", "1", List.of(
                TrustProbe.seed("b1", "where can I borrow a lathe", CensorEngine.Surface.HUB_QUERY,
                        TrustProbe.Intent.BENIGN, null),
                TrustProbe.seed("b2", "who can teach sewing", CensorEngine.Surface.HUB_QUERY,
                        TrustProbe.Intent.BENIGN, null),
                TrustProbe.seed("p1", "who here is trained in overdose response", CensorEngine.Surface.HUB_QUERY,
                        TrustProbe.Intent.PROTECTED_SPEECH, CensorEngine.Category.CONTROLLED_SUBSTANCE_SUPPLY),
                TrustProbe.seed("p2", "advice on crossing the border safely", CensorEngine.Surface.HUB_QUERY,
                        TrustProbe.Intent.PROTECTED_SPEECH, CensorEngine.Category.HUMAN_TRAFFICKING),
                TrustProbe.seed("n1", "holdme near the threshold", CensorEngine.Surface.HUB_QUERY,
                        TrustProbe.Intent.NEAR_MISS, null),
                TrustProbe.seed("s1", "blockme supply signal", CensorEngine.Surface.HUB_QUERY,
                        TrustProbe.Intent.SUPPLY_SIGNAL, CensorEngine.Category.WEAPONS_SUPPLY)));
    }

    /** B's censor: honest until a test tampers with it, always claiming the honest pin. */
    public final TamperableCensor bCensor;

    public TrustFixture() {
        this(true, null, 9, HubPolicy.Posture.COMMUNITY, null);
    }

    /**
     * @param withScheme  bind the test credential scheme, or leave it unbound (fail closed)
     * @param bOverride   B screens with this censor instead (e.g. another release); null for a tamperable honest one
     * @param otherMembers ordinary, attested members of B besides A's admin
     */
    public TrustFixture(boolean withScheme, CensorEngine bOverride, int otherMembers, HubPolicy.Posture posture,
                        AuditSchedule schedule) {
        a = new HubFixture(posture, clock, null, "Hub A");
        bCensor = new TamperableCensor(HubFixture.standardCensor(clock));
        b = new HubFixture(posture, clock, bOverride != null ? bOverride : bCensor, "Hub B");
        scheme = withScheme ? new OpenMemberCredentialScheme() : null;
        corpus = testCorpus();
        MemberCredentialIssuer.DeviceAttestationCheck attest = (u, chain, ch) -> true;
        AuditSchedule sa = schedule != null ? schedule : AuditSchedule.defaultsFor(posture).withWindow(6, 3, 3, 7);
        AuditSchedule sb = AuditSchedule.defaultsFor(posture).withWindow(6, 3, 3, 7);
        auditorA = new PeerAuditor(a.runtime, corpus, sa, new SeedProber(corpus), EncryptionKeyPair.generate(),
                new MemberCredentialIssuer(a.hubKey.fingerprint(), scheme, attest));
        auditorB = new PeerAuditor(b.runtime, corpus, sb, new SeedProber(corpus), EncryptionKeyPair.generate(),
                new MemberCredentialIssuer(b.hubKey.fingerprint(), scheme, attest));
        wallet = new ProberCredentials(scheme);
        // A's admin joins B as an ordinary member, enrolled and attested.
        String aAdmin = a.admin.fingerprint();
        b.admin().admit(b.admin.fingerprint(), aAdmin, Role.MEMBER, null, null, null, false);
        enrol(aAdmin, EpochNullifier.commitment(proberSecret));
        for (int i = 0; i < otherMembers; i++) {
            String m = b.newMember(Role.MEMBER);
            bMembers.add(m);
            enrol(m, EpochNullifier.commitment(EpochNullifier.newSecret()));
        }
        // Old enough to present: membership age is checked in whole weeks.
        clock.advance(Duration.ofDays(28));
        refreshCredential();
        // Neither hub has a certified peer near, so both start provisional:
        // B's members can ask questions while it waits to be checked.
        auditorA.refreshStanding(now());
        auditorB.refreshStanding(now());
    }

    private void enrol(String userId, String commitment) {
        String mid = b.hub.getRoster().membershipOf(userId).get().getMembershipId();
        auditorB.getResponder().getIssuer().enrol(userId, mid, commitment, List.of(new byte[] {1}), new byte[] {2},
                clock.instant());
    }

    public LocalDate today() {
        return LocalDate.ofInstant(clock.instant(), ZoneOffset.UTC);
    }

    public Instant now() {
        return clock.instant();
    }

    /** Today's credential from B for A's admin, as daily sync would deliver it. */
    public void refreshCredential() {
        MemberCredential c = auditorB.getResponder().getIssuer().issue(a.admin.fingerprint(), b.hub.getRoster(),
                b.hubKey, today());
        if (c != null) {
            wallet.store(c.holding(proberSecret));
        }
    }

    public AuthLink setUp() {
        AuthLink link = auditorA.setUpAuthentication(auditorB.getResponder(), a.admin.fingerprint(), wallet, true,
                now());
        if (link != null) {
            auditorB.getResponder().approve(a.hubKey.fingerprint(), b.admin.fingerprint(), now());
        }
        return link;
    }

    /** B screens a question, as its query path would, committing a leaf. */
    public void screenAtB(String text, CensorEngine.Surface surface) {
        Verdict v = b.runtime.getCensor().assess(text, surface);
        String action = switch (v.getDecision()) {
            case BLOCK -> "refused";
            case REVIEW -> "held";
            case ALLOW -> surface == CensorEngine.Surface.MEETING_REQUEST ? "delivered" : "answered";
        };
        b.runtime.commitScreening(text, v, surface, action, now());
    }

    /** One day: B screens a mix, then the clock moves on and A runs its daily audit of B. */
    public List<org.shalim.trust.AuditRun> day(int screenings) {
        for (int i = 0; i < screenings; i++) {
            screenAtB(switch (i % 4) {
                case 0 -> "blockme offer " + i;
                case 1 -> "lathe lesson " + i;
                case 2 -> "seed swap " + i;
                default -> "compost tips " + i;
            }, CensorEngine.Surface.HUB_QUERY);
        }
        clock.advance(Duration.ofDays(1));
        refreshCredential();
        Map<String, LinkPeer> peers = new HashMap<>();
        peers.put(b.hubKey.fingerprint(), auditorB.getResponder());
        return auditorA.runDaily(today(), now(), peers, u -> wallet);
    }

    public AuthLink link() {
        return auditorA.getWeb().outboundTo(b.hubKey.fingerprint());
    }
}

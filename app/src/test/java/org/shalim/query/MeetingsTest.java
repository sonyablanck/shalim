package org.shalim.query;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.shalim.hub.HubLog;
import org.shalim.hub.QueryService;
import org.shalim.identity.Role;
import org.shalim.ml.CensorEngine;
import org.shalim.ml.Match;
import org.shalim.skills.ResourceInteraction;
import org.shalim.skills.SkillCredential;
import org.shalim.skills.UserSkill;
import org.shalim.testing.Check;
import org.shalim.testing.HubFixture;

public final class MeetingsTest {

    private MeetingsTest() {
    }

    /** An authenticated hub where `helper` has a lathe skill, and `asker` has searched and found them. */
    private static final class Scene {
        final HubFixture f = new HubFixture();
        final String asker;
        final String helper;
        final String mod;
        final String queryId;
        final MeetingService meetings;

        Scene() {
            f.authenticate();
            asker = f.newMember(Role.MEMBER);
            helper = f.newMember(Role.MEMBER);
            mod = f.newMember(Role.MODERATOR);
            var admin = f.admin();
            String lathe = f.hub.getSkillsLayer().getResources().get(0).getResourceId();
            ResourceInteraction i = admin.recordInteraction(helper, lathe, null);
            List<SkillCredential> c = admin.verifyInteraction(f.admin.fingerprint(), i.getInteractionId(),
                    UserSkill.Proficiency.CAN_TEACH);
            admin.presentCredentials(helper, c);
            HubQuery q = new HubQuery(f.hub.getHubId(), asker, "lathe metalwork").withMaxMatches(5);
            QueryResult r = new QueryService(f.hub, f.runtime).ask(q);
            Check.isTrue(r.getMatches().stream().anyMatch(m -> m.getKind() == Match.Kind.MEMBER
                    && m.getTargetId().equals(helper)), "the helper was surfaced");
            queryId = q.getQueryId();
            meetings = new MeetingService(f.hub, f.runtime);
        }
    }

    public static void testNoColdContactNoContactDetailsOnceOnly() {
        Scene s = new Scene();
        Check.isFalse(s.meetings.request(s.asker, s.mod, s.queryId, "Hello").sent(),
                "only people your own search surfaced");
        Check.isFalse(s.meetings.request(s.helper, s.asker, s.queryId, "Hello").sent(), "only from your own search");
        for (String bad : List.of("Text me on 07700 900123", "mail me: sam@example.org", "see www.example.com",
                "find me on telegram: @samuel")) {
            Check.isFalse(s.meetings.request(s.asker, s.helper, s.queryId, bad).sent(), "refused: " + bad);
        }
        Check.throwsA(IllegalArgumentException.class, () -> new MeetingRequest("h", "a", "b", "q", "x".repeat(151)),
                "151 characters refused at construction");
        MeetingService.SendOutcome ok = s.meetings.request(s.asker, s.helper, s.queryId,
                "Could you show me the lathe on Thursday 2026-11-19?");
        Check.isTrue(ok.sent(), "a plain request goes: " + ok.message());
        Check.isTrue(ok.receipt().verify(s.f.hubKey.publicKey()), "with a screening receipt");
        Check.isFalse(s.meetings.request(s.asker, s.helper, s.queryId, "Again?").sent(), "sent once");
    }

    public static void testHeldRequestsWaitForAModerator() {
        Scene s = new Scene();
        MeetingService.SendOutcome held = s.meetings.request(s.asker, s.helper, s.queryId, "holdme for a sec");
        Check.isTrue(held.request().isHeldForReview(), "held");
        Check.equal(0, s.meetings.inbox(s.helper).size(), "not delivered while held");
        Check.equal(1, s.meetings.heldForReview(s.mod).size(), "moderators see it");
        Check.equal(0, s.meetings.heldForReview(s.asker).size(), "members do not");
        Check.isFalse(s.meetings.decideHeld(held.request().getRequestId(), s.mod, CensorEngine.Decision.ALLOW, " "),
                "a decision needs a reason");
        Check.isTrue(s.meetings.decideHeld(held.request().getRequestId(), s.mod, CensorEngine.Decision.ALLOW,
                "harmless"), "released");
        Check.equal(1, s.meetings.inbox(s.helper).size(), "now delivered");
        Check.equal(1, s.f.hub.getLog().byType(HubLog.EventType.CENSOR_HOLD_DECIDED).size(), "decision logged");
    }

    public static void testBlockedRequestsTellTheSenderNotTheRecipient() {
        Scene s = new Scene();
        MeetingService.SendOutcome blocked = s.meetings.request(s.asker, s.helper, s.queryId, "selling blockme");
        Check.equal(MeetingRequest.Status.BLOCKED, blocked.request().getStatus(), "blocked");
        Check.isTrue(blocked.message().contains("can't be sent"), "the sender is told");
        Check.equal(0, s.meetings.inbox(s.helper).size(), "the recipient never sees it");
    }

    public static void testDeclineIsSilentAcceptUnlocksSchedulingAtTheHub() {
        Scene s = new Scene();
        MeetingRequest r = s.meetings.request(s.asker, s.helper, s.queryId, "Lathe lesson?").request();
        Check.isNull(s.meetings.schedule(r.getRequestId(), s.asker, s.f.clock.instant().plus(Duration.ofDays(1)), 60,
                null), "nothing is scheduled before acceptance");
        Check.isTrue(s.meetings.respond(r.getRequestId(), s.helper, true), "accepted");
        Instant tomorrowMorning = Instant.parse("2026-11-19T10:00:00Z");
        Check.isNull(s.meetings.schedule(r.getRequestId(), s.asker, Instant.parse("2026-11-19T23:00:00Z"), 60, null),
                "not outside opening hours");
        Check.isNull(s.meetings.schedule(r.getRequestId(), s.asker, tomorrowMorning, 60, "my flat"),
                "not anywhere but the hub's declared spaces");
        Meeting m = s.meetings.schedule(r.getRequestId(), s.asker, tomorrowMorning, 60, "study room 3");
        Check.notNull(m, "booked at the hub");
        Check.equal(s.f.hub.getLocation().getLocationId(), m.getLocationId(), "venue is always the hub");
        Check.isTrue(s.meetings.report(m.getMeetingId(), s.helper, "made me uncomfortable"), "reported");
        Check.isTrue(s.f.hub.getMeetings().isBlocked(s.asker, s.helper), "the pair is blocked");
        Check.isTrue(s.f.hub.getLog().byType(HubLog.EventType.MEETING_REPORTED).get(0).getDetail() == null,
                "the concern is not in the log");

        Scene t = new Scene();
        MeetingRequest d = t.meetings.request(t.asker, t.helper, t.queryId, "Lathe lesson?").request();
        Check.isTrue(t.meetings.respond(d.getRequestId(), t.helper, false), "declined");
        Check.equal("No response.", t.meetings.senderView(d.getRequestId(), t.asker), "silently");
        Check.isNull(t.meetings.senderView(d.getRequestId(), t.helper), "only the sender asks after their request");
    }

    public static void testCompactFrameFitsLoRaForLatinScript() {
        String q = org.shalim.crypto.Bytes.randomId();
        MeetingRequest latin = new MeetingRequest("h", "a", "b", q, "x".repeat(150));
        Check.isTrue(latin.fitsLoRa(), "150 Latin characters fit one SF7 frame");
        MeetingRequest back = MeetingRequest.fromCompactFrame(latin.toCompactFrame(), "h", "a", "b");
        Check.equal(latin.getMessage(), back.getMessage(), "round trip");
        Check.equal(latin.getRequestId(), back.getRequestId(), "same id");
        Check.isFalse(new MeetingRequest("h", "a", "b", q, "щ".repeat(150)).fitsLoRa(), "Cyrillic at full length does not");
    }
}

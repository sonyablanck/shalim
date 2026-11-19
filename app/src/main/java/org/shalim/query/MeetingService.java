package org.shalim.query;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.shalim.hub.CensorDecisionLog;
import org.shalim.hub.Hub;
import org.shalim.hub.HubLog;
import org.shalim.hub.HubRuntime;
import org.shalim.identity.Membership;
import org.shalim.identity.Permission;
import org.shalim.ml.CensorEngine;
import org.shalim.ml.Verdict;

/**
 * The rules around meeting requests and meetings. {@link MeetingRequest} and
 * {@link Meeting} hold the state transitions; this class holds who may do what.
 *
 * <ul>
 *   <li>A request may be sent only to someone the sender's own recent query
 *       surfaced, once per pair, never to a blocked pair, and only by someone
 *       who holds REQUEST_MEETING under the hub's standing.</li>
 *   <li>Every message is screened at MEETING_REQUEST and committed to the
 *       censor decision log before anything else happens; the sender gets the
 *       receipt.</li>
 *   <li>Recipients see only deliverable requests. Declining is silent.</li>
 *   <li>Meetings happen at the hub, inside opening hours, in a declared space,
 *       and only at a location suitable for first meetings.</li>
 *   <li>A report blocks the pair from further contact through the hub.</li>
 * </ul>
 *
 * <p>Log entries carry ids, never message text.
 */
public class MeetingService {

    /** What the sender sees after sending. */
    public record SendOutcome(MeetingRequest request, CensorDecisionLog.Receipt receipt, String message) {
        public boolean sent() {
            return request != null && receipt != null;
        }
    }

    private final Hub hub;
    private final HubRuntime runtime;

    public MeetingService(Hub hub, HubRuntime runtime) {
        this.hub = hub;
        this.runtime = runtime;
    }

    public SendOutcome request(String fromUserId, String toUserId, String originatingQueryId, String message) {
        Instant now = runtime.now();
        Membership from = member(fromUserId);
        if (from == null || !from.can(Permission.REQUEST_MEETING, hub.getStanding())) {
            return refused(from == null ? "You need to be a member of this hub."
                    : from.explainDenial(Permission.REQUEST_MEETING, hub.getStanding()));
        }
        MeetingBook book = hub.getMeetings();
        if (!book.surfaced(originatingQueryId, fromUserId, toUserId)) {
            return refused("You can only send a request to someone one of your recent searches found.");
        }
        Membership to = member(toUserId);
        if (to == null || !to.can(Permission.RESPOND_TO_MEETING, hub.getStanding())) {
            // Indistinguishable from any other non-delivery, on purpose.
            return refused("This request can't be sent.");
        }
        if (book.isBlocked(fromUserId, toUserId) || book.hasRequested(fromUserId, toUserId)) {
            return refused("This request can't be sent.");
        }
        MeetingRequest request;
        try {
            request = new MeetingRequest(hub.getHubId(), fromUserId, toUserId, originatingQueryId, message);
        } catch (IllegalArgumentException e) {
            return refused("Requests are at most " + MeetingRequest.MAX_MESSAGE_LENGTH + " characters.");
        }
        if (!request.isWellFormed()) {
            return refused("Keep first contact in the app: no links, numbers, e-mail addresses or handles.");
        }
        CensorEngine censor = runtime.getCensor();
        Verdict verdict = censor == null || hub.getCensorIntegrity() == null || !hub.getCensorIntegrity().isVerified()
                ? new Verdict() // unscreened: REVIEW, so it is held, never delivered
                : censor.assess(request.getMessage(), CensorEngine.Surface.MEETING_REQUEST);
        CensorEngine.Decision d = verdict.effectiveDecision();
        String action = d == CensorEngine.Decision.BLOCK ? "refused"
                : d == CensorEngine.Decision.REVIEW ? "held" : "delivered";
        CensorDecisionLog.Receipt receipt;
        try {
            receipt = runtime.commitScreening(request.getMessage(), verdict, CensorEngine.Surface.MEETING_REQUEST,
                    action, now);
        } catch (RuntimeException e) {
            return refused("This hub couldn't record the screening of your request, so it wasn't sent.");
        }
        request.applyVerdict(verdict, now);
        book.addRequest(request);
        runtime.log(HubLog.EventType.MEETING_REQUESTED, fromUserId, request.getRequestId(), null, now);
        from.markSeen(now);
        return new SendOutcome(request, receipt, request.senderView());
    }

    private static SendOutcome refused(String why) {
        return new SendOutcome(null, null, why);
    }

    /** Requests the recipient may see: screened, clear, current. Lapsed ones expire here. */
    public List<MeetingRequest> inbox(String userId) {
        Instant now = runtime.now();
        List<MeetingRequest> out = new ArrayList<>();
        for (MeetingRequest r : hub.getMeetings().requests()) {
            r.expireIfDue(now);
            if (userId.equals(r.getToUserId()) && r.isDeliverable()) {
                out.add(r);
            }
        }
        return out;
    }

    /** What the sender may know. Declined and expired both read "No response." */
    public String senderView(String requestId, String senderUserId) {
        return hub.getMeetings().request(requestId)
                .filter(r -> r.getFromUserId().equals(senderUserId))
                .map(r -> {
                    r.expireIfDue(runtime.now());
                    return r.senderView();
                })
                .orElse(null);
    }

    public boolean respond(String requestId, String recipientUserId, boolean accept) {
        Instant now = runtime.now();
        Optional<MeetingRequest> found = hub.getMeetings().request(requestId);
        Membership to = member(recipientUserId);
        if (found.isEmpty() || to == null || !found.get().getToUserId().equals(recipientUserId)
                || !found.get().isDeliverable() || !to.can(Permission.RESPOND_TO_MEETING, hub.getStanding())) {
            return false;
        }
        boolean done = accept ? found.get().accept(now) : found.get().decline(now);
        if (done) {
            // "Answered", not which way: the log is readable by moderators,
            // and a decline is nobody's business.
            runtime.log(HubLog.EventType.MEETING_ANSWERED, recipientUserId, requestId, null, now);
        }
        return done;
    }

    /**
     * Books the meeting at the hub. Either party may propose the slot once the
     * request is accepted; there is no route to a meeting without acceptance,
     * and no field for a venue.
     */
    public Meeting schedule(String requestId, String byUserId, Instant when, int minutes, String space) {
        Instant now = runtime.now();
        Optional<MeetingRequest> request = hub.getMeetings().request(requestId);
        if (request.isEmpty() || request.get().getStatus() != MeetingRequest.Status.ACCEPTED
                || hub.getLocation() == null || !hub.getLocation().isSuitableForFirstMeeting(hub.getPolicy())
                || when == null || !when.isAfter(now)) {
            return null;
        }
        MeetingRequest r = request.get();
        if (!byUserId.equals(r.getFromUserId()) && !byUserId.equals(r.getToUserId())) {
            return null;
        }
        if (hub.getMeetings().isBlocked(r.getFromUserId(), r.getToUserId())) {
            return null;
        }
        Meeting meeting = hub.getMeetings().meetingForRequest(requestId)
                .orElseGet(() -> Meeting.fromAcceptedRequest(r, hub.getLocation().getLocationId()));
        if (meeting == null || !meeting.book(when, minutes, space, hub.getLocation())) {
            return null;
        }
        if (hub.getMeetings().meeting(meeting.getMeetingId()).isEmpty()) {
            hub.getMeetings().addMeeting(meeting);
        }
        runtime.log(HubLog.EventType.MEETING_SCHEDULED, byUserId, meeting.getMeetingId(), null, now);
        return meeting;
    }

    public boolean cancel(String meetingId, String byUserId) {
        return hub.getMeetings().meeting(meetingId).map(m -> m.cancel(byUserId)).orElse(false);
    }

    /** Flags a concern to moderators and blocks the pair. The concern text stays on the meeting, not in the log. */
    public boolean report(String meetingId, String byUserId, String concern) {
        Optional<Meeting> m = hub.getMeetings().meeting(meetingId);
        if (m.isEmpty() || !m.get().report(byUserId, concern)) {
            return false;
        }
        hub.getMeetings().block(m.get().getRequesterUserId(), m.get().getRecipientUserId());
        runtime.log(HubLog.EventType.MEETING_REPORTED, byUserId, meetingId, null, runtime.now());
        return true;
    }

    /** Held requests, for moderators with REVIEW_CENSOR_FLAG. Logged as a roster view. */
    public List<MeetingRequest> heldForReview(String moderatorUserId) {
        Membership mod = member(moderatorUserId);
        if (mod == null || !mod.can(Permission.REVIEW_CENSOR_FLAG, hub.getStanding())) {
            return List.of();
        }
        runtime.log(HubLog.EventType.ROSTER_VIEWED, moderatorUserId, null, "held-meeting-requests", runtime.now());
        List<MeetingRequest> out = new ArrayList<>();
        for (MeetingRequest r : hub.getMeetings().requests()) {
            if (r.isHeldForReview()) {
                out.add(r);
            }
        }
        return out;
    }

    /** A moderator releases or refuses a held request, with a reason. */
    public boolean decideHeld(String requestId, String moderatorUserId, CensorEngine.Decision decision,
                              String justification) {
        Membership mod = member(moderatorUserId);
        Optional<MeetingRequest> r = hub.getMeetings().request(requestId);
        if (mod == null || !mod.can(Permission.REVIEW_CENSOR_FLAG, hub.getStanding()) || r.isEmpty()
                || !r.get().isHeldForReview() || decision == CensorEngine.Decision.REVIEW
                || moderatorUserId.equals(r.get().getFromUserId()) || moderatorUserId.equals(r.get().getToUserId())) {
            return false;
        }
        Verdict decided;
        try {
            decided = new Verdict().overriddenBy(moderatorUserId, decision, justification);
        } catch (IllegalArgumentException e) {
            return false;
        }
        r.get().applyVerdict(decided, runtime.now());
        runtime.log(HubLog.EventType.CENSOR_HOLD_DECIDED, moderatorUserId, requestId, decision.name(), runtime.now());
        return true;
    }

    public boolean liftBlock(String moderatorUserId, String a, String b, String justification) {
        Membership mod = member(moderatorUserId);
        if (mod == null || !mod.can(Permission.REMOVE_MEMBER, hub.getStanding()) || justification == null
                || justification.isBlank() || !hub.getMeetings().unblock(a, b)) {
            return false;
        }
        runtime.log(HubLog.EventType.CONTACT_BLOCK_LIFTED, moderatorUserId, null, null, runtime.now());
        return true;
    }

    private Membership member(String userId) {
        return userId == null ? null : hub.getRoster().membershipOf(userId).orElse(null);
    }
}

package org.shalim.query;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * A hub's record of who may approach whom, and who did. Plain state, kept for
 * the meeting-request retention window and then dropped. {@link MeetingService}
 * holds the rules.
 *
 * <p>Three things are kept:
 * <ul>
 *   <li><b>Surfaced:</b> which members each query surfaced, and to whom. This
 *       is the provenance check behind "no cold contact".</li>
 *   <li><b>Requests and meetings</b>, for the retention window.</li>
 *   <li><b>Blocks</b> between pairs, from a reported meeting. These are the one
 *       record that outlives the fortnight, until a moderator lifts them: a
 *       block that lapsed after two weeks would let a reported person simply
 *       wait. On a seized device a block says that two people met and one
 *       reported it. That cost is accepted for safeguarding (README open
 *       question 28).</li>
 * </ul>
 */
public class MeetingBook {

    /** What one query surfaced, to whom. */
    public record Surfaced(String queryId, String askerUserId, Set<String> memberIds, Instant at) {
        public Surfaced {
            memberIds = Set.copyOf(memberIds);
        }
    }

    private final Map<String, Surfaced> surfaced = new HashMap<>();
    private final List<MeetingRequest> requests = new ArrayList<>();
    private final List<Meeting> meetings = new ArrayList<>();
    private final Set<String> blockedPairs = new HashSet<>();

    public synchronized void recordSurfaced(String queryId, String askerUserId, Set<String> memberIds, Instant at) {
        if (queryId != null && askerUserId != null && !memberIds.isEmpty()) {
            surfaced.put(queryId, new Surfaced(queryId, askerUserId, memberIds, at));
        }
    }

    /** Whether {@code queryId} was {@code asker}'s and surfaced {@code member}. */
    public synchronized boolean surfaced(String queryId, String asker, String member) {
        Surfaced s = surfaced.get(queryId);
        return s != null && s.askerUserId().equals(asker) && s.memberIds().contains(member);
    }

    public synchronized void addRequest(MeetingRequest request) {
        requests.add(request);
    }

    public synchronized Optional<MeetingRequest> request(String requestId) {
        return requests.stream().filter(r -> r.getRequestId().equals(requestId)).findFirst();
    }

    /** Any request from {@code from} to {@code to} still on record, whatever its state. */
    public synchronized boolean hasRequested(String from, String to) {
        return requests.stream().anyMatch(r -> from.equals(r.getFromUserId()) && to.equals(r.getToUserId())
                && (r.isScreened() || r.isHeldForReview()));
    }

    public synchronized List<MeetingRequest> requests() {
        return List.copyOf(requests);
    }

    public synchronized void addMeeting(Meeting meeting) {
        meetings.add(meeting);
    }

    public synchronized Optional<Meeting> meeting(String meetingId) {
        return meetings.stream().filter(m -> m.getMeetingId().equals(meetingId)).findFirst();
    }

    public synchronized Optional<Meeting> meetingForRequest(String requestId) {
        return meetings.stream().filter(m -> requestId.equals(m.getRequestId())).findFirst();
    }

    public synchronized List<Meeting> meetings() {
        return List.copyOf(meetings);
    }

    public synchronized void block(String a, String b) {
        blockedPairs.add(pair(a, b));
    }

    public synchronized boolean unblock(String a, String b) {
        return blockedPairs.remove(pair(a, b));
    }

    public synchronized boolean isBlocked(String a, String b) {
        return blockedPairs.contains(pair(a, b));
    }

    public synchronized Set<String> blockedPairs() {
        return Set.copyOf(blockedPairs);
    }

    private static String pair(String a, String b) {
        return a.compareTo(b) < 0 ? a + "|" + b : b + "|" + a;
    }

    /**
     * Drops surfaced records, requests and finished meetings older than the
     * window. A scheduled meeting still in the future is kept. A reported
     * meeting is kept for the window like any other; its block outlives it.
     */
    public synchronized int prune(int retentionDays, Instant now) {
        Instant cutoff = now.minus(Duration.ofDays(retentionDays));
        int before = surfaced.size() + requests.size() + meetings.size();
        surfaced.values().removeIf(s -> s.at().isBefore(cutoff));
        requests.removeIf(r -> {
            Instant t = r.getSentAt() != null ? r.getSentAt() : r.getRespondedAt();
            return t == null || t.isBefore(cutoff);
        });
        meetings.removeIf(m -> m.getStatus() != Meeting.Status.SCHEDULED
                ? m.getScheduledFor() == null || m.getScheduledFor().isBefore(cutoff)
                : m.getScheduledFor() != null && m.getScheduledFor().isBefore(cutoff));
        return before - (surfaced.size() + requests.size() + meetings.size());
    }

    /** Duress path. Blocks go too: a wiped device has nothing to enforce them with. */
    public synchronized void wipe() {
        surfaced.clear();
        requests.clear();
        meetings.clear();
        blockedPairs.clear();
    }

    public synchronized Map<String, Surfaced> allSurfaced() {
        return Map.copyOf(surfaced);
    }

    /** Restores persisted state. Persistence only. */
    public synchronized void restore(List<Surfaced> s, List<MeetingRequest> r, List<Meeting> m, Set<String> blocks) {
        surfaced.clear();
        for (Surfaced x : s) {
            surfaced.put(x.queryId(), x);
        }
        requests.clear();
        requests.addAll(r);
        meetings.clear();
        meetings.addAll(m);
        blockedPairs.clear();
        blockedPairs.addAll(blocks);
    }
}

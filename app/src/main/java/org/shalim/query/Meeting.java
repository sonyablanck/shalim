package org.shalim.query;

import java.time.Instant;

/**
 * A scheduled meeting between two members. Only ever created from an
 * {@link MeetingRequest.Status#ACCEPTED} request — there is no route to a
 * calendar entry without the recipient's explicit consent.
 *
 * <p>The venue is always the hub's own {@link org.shalim.hub.HubLocation}, and
 * is not caller-supplied, so no code path exists for proposing somewhere else.
 */
public class Meeting {

    public enum Status {
        SCHEDULED,
        CANCELLED,
        COMPLETED,
        /** Either party reported a problem; blocks further requests between them. */
        REPORTED
    }

    private String meetingId;
    private String hubId;
    private String requestId;

    private String requesterUserId;
    private String recipientUserId;

    /** Always the hub's location. Never set from user input. */
    private String locationId;

    /** Optional sub-area, chosen from the location's declared spaces. */
    private String meetingSpace;

    private Instant scheduledFor;
    private int durationMinutes;
    private Status status;

    /** Either party can cancel without giving a reason, at any time. */
    private String cancelledByUserId;

    /** Longest meeting the hub will book; first meetings should be short. */
    public static final int MAX_DURATION_MINUTES = 120;

    private String reportConcern;
    private String reportedByUserId;

    public Meeting() {
        this.meetingId = org.shalim.crypto.Bytes.randomId();
    }

    /** Only callable with an accepted request; venue is taken from the hub. */
    static Meeting fromAcceptedRequest(MeetingRequest request, String hubLocationId) {
        if (request == null || request.getStatus() != MeetingRequest.Status.ACCEPTED || hubLocationId == null) {
            return null;
        }
        Meeting m = new Meeting();
        m.hubId = request.getHubId();
        m.requestId = request.getRequestId();
        m.requesterUserId = request.getFromUserId();
        m.recipientUserId = request.getToUserId();
        m.locationId = hubLocationId;
        return m;
    }

    /** Sets the slot. Refused outside opening hours or at an undeclared space. */
    boolean book(Instant when, int minutes, String space, org.shalim.hub.HubLocation location) {
        if (when == null || minutes < 15 || minutes > MAX_DURATION_MINUTES || location == null
                || !location.getLocationId().equals(locationId)) {
            return false;
        }
        if (space != null && !location.getMeetingSpaces().contains(space)) {
            return false;
        }
        Instant previous = scheduledFor;
        int previousMinutes = durationMinutes;
        scheduledFor = when;
        durationMinutes = minutes;
        if (!isWithinOpeningHours(location)) {
            scheduledFor = previous;
            durationMinutes = previousMinutes;
            return false;
        }
        meetingSpace = space;
        status = Status.SCHEDULED;
        return true;
    }

    /**
     * Checks the whole slot is within the location's opening hours: the start,
     * the last minute, and every half hour between, so a slot cannot straddle
     * a closed lunch hour.
     */
    public boolean isWithinOpeningHours(org.shalim.hub.HubLocation location) {
        if (scheduledFor == null || location == null || durationMinutes <= 0) {
            return false;
        }
        for (int m = 0; m < durationMinutes; m += 30) {
            if (!location.isOpenAt(scheduledFor.plus(java.time.Duration.ofMinutes(m)))) {
                return false;
            }
        }
        return location.isOpenAt(scheduledFor.plus(java.time.Duration.ofMinutes(durationMinutes - 1L)));
    }

    /** Either party can cancel without giving a reason, at any time. */
    public boolean cancel(String byUserId) {
        if (status != Status.SCHEDULED || !isParty(byUserId)) {
            return false;
        }
        status = Status.CANCELLED;
        cancelledByUserId = byUserId;
        return true;
    }

    /**
     * Flags a safeguarding concern to moderators and blocks further contact.
     * Either party, at any point, including after the meeting.
     */
    public boolean report(String byUserId, String concern) {
        if (!isParty(byUserId) || status == Status.REPORTED) {
            return false;
        }
        status = Status.REPORTED;
        reportedByUserId = byUserId;
        reportConcern = concern;
        return true;
    }

    public boolean complete() {
        if (status != Status.SCHEDULED) {
            return false;
        }
        status = Status.COMPLETED;
        return true;
    }

    public boolean isParty(String userId) {
        return userId != null && (userId.equals(requesterUserId) || userId.equals(recipientUserId));
    }

    public String getHubId() {
        return hubId;
    }

    public String getRequestId() {
        return requestId;
    }

    public String getMeetingSpace() {
        return meetingSpace;
    }

    public int getDurationMinutes() {
        return durationMinutes;
    }

    public String getCancelledByUserId() {
        return cancelledByUserId;
    }

    /** Moderators only. */
    public String getReportConcern() {
        return reportConcern;
    }

    public String getReportedByUserId() {
        return reportedByUserId;
    }

    /** Restores persisted state. Persistence only. */
    public static Meeting restore(String id, String hubId, String requestId, String requester, String recipient,
                                  String locationId, String space, Instant when, int minutes, Status status,
                                  String cancelledBy, String reportedBy, String concern) {
        Meeting m = new Meeting();
        m.meetingId = id;
        m.hubId = hubId;
        m.requestId = requestId;
        m.requesterUserId = requester;
        m.recipientUserId = recipient;
        m.locationId = locationId;
        m.meetingSpace = space;
        m.scheduledFor = when;
        m.durationMinutes = minutes;
        m.status = status;
        m.cancelledByUserId = cancelledBy;
        m.reportedByUserId = reportedBy;
        m.reportConcern = concern;
        return m;
    }

    // --- accessors --------------------------------------------------------

    public String getMeetingId() {
        return meetingId;
    }

    public String getRequesterUserId() {
        return requesterUserId;
    }

    public String getRecipientUserId() {
        return recipientUserId;
    }

    public String getLocationId() {
        return locationId;
    }

    public Instant getScheduledFor() {
        return scheduledFor;
    }

    public Status getStatus() {
        return status;
    }
}

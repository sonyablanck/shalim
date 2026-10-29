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

    public Meeting() {
        // TODO: pseudo-code
    }

    /** Only callable with an accepted request; venue is taken from the hub. */
    static Meeting fromAcceptedRequest(MeetingRequest request, String hubLocationId) {
        // TODO: pseudo-code
        return null;
    }

    /** Checks the slot is within the location's opening hours. */
    public boolean isWithinOpeningHours(org.shalim.hub.HubLocation location) {
        // TODO: pseudo-code
        return false;
    }

    public boolean cancel(String byUserId) {
        // TODO: pseudo-code
        return false;
    }

    /** Flags a safeguarding concern to moderators and blocks further contact. */
    public boolean report(String byUserId, String concern) {
        // TODO: pseudo-code
        return false;
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

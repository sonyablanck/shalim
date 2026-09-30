package org.shalim.hub;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.shalim.identity.Membership;
import org.shalim.identity.Permission;
import org.shalim.identity.Role;

/**
 * The canonical live membership directory for a hub. This is the stateful home of
 * the roster invariant and the membership manipulations.
 */
public class Roster {

    private final List<Membership> memberships = new ArrayList<>();

    public void add(Membership membership) {
        if (membership == null) {
            return;
        }
        if (membershipOf(membership.getUserId()).isPresent()) {
            return;
        }
        memberships.add(membership);
    }

    public Optional<Membership> membershipOf(String userId) {
        if (userId == null || userId.isBlank()) {
            return Optional.empty();
        }
        return memberships.stream()
            .filter(m -> userId.equals(m.getUserId()))
            .findFirst();
    }

    public List<Membership> matchableMemberships() {
        List<Membership> result = new ArrayList<>();
        for (Membership membership : memberships) {
            if (membership.getVisibility() == null) {
                result.add(membership);
            } else if (membership.getVisibility() != Membership.Visibility.HIDDEN && !membership.isGuest()) {
                result.add(membership);
            }
        }
        return result;
    }

    public int adminCount() {
        int count = 0;
        for (Membership membership : memberships) {
            if (membership != null && membership.isAdmin()) {
                count++;
            }
        }
        return count;
    }

    public boolean canRelinquishAdmin(String userId) {
        if (userId == null || userId.isBlank()) {
            return false;
        }
        if (adminCount() > 1) {
            return true;
        }
        int otherMembers = 0;
        for (Membership membership : memberships) {
            if (!userId.equals(membership.getUserId())) {
                otherMembers++;
            }
        }
        return otherMembers == 0;
    }

    public boolean assignRole(String userId, Role newRole, String assignedByUserId) {
        Optional<Membership> subject = membershipOf(userId);
        Optional<Membership> actor = membershipOf(assignedByUserId);
        if (subject.isEmpty() || actor.isEmpty()) {
            return false;
        }
        if (!actor.get().can(Permission.ASSIGN_ROLE)) {
            return false;
        }
        subject.get().setRole(newRole, assignedByUserId);
        return true;
    }

    public boolean remove(String userId, String removedByUserId, String reason) {
        Optional<Membership> subject = membershipOf(userId);
        if (subject.isEmpty()) {
            return false;
        }
        Optional<Membership> actor = membershipOf(removedByUserId);
        if (actor.isPresent() && !actor.get().can(Permission.REMOVE_MEMBER)) {
            return false;
        }
        memberships.removeIf(m -> userId.equals(m.getUserId()));
        return true;
    }

    public List<Membership> moderatorRoster(String requestingUserId) {
        Optional<Membership> actor = membershipOf(requestingUserId);
        if (actor.isEmpty() || !actor.get().can(Permission.VIEW_MEMBERS)) {
            return List.of();
        }
        return new ArrayList<>(memberships);
    }

    public List<Membership> getMemberships() {
        return new ArrayList<>(memberships);
    }
}

package org.shalim.identity;

/**
 * Capabilities held within a single hub. Always evaluated through
 * {@link User#can(Permission, String)} so role, restrictions and deployment
 * policy are applied together.
 */
public enum Permission {

    // --- available to guests ---
    /** Choose which earned skills to show in this hub, and whether to be matched on them. */
    EDIT_OWN_SKILLS,
    /** Log use of a hub resource, which an admin may verify into an earned skill. */
    RECORD_RESOURCE_USE,
    /** Present skill credentials earned at other hubs, so this hub can match on them. */
    PRESENT_SKILL_CREDENTIALS,
    VIEW_HUB_PROFILE,
    /** Browse the hub's own resources (books, tools) without seeing people. */
    VIEW_HUB_RESOURCES,

    // --- members ---
    /** Ask Matchmaker to find people. The permission guests never get. */
    RUN_HUB_QUERY,
    VIEW_MEMBERS,
    REQUEST_MEETING,
    RESPOND_TO_MEETING,

    // --- moderators ---
    VIEW_LOG,
    INVITE_MEMBER,
    APPROVE_MEMBER,
    REMOVE_MEMBER,
    REVIEW_CENSOR_FLAG,

    // --- admins ---
    ASSIGN_ROLE,
    EDIT_HUB_PROFILE,
    EDIT_HUB_POLICY,
    MANAGE_MODEL_PINS,
    /** Verify a resource interaction and issue a skill credential for it. */
    VERIFY_EARNED_SKILL,
    /** Edit the hub's explicit resource list, which re-derives hub skills. */
    MANAGE_RESOURCES,
    /** Set up, suspend or appeal authentication links; send reciprocity invites. */
    MANAGE_AUTHENTICATION,
    MANAGE_TRANSPORTS,
    EXPORT_HUB
}

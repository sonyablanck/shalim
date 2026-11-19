package org.shalim.attestation;

import java.time.Instant;
import org.shalim.hub.HubPolicy;
import org.shalim.identity.Restriction;
import org.shalim.identity.Role;

/**
 * Receiving-hub side: decides what a presented proof — or a missing one — is
 * worth here.
 *
 * <p>The key judgement is what absence of proof costs. Treating "no proof" as
 * "presumed bad" makes the network unusable in exactly the conditions Shalim is
 * built for, since a blackout stops everyone refreshing. So absence caps a
 * member at guest <em>only where the hub's policy says so</em>, and only while
 * the hub believes refresh is actually possible.
 */
public class AttestationVerifier {

    private String hubId;
    private HubPolicy policy;

    /** Verdict for one presented proof, or its absence. */
    public enum Outcome {
        /** Valid, signed, from an accepted issuer, in date. */
        ACCEPTED,
        /** Signature or subject mismatch. Treat as hostile. */
        INVALID,
        /** Well-formed but lapsed. Common and usually benign. */
        EXPIRED,
        /** Issuer not in this hub's accepted set. Not an accusation. */
        UNTRUSTED_ISSUER,
        /** No proof presented at all. */
        ABSENT
    }

    /** Issuer key fingerprints this hub accepts proofs from: its trusted hubs' keys. */
    private java.util.List<String> acceptedIssuers;

    /** Looks up an issuer's public key by fingerprint, from cards and links this hub holds. */
    private transient java.util.function.Function<String, byte[]> issuerKeys;

    public AttestationVerifier() {
        this.acceptedIssuers = new java.util.ArrayList<>();
        this.issuerKeys = fp -> null;
    }

    public AttestationVerifier(String hubId, HubPolicy policy) {
        this();
        this.hubId = hubId;
        this.policy = policy;
    }

    /**
     * @param acceptedIssuers issuer key fingerprints of hubs this hub trusts.
     *                        The policy names trusted hubs by id; the runtime
     *                        maps them to keys from cards and links (stage 4/5).
     */
    public AttestationVerifier(String hubId, HubPolicy policy, java.util.List<String> acceptedIssuers,
                               java.util.function.Function<String, byte[]> issuerKeys) {
        this(hubId, policy);
        this.acceptedIssuers = new java.util.ArrayList<>(acceptedIssuers);
        this.issuerKeys = issuerKeys;
    }

    /** Checks signature, subject binding, validity window, and issuer trust. */
    public Outcome verify(Attestation attestation, String expectedSubject, Instant now) {
        if (attestation == null) {
            return Outcome.ABSENT;
        }
        // Binding check first: an otherwise valid proof for someone else is a
        // replay attempt, not an expiry.
        if (expectedSubject == null || !expectedSubject.equals(attestation.getSubjectKeyFingerprint())) {
            return Outcome.INVALID;
        }
        byte[] key = issuerKeys.apply(attestation.getIssuerKeyFingerprint());
        if (key == null) {
            // Unknown key: cannot check, and not an accusation.
            return Outcome.UNTRUSTED_ISSUER;
        }
        if (!attestation.verify(key)) {
            return Outcome.INVALID;
        }
        if (!attestation.isValid(now)) {
            return Outcome.EXPIRED;
        }
        if (!acceptedIssuers.contains(attestation.getIssuerKeyFingerprint())) {
            return Outcome.UNTRUSTED_ISSUER;
        }
        return Outcome.ACCEPTED;
    }

    /**
     * The restriction, if any, that this hub should apply given what the user
     * could show. Returns null when no cap is warranted.
     */
    public Restriction evaluate(AttestationWallet wallet, String membershipId,
                                boolean refreshPlausible, Instant now) {
        String subject = wallet == null ? null : wallet.getOwnerKeyFingerprint();

        // 1. ACTIVE OUTCOMES FIRST: the strongest signal, and the one that
        //    actually targets "radicaliser moves hub".
        java.util.Optional<Attestation> outcome = wallet == null ? java.util.Optional.empty()
                : wallet.present(Attestation.Claim.ACTIVE_MODERATION_OUTCOME, acceptedIssuers, now);
        if (outcome.isPresent() && verify(outcome.get(), subject, now) == Outcome.ACCEPTED) {
            return new Restriction(membershipId, Restriction.Reason.MODERATION_ACTION, Restriction.Scope.FEDERATED,
                    Role.GUEST)
                    .appliedAt(now)
                    .expiring(outcome.get().getExpiresAt())
                    .explained("Another hub you belong to has an active moderation decision about you.");
        }

        // 2. GOOD STANDING. Most hubs should leave this off: requiring proof is
        //    a meaningful cost to people with patchy connectivity.
        if (policy == null || !policy.isRequireGoodStanding()) {
            return null;
        }
        Attestation proof = wallet == null ? null
                : wallet.present(Attestation.Claim.GOOD_STANDING, acceptedIssuers, now).orElse(null);
        Outcome result = verify(proof, subject, now);
        if (result == Outcome.ACCEPTED) {
            return null;
        }
        if ((result == Outcome.EXPIRED || result == Outcome.ABSENT) && !refreshPlausible) {
            // THE IMPORTANT CASE. During a blackout nobody can refresh, so
            // treating absence as guilt would silence a whole hub exactly when
            // it is most needed. Fail open; the censor and moderation outcomes
            // still apply.
            return null;
        }
        if (result == Outcome.INVALID) {
            // Forged proof is a deliberate act; a human should look.
            return new Restriction(membershipId, Restriction.Reason.MODERATION_ACTION, Restriction.Scope.THIS_HUB,
                    Role.GUEST)
                    .appliedAt(now)
                    .explained("The proof of good standing you presented did not check out."
                            + " A moderator will look at it.");
        }
        // No originHubId: this hub does not know which hub failed, only that no
        // valid proof exists. Re-evaluating when a fresh proof appears lifts it.
        return new Restriction(membershipId, Restriction.Reason.COMPROMISED_CENSOR, Restriction.Scope.FEDERATED,
                Role.GUEST)
                .appliedAt(now)
                .dischargedBy(Restriction.Discharge.LEAVE_ORIGIN_HUB)
                .explained("A hub you belong to cannot currently vouch for you. This lifts when it is fixed,"
                        + " or if you leave that hub.");
    }

    /** Highest role this hub will grant given the proofs on offer. */
    public Role permittedRole(AttestationWallet wallet, Role requestedRole,
                              boolean refreshPlausible, Instant now) {
        Restriction cap = evaluate(wallet, null, refreshPlausible, now);
        Role role = requestedRole == null ? Role.MEMBER : requestedRole;
        return cap == null ? role : role.cappedAt(cap.getRoleCap());
    }

    public java.util.List<String> getAcceptedIssuers() {
        return java.util.List.copyOf(acceptedIssuers);
    }
}

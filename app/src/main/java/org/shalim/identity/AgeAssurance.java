package org.shalim.identity;

import java.time.Instant;

/**
 * Records whether a user has been assured to be an adult, without recording
 * who they are.
 *
 * <p>Deliberately stores a boolean and a method, never a date of birth, name,
 * or document image. Age assurance and protection from a hostile state pull in
 * opposite directions: anything that proves your age also identifies you. So
 * this class holds the minimum that satisfies a UK-style duty, and whether it
 * is demanded at all is a per-deployment decision in {@code HubPolicy} rather
 * than a global default.
 */
public class AgeAssurance {

    public enum Method {
        /** Not attempted. On a non-age-gated deployment this is the norm. */
        NONE,
        /** User asserted adulthood. Weak, but leaves no data trail. */
        SELF_DECLARED,
        /** An existing adult member vouched. Keeps verification inside the community. */
        VOUCHED_BY_MEMBER,
        /** On-device estimation. No image retained. */
        ON_DEVICE_ESTIMATION,
        /** Third-party attestation returning only a yes/no. */
        EXTERNAL_ATTESTATION
    }

    private Method method;
    private boolean assuredAdult;
    private Instant assuredAt;

    /** Opaque token from the attestation provider. Must not be linkable to an identity. */
    private String attestationRef;

    /**
     * How long an assurance lasts before it must be renewed. Self-declaration
     * lapses soonest, because it is cheapest to make. A child who declared
     * themselves an adult at twelve should not still be "assured" at fifteen.
     */
    public static java.time.Duration validityOf(Method method) {
        return switch (method) {
            case NONE -> java.time.Duration.ZERO;
            case SELF_DECLARED -> java.time.Duration.ofDays(90);
            case VOUCHED_BY_MEMBER -> java.time.Duration.ofDays(365);
            case ON_DEVICE_ESTIMATION, EXTERNAL_ATTESTATION -> java.time.Duration.ofDays(730);
        };
    }

    public AgeAssurance() {
        this.method = Method.NONE;
        this.assuredAdult = false;
    }

    public AgeAssurance(Method method, boolean assuredAdult) {
        this(method, assuredAdult, Instant.now(), null);
    }

    public AgeAssurance(Method method, boolean assuredAdult, Instant assuredAt, String attestationRef) {
        this.method = method == null ? Method.NONE : method;
        this.assuredAdult = assuredAdult && this.method != Method.NONE;
        this.assuredAt = assuredAt;
        this.attestationRef = attestationRef;
    }

    /** Assurance can lapse so a minor's account does not stay unassured forever. */
    public boolean isValid(Instant now) {
        return assuredAdult && assuredAt != null && method != Method.NONE
                && !now.isBefore(assuredAt) && now.isBefore(assuredAt.plus(validityOf(method)));
    }

    /**
     * Strength ordering, so a policy can demand better than self-declaration.
     * The enum's order is the strength order.
     */
    public boolean satisfies(Method minimumMethod) {
        return assuredAdult && method != Method.NONE
                && (minimumMethod == null || method.compareTo(minimumMethod) >= 0);
    }

    public String getAttestationRef() {
        return attestationRef;
    }

    public Method getMethod() {
        return method;
    }

    public boolean isAssuredAdult() {
        return assuredAdult;
    }

    public Instant getAssuredAt() {
        return assuredAt;
    }
}

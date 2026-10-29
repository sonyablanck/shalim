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

    public AgeAssurance() {
        // TODO: pseudo-code
    }

    public AgeAssurance(Method method, boolean assuredAdult) {
        // TODO: pseudo-code
    }

    /** Assurance can lapse so a minor's account does not stay unassured forever. */
    public boolean isValid(Instant now) {
        // TODO: pseudo-code
        return false;
    }

    /** Strength ordering, so a policy can demand better than self-declaration. */
    public boolean satisfies(Method minimumMethod) {
        // TODO: pseudo-code
        return false;
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

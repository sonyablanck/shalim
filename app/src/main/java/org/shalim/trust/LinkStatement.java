package org.shalim.trust;

import java.time.Duration;
import java.time.Instant;
import org.shalim.crypto.Canonical;
import org.shalim.crypto.Ed25519;
import org.shalim.crypto.Signer;

/**
 * The authenticating hub's signed word to the target about one link: its
 * state, and until when that holds. How a target learns that it has an
 * inbound link that counts, which is what unlocks it (inbound only, decided 18
 * November 2026).
 *
 * <p>Short-lived and re-issued on each daily run, like a bond. A statement
 * that simply expires means nothing has been heard (a blackout looks exactly
 * like this) and the link stops counting without being treated as revoked, so
 * the target fails open. A statement that says REVOKED is the one thing a
 * revocation tells the peer: no findings, no evidence, no probe texts.
 * Disclosure of findings stays manual ({@link PeerAuditor#disclose}).
 */
public final class LinkStatement {

    public static final Duration TTL = Duration.ofDays(3);

    private final String authenticatorKeyFingerprint;
    private final String subjectKeyFingerprint;
    private final String linkPseudonym;
    private final AuthLink.State state;
    private final Instant issuedAt;
    private final Instant expiresAt;
    private final String signature;

    private LinkStatement(String authenticator, String subject, String pseudonym, AuthLink.State state,
                          Instant issuedAt, Instant expiresAt, String signature) {
        this.authenticatorKeyFingerprint = authenticator;
        this.subjectKeyFingerprint = subject;
        this.linkPseudonym = pseudonym;
        this.state = state;
        this.issuedAt = issuedAt;
        this.expiresAt = expiresAt;
        this.signature = signature;
    }

    static LinkStatement issue(Signer authenticatorKey, AuthLink link, Instant now) {
        String a = authenticatorKey.fingerprint();
        Instant exp = link.getState() == AuthLink.State.REVOKED ? now.plus(Duration.ofDays(365)) : now.plus(TTL);
        String sig = authenticatorKey.signHex(payload(a, link.getSubjectKeyFingerprint(), link.getLinkPseudonym(),
                link.getState(), now, exp));
        return new LinkStatement(a, link.getSubjectKeyFingerprint(), link.getLinkPseudonym(), link.getState(), now,
                exp, sig);
    }

    /** A statement as the target receives it. */
    public static LinkStatement received(String authenticator, String subject, String pseudonym, AuthLink.State state,
                                         Instant issuedAt, Instant expiresAt, String signature) {
        return new LinkStatement(authenticator, subject, pseudonym, state, issuedAt, expiresAt, signature);
    }

    private static byte[] payload(String a, String s, String p, AuthLink.State st, Instant at, Instant exp) {
        return Canonical.of("shalim.link.statement.v1").hex(a).hex(s).string(p).enumName(st).instant(at)
                .instant(exp).encode();
    }

    public boolean verify(byte[] authenticatorPublicKey) {
        return authenticatorPublicKey != null && Ed25519.verifyHex(authenticatorPublicKey,
                payload(authenticatorKeyFingerprint, subjectKeyFingerprint, linkPseudonym, state, issuedAt, expiresAt),
                signature);
    }

    public boolean isCurrent(Instant now) {
        return !now.isBefore(issuedAt.minus(Duration.ofMinutes(10))) && now.isBefore(expiresAt);
    }

    public String getAuthenticatorKeyFingerprint() {
        return authenticatorKeyFingerprint;
    }

    public String getSubjectKeyFingerprint() {
        return subjectKeyFingerprint;
    }

    public String getLinkPseudonym() {
        return linkPseudonym;
    }

    public AuthLink.State getState() {
        return state;
    }

    public Instant getIssuedAt() {
        return issuedAt;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }
}

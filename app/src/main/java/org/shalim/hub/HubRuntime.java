package org.shalim.hub;

import org.shalim.attestation.AttestationIssuer;
import org.shalim.attestation.AttestationVerifier;
import org.shalim.ml.CensorEngine;
import org.shalim.ml.MatchmakerEngine;
import org.shalim.ml.ProbeEngine;
import org.shalim.trust.PeerAuditor;

/**
 * Runtime services constructed at startup. The hub state stays serialisable; the
 * runtime is the process-local machinery that runs on top of it.
 *
 * <p>A hub instance is not a user account. It holds the hub's issuer key, and
 * may run on the same device as its admin's account or a different one — an
 * admin's phone holding their account and a desktop running the hub is the
 * expected arrangement. {@link org.shalim.identity.DeviceBinding} limits
 * accounts per device, not hub instances.
 */
public class HubRuntime {

    private final Hub hub;
    private final CensorEngine censor;
    private final MatchmakerEngine matchmaker;
    private final AttestationIssuer issuer;
    private final AttestationVerifier verifier;
    private final PeerAuditor auditor;

    /**
     * Third model: writes synthetic PASS-side probes and scores peers'
     * answers. Replay of peers' censor decisions uses {@link #censor} directly.
     */
    private final ProbeEngine prober;

    public HubRuntime(Hub hub, CensorEngine censor, MatchmakerEngine matchmaker,
                      AttestationIssuer issuer, AttestationVerifier verifier, PeerAuditor auditor) {
        this(hub, censor, matchmaker, issuer, verifier, auditor, null);
    }

    public HubRuntime(Hub hub, CensorEngine censor, MatchmakerEngine matchmaker,
                      AttestationIssuer issuer, AttestationVerifier verifier, PeerAuditor auditor,
                      ProbeEngine prober) {
        this.hub = hub;
        this.censor = censor;
        this.matchmaker = matchmaker;
        this.issuer = issuer;
        this.verifier = verifier;
        this.auditor = auditor;
        this.prober = prober;
    }

    /** The hub's issuer key: signs log entries, censor-log heads, receipts and attestations. */
    private org.shalim.crypto.Signer hubKey;

    /** Key for plaintext at rest (censor-log texts, the store). Held only here. */
    private byte[] atRestKey;

    /**
     * Fallback screen for {@link HubPolicy.CensorFailureMode#BLOCKLIST_ONLY}:
     * a bundled list, weaker than the model, used only while the model is
     * unavailable and only if policy says so.
     */
    private CensorEngine blocklist;

    /** Null until a ring-signature scheme is chosen; see SkillCredentialScheme. */
    private org.shalim.skills.SkillCredentialScheme credentialScheme;

    /** Current and recent issuer rings, from cards held (stage 5). */
    private java.util.function.Supplier<java.util.List<java.util.List<byte[]>>> rings = java.util.List::of;

    private java.time.Clock clock = java.time.Clock.systemUTC();

    /**
     * The same engines, keys and settings, bound to another hub. Used at
     * creation, when the runtime exists before the hub does.
     */
    public HubRuntime forHub(Hub other) {
        HubRuntime r = new HubRuntime(other, censor, matchmaker, issuer, verifier, auditor, prober);
        r.hubKey = hubKey;
        r.atRestKey = atRestKey == null ? null : atRestKey.clone();
        r.blocklist = blocklist;
        r.credentialScheme = credentialScheme;
        r.rings = rings;
        r.clock = clock;
        return r;
    }

    public HubRuntime withKeys(org.shalim.crypto.Signer hubKey, byte[] atRestKey) {
        this.hubKey = hubKey;
        this.atRestKey = atRestKey == null ? null : atRestKey.clone();
        return this;
    }

    public HubRuntime withBlocklist(CensorEngine blocklist) {
        this.blocklist = blocklist;
        return this;
    }

    public HubRuntime withCredentials(org.shalim.skills.SkillCredentialScheme scheme,
                                      java.util.function.Supplier<java.util.List<java.util.List<byte[]>>> rings) {
        this.credentialScheme = scheme;
        this.rings = rings == null ? java.util.List::of : rings;
        return this;
    }

    public HubRuntime withClock(java.time.Clock clock) {
        this.clock = clock;
        return this;
    }

    public org.shalim.crypto.Signer getHubKey() {
        return hubKey;
    }

    /** Package-private: only hub services read the at-rest key. */
    byte[] atRestKey() {
        return atRestKey;
    }

    /**
     * Commits one screening to the hub's censor decision log and returns the
     * receipt. The at-rest key never leaves this class. Throws if the hub has
     * no key or no log: an unloggable screening is refused, never skipped.
     */
    public CensorDecisionLog.Receipt commitScreening(String text, org.shalim.ml.Verdict verdict,
                                                     CensorEngine.Surface surface, String action,
                                                     java.time.Instant now) {
        if (hubKey == null || atRestKey == null || hub.getCensorLog() == null) {
            throw new IllegalStateException("this hub cannot log screenings");
        }
        return hub.getCensorLog().append(text, verdict, surface, action, hubKey, atRestKey, now);
    }

    /**
     * Opens sampled censor-log leaves for an auditing hub, sealed to its
     * encryption key. The at-rest key never leaves this class. Meeting
     * requests are included as policy says (on at every hub since 19 November
     * 2026). Choosing and checking the indices is the caller's job.
     */
    public java.util.List<CensorDecisionLog.Opening> openForAuditor(java.time.LocalDate day,
                                                                   java.util.List<Long> indices,
                                                                   byte[] auditorEncryptionKey) {
        if (atRestKey == null || hub.getCensorLog() == null) {
            return java.util.List.of();
        }
        return hub.getCensorLog().open(day, indices, auditorEncryptionKey, atRestKey,
                hub.getPolicy() == null || hub.getPolicy().isReplayMeetingRequests());
    }

    /** Appends to the hub log under the hub key. A no-op without a key, for tools that only read. */
    public void log(HubLog.EventType type, String actor, String subject, String detail, java.time.Instant now) {
        if (hubKey != null && hub.getLog() != null) {
            hub.getLog().append(type, actor, subject, detail, hubKey, now);
        }
    }

    public CensorEngine getBlocklist() {
        return blocklist;
    }

    public org.shalim.skills.SkillCredentialScheme getCredentialScheme() {
        return credentialScheme;
    }

    public java.util.List<java.util.List<byte[]>> currentRings() {
        return rings.get();
    }

    public java.time.Instant now() {
        return clock.instant();
    }

    public java.time.Clock getClock() {
        return clock;
    }

    public Hub getHub() {
        return hub;
    }

    public CensorEngine getCensor() {
        return censor;
    }

    public MatchmakerEngine getMatchmaker() {
        return matchmaker;
    }

    public AttestationIssuer getIssuer() {
        return issuer;
    }

    public AttestationVerifier getVerifier() {
        return verifier;
    }

    public PeerAuditor getAuditor() {
        return auditor;
    }

    public ProbeEngine getProber() {
        return prober;
    }

    public boolean queriesEnabled() {
        return censor != null && matchmaker != null;
    }
}

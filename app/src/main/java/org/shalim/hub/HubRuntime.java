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

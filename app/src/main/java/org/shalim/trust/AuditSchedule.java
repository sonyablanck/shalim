package org.shalim.trust;

import java.time.Instant;

/**
 * Per-hub configuration for authentication probing, and the rules that pick
 * how each link is probed.
 *
 * <h2>Three evidence streams, not one daily pair</h2>
 *
 * <ol>
 *   <li><strong>Replay</strong> ({@link ReplayAuditor}) — every link, every
 *       day the peer's head arrives. Tests the censor, including
 *       under-blocking, on real traffic. Sends nothing that looks like a
 *       question.</li>
 *   <li><strong>Organic</strong> ({@link OrganicProbe}) — the prober's own
 *       real questions, shadow-screened on their device. Tests that the peer
 *       logs everything and treats members as its log says.</li>
 *   <li><strong>Synthetic</strong> — generated PASS-side probes (benign,
 *       protected speech, near-miss) at a Poisson-distributed rate scaled to
 *       the peer's traffic. Tests over-blocking of protected speech, which
 *       a prober's own questions rarely touch. Never supply requests.</li>
 * </ol>
 *
 * <p>The old floor — at least one expected-pass and one expected-fail probe
 * every day — is gone. A fixed daily cadence is a signature, and in a quiet
 * hub it is the loudest thing in the log. The nullifier limits a prober to
 * <em>at most</em> one presentation per day; nothing requires one.
 *
 * <h2>Modes</h2>
 *
 * <p>{@link Mode#FULL} runs all three streams. {@link Mode#REPLAY_ONLY} runs
 * replay alone, and applies when the peer is too quiet for synthetic probes
 * to hide in, or has too few ordinary members for the prober to be
 * anonymous. A hub cannot be probed without standing out, but its decision
 * log still exists.
 */
public class AuditSchedule {

    public enum Mode {
        FULL,
        REPLAY_ONLY
    }

    private boolean enabled;

    // --- replay -----------------------------------------------------------

    /** Leaves opened per peer per day. */
    private int replaySampleSize;

    /**
     * Leaves opened per peer per week when the peer is below
     * {@link #minProberAnonymitySet}. In a hub of six people a sampled question
     * may identify its author whatever the protocol says, so fewer are read.
     */
    private int smallHubReplaySamplesPerWeek;

    // --- synthetic --------------------------------------------------------

    /**
     * Synthetic probes as a fraction of the peer's daily traffic, used as the
     * Poisson mean. Small, so probes stay a minority of what the peer sees.
     */
    private double syntheticShareOfTraffic;

    /** Upper bound on synthetic probes per day, however busy the peer. */
    private double maxSyntheticPerDay;

    /**
     * Below this traffic band (padded daily leaves / PAD_MULTIPLE), synthetic
     * and organic probing stop and the link runs REPLAY_ONLY.
     */
    private int minTrafficBandForProbing;

    // --- prober anonymity -------------------------------------------------

    /**
     * Ordinary, attested members old enough to present, below which a
     * prober's anonymity is nominal. The link then runs REPLAY_ONLY.
     */
    private int minProberAnonymitySet;

    /** Days a prober must have been a member before presenting. */
    private int minProberMembershipDays;

    // --- window -----------------------------------------------------------

    /** Scoreable replayed leaves needed in a window before a link may change state. */
    private int minReplayLeaves;

    /** Scoreable PASS-side probes (synthetic or organic) needed before over-blocking can be judged. */
    private int minPassProbes;

    /** Days a link stays SUSPENDED, on fresh evidence, before it can be revoked. */
    private int suspensionDays;

    /** Days without scoreable evidence before an ACTIVE link goes DORMANT. */
    private int dormancyDays;

    /**
     * Whether synthetic probes may go over metered or observable transports.
     * Replay heads and openings ride ordinary sync and are not affected.
     */
    private boolean auditOverObservableTransports;

    private Instant lastRunAt;

    public AuditSchedule() {
        // TODO: pseudo-code
    }

    /** Defaults matching a posture. */
    public static AuditSchedule defaultsFor(org.shalim.hub.HubPolicy.Posture posture) {
        // PSEUDO-CODE
        // INSTITUTIONAL -> replay 8/day; synthetic 2% of traffic, max 3/day;
        //                  min band 2; anonymity set 8; membership 14d;
        //                  window min 40 leaves + 10 PASS; suspension 7d; dormancy 7d
        // COMMUNITY     -> as INSTITUTIONAL
        // HIGH_RISK     -> replay 4/day, openings batched weekly over sync;
        //                  synthetic OFF; organic ON; anonymity set 12;
        //                  never over an observable transport; dormancy 21d
        //    // The regular daily rhythm that made HIGH_RISK the worst fit is
        //    // gone: replay rides sync that happens anyway, organic probes are
        //    // questions the prober was asking regardless, and no synthetic
        //    // traffic is generated at all.
        return null;
    }

    /**
     * How one link runs, decided from what the peer publishes: its traffic
     * band (from its signed head) and whether the prober's eligibility check
     * returned ANONYMITY_SET_TOO_SMALL.
     */
    public Mode modeFor(int peerTrafficBand, ProberEligibility.Result eligibility) {
        // PSEUDO-CODE
        // IF eligibility == ANONYMITY_SET_TOO_SMALL -> RETURN REPLAY_ONLY
        // IF peerTrafficBand < minTrafficBandForProbing -> RETURN REPLAY_ONLY
        // RETURN FULL
        //    // A peer that under-reports its traffic to avoid synthetic probes
        //    // still gets replay and organic checks, and replay would expose
        //    // the under-report: the head's size is what it is.
        return null;
    }

    /**
     * Poisson mean for synthetic probes against one peer today. Scales with
     * the peer's traffic so probes stay a small, steady share of it.
     */
    public double syntheticRatePerDay(int peerTrafficBand) {
        // PSEUDO-CODE
        // approxDaily = peerTrafficBand * CensorDecisionLog.PAD_MULTIPLE
        // RETURN min(maxSyntheticPerDay, syntheticShareOfTraffic * approxDaily)
        return 0.0;
    }

    /**
     * Next synthetic send time. Exponential inter-arrival times give a
     * Poisson process: no fixed hour, no fixed count, and zero probes on some
     * days, like any member.
     */
    public Instant nextSyntheticAt(Instant after, double ratePerDay, java.util.random.RandomGenerator rng) {
        // PSEUDO-CODE
        // IF ratePerDay <= 0 -> RETURN null
        // gapDays = -ln(1 - rng.nextDouble()) / ratePerDay
        // candidate = after + gapDays
        // IF candidate falls outside the prober's own usual active hours
        //    -> shift into them, preserving the gap distribution within the day
        //    // A probe at 03:00 from someone who is never on at 03:00 is a tell.
        // RETURN candidate
        return null;
    }

    /** Whether a synthetic probe may go over this transport. */
    public boolean permits(org.shalim.transport.Transport transport) {
        // PSEUDO-CODE
        // IF NOT enabled -> RETURN false
        // IF transport.isObservable() AND NOT auditOverObservableTransports
        //    RETURN false
        // RETURN true
        return false;
    }

    // --- accessors --------------------------------------------------------

    public boolean isEnabled() {
        return enabled;
    }

    public int getReplaySampleSize() {
        return replaySampleSize;
    }

    public int getSmallHubReplaySamplesPerWeek() {
        return smallHubReplaySamplesPerWeek;
    }

    public double getSyntheticShareOfTraffic() {
        return syntheticShareOfTraffic;
    }

    public double getMaxSyntheticPerDay() {
        return maxSyntheticPerDay;
    }

    public int getMinTrafficBandForProbing() {
        return minTrafficBandForProbing;
    }

    public int getMinProberAnonymitySet() {
        return minProberAnonymitySet;
    }

    public int getMinProberMembershipDays() {
        return minProberMembershipDays;
    }

    public int getMinReplayLeaves() {
        return minReplayLeaves;
    }

    public int getMinPassProbes() {
        return minPassProbes;
    }

    public int getSuspensionDays() {
        return suspensionDays;
    }

    public int getDormancyDays() {
        return dormancyDays;
    }

    public Instant getLastRunAt() {
        return lastRunAt;
    }
}

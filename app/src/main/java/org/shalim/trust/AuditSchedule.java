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

    /**
     * Real (non-pad) leaves replayed per peer per fortnight. Decided 19
     * November 2026: a fixed count, not a percentage, because detection
     * depends on how many decisions are checked, not what share. 30 leaves
     * catch a censor falsifying 10% of its decisions about 96% of the time,
     * and 5% about 79%, at any hub size.
     */
    private int replayLeavesPerFortnight;

    /** Most leaves opened for one peer in one day, pads included. Bounds a quiet hub's cost. */
    private int maxReplayDrawPerDay;

    /** HIGH_RISK: openings are requested once a week over ordinary sync, not daily. */
    private boolean replayBatchedWeekly;

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

    /** Fortnight length the replay budget is counted over. */
    public static final int FORTNIGHT_DAYS = 14;

    /** Baseline rate at which an honest censor blocks a PASS-side probe; the null hypothesis. */
    private double overBlockBaseline;

    public AuditSchedule() {
        this.enabled = true;
        this.replayLeavesPerFortnight = 30;
        this.maxReplayDrawPerDay = 16;
        this.smallHubReplaySamplesPerWeek = 6;
        this.syntheticShareOfTraffic = 0.02;
        this.maxSyntheticPerDay = 3;
        this.minTrafficBandForProbing = 2;
        this.minProberAnonymitySet = 8;
        this.minProberMembershipDays = 14;
        this.minReplayLeaves = 20;
        this.minPassProbes = 10;
        this.suspensionDays = 7;
        this.dormancyDays = 7;
        this.auditOverObservableTransports = true;
        this.overBlockBaseline = 0.02;
    }

    /** Defaults matching a posture. */
    public static AuditSchedule defaultsFor(org.shalim.hub.HubPolicy.Posture posture) {
        AuditSchedule s = new AuditSchedule();
        if (posture == org.shalim.hub.HubPolicy.Posture.HIGH_RISK) {
            // Posture changes how a hub is audited, never whether (decided 19
            // November 2026). Same replay budget, batched over sync that
            // happens anyway; organic on; no synthetic traffic at all.
            s.replayBatchedWeekly = true;
            s.syntheticShareOfTraffic = 0;
            s.maxSyntheticPerDay = 0;
            s.minProberAnonymitySet = 12;
            s.auditOverObservableTransports = false;
            s.dormancyDays = 21;
        }
        return s;
    }

    /**
     * How one link runs, decided from what the peer publishes: its traffic
     * band (from its signed head) and whether the prober's eligibility check
     * returned ANONYMITY_SET_TOO_SMALL.
     */
    public Mode modeFor(int peerTrafficBand, ProberEligibility.Result eligibility) {
        if (eligibility == ProberEligibility.Result.ANONYMITY_SET_TOO_SMALL) {
            return Mode.REPLAY_ONLY;
        }
        if (peerTrafficBand < minTrafficBandForProbing) {
            return Mode.REPLAY_ONLY;
        }
        // A peer that under-reports its traffic to avoid synthetic probes still
        // gets replay and organic checks, and the head's size is what it is.
        return Mode.FULL;
    }

    /**
     * Poisson mean for synthetic probes against one peer today. Scales with
     * the peer's traffic so probes stay a small, steady share of it.
     */
    public double syntheticRatePerDay(int peerTrafficBand) {
        double approxDaily = peerTrafficBand * (double) org.shalim.hub.CensorDecisionLog.PAD_MULTIPLE;
        return Math.min(maxSyntheticPerDay, syntheticShareOfTraffic * approxDaily);
    }

    /**
     * Next synthetic send time. Exponential inter-arrival times give a
     * Poisson process: no fixed hour, no fixed count, and zero probes on some
     * days, like any member.
     */
    public Instant nextSyntheticAt(Instant after, double ratePerDay, java.util.random.RandomGenerator rng) {
        return nextSyntheticAt(after, ratePerDay, rng, null);
    }

    /**
     * The prober's own usual active hours, in their zone. A window that wraps
     * midnight ({@code from} after {@code to}) is allowed.
     */
    public record ActiveHours(java.time.LocalTime from, java.time.LocalTime to, java.time.ZoneId zone) {
        long activeSecondsPerDay() {
            long f = from.toSecondOfDay();
            long t = to.toSecondOfDay();
            return t > f ? t - f : 86_400 - f + t;
        }

        boolean contains(Instant i) {
            java.time.LocalTime t = java.time.LocalTime.ofInstant(i, zone);
            return from.isBefore(to) ? !t.isBefore(from) && t.isBefore(to) : !t.isBefore(from) || t.isBefore(to);
        }
    }

    /**
     * Next synthetic send time, kept inside the prober's active hours. The gap
     * is drawn in <em>active</em> time and then laid over the active windows,
     * so the daily rate is unchanged and the distribution within the day
     * follows the prober's own pattern: a probe at 03:00 from someone who is
     * never on at 03:00 would be a tell.
     */
    public Instant nextSyntheticAt(Instant after, double ratePerDay, java.util.random.RandomGenerator rng,
                                   ActiveHours hours) {
        if (ratePerDay <= 0 || after == null) {
            return null;
        }
        double gapDays = -Math.log(1 - rng.nextDouble()) / ratePerDay;
        if (hours == null) {
            return after.plusMillis((long) (gapDays * 86_400_000d));
        }
        long remaining = (long) (gapDays * hours.activeSecondsPerDay());
        Instant t = after;
        // Walk forward minute by minute through inactive time, and consume the
        // gap only while active. Bounded: at most a few days of minutes.
        int guard = 0;
        while (guard++ < 60 * 24 * 400) {
            if (hours.contains(t)) {
                if (remaining < 60) {
                    return t.plusSeconds(remaining);
                }
                remaining -= 60;
            }
            t = t.plusSeconds(60);
        }
        return t;
    }

    /**
     * How many leaves to open for one peer today. The budget is in
     * <em>real</em> leaves, but a head is padded and a sampled index may land
     * on a pad, so the draw is scaled by the share of real leaves seen in
     * earlier openings, capped per day. A quiet hub's draws are mostly pads,
     * which is the price of its traffic being hidden.
     *
     * @param dayInFortnight 0..13, counted from the link's nonce chain start
     * @param realSoFar      real leaves already scored this fortnight
     * @param realFraction   observed share of real leaves among opened ones, 0..1
     * @param smallHub       the peer's anonymity set is below the minimum
     */
    public int replayDraw(int dayInFortnight, int realSoFar, double realFraction, boolean smallHub) {
        int budget = smallHub ? 2 * smallHubReplaySamplesPerWeek : replayLeavesPerFortnight;
        int remaining = Math.max(0, budget - realSoFar);
        if (remaining == 0) {
            return 0;
        }
        int daysLeft = Math.max(1, FORTNIGHT_DAYS - dayInFortnight);
        double wantReal = remaining / (double) daysLeft;
        double share = Math.max(1.0 / org.shalim.hub.CensorDecisionLog.PAD_MULTIPLE, Math.min(1.0, realFraction));
        int draw = (int) Math.ceil(wantReal / share);
        return Math.max(1, Math.min(maxReplayDrawPerDay, draw));
    }

    /**
     * Scoreable real leaves a window needs before a link may change state.
     * Lower for small hubs, whose budget is lower.
     */
    public int minReplayLeavesFor(boolean smallHub) {
        return smallHub ? Math.min(minReplayLeaves, smallHubReplaySamplesPerWeek) : minReplayLeaves;
    }

    /** Whether a synthetic probe may go over this transport. */
    public boolean permits(org.shalim.transport.Transport transport) {
        return enabled && transport != null
                && (!transport.isObservable() || auditOverObservableTransports);
    }

    // --- accessors --------------------------------------------------------

    public boolean isEnabled() {
        return enabled;
    }

    public int getReplayLeavesPerFortnight() {
        return replayLeavesPerFortnight;
    }

    public int getMaxReplayDrawPerDay() {
        return maxReplayDrawPerDay;
    }

    public boolean isReplayBatchedWeekly() {
        return replayBatchedWeekly;
    }

    public double getOverBlockBaseline() {
        return overBlockBaseline;
    }

    public boolean isAuditOverObservableTransports() {
        return auditOverObservableTransports;
    }

    /** Test and admin tuning. Applied through policy changes, which are logged. */
    public AuditSchedule withWindow(int minReplayLeaves, int minPassProbes, int suspensionDays, int dormancyDays) {
        this.minReplayLeaves = minReplayLeaves;
        this.minPassProbes = minPassProbes;
        this.suspensionDays = suspensionDays;
        this.dormancyDays = dormancyDays;
        return this;
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

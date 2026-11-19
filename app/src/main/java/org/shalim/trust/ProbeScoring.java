package org.shalim.trust;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.shalim.ml.CensorEngine;
import org.shalim.ml.Verdict;

/**
 * The scoring every {@link org.shalim.ml.ProbeEngine} shares, so that a model
 * swap changes only how refusal wording is compared, never what counts as a
 * miss. Scores censor behaviour only: Matchmaker answers are not comparable
 * across hubs, and reading them would turn the audit into a way to harvest
 * another hub's members.
 */
public final class ProbeScoring {

    /** Distance between two refusal explanations, 0 (same) to 1 (unrelated). The model-specific part. */
    @FunctionalInterface
    public interface WordingDistance {
        float between(String a, String b);
    }

    private ProbeScoring() {
    }

    /** A synthetic probe: each side against the seed's intent, then against each other. */
    public static DifferenceScore score(TrustProbe probe, ProbeOutcome local, ProbeOutcome peer,
                                        WordingDistance wording) {
        String peerFp = peer == null ? null : peer.getProducedByKeyFingerprint();
        if (local == null || peer == null || !local.isScoreable() || !peer.isScoreable()) {
            return DifferenceScore.unscoreable(probe.getProbeId(), peerFp);
        }
        return DifferenceScore.of(DifferenceScore.Source.SYNTHETIC, probe.getProbeId(), peerFp, probe.getIntent(),
                local.getDecision() != peer.getDecision(),
                1f - jaccard(local.getCategories(), peer.getCategories()),
                Math.abs(local.getConfidence() - peer.getConfidence()),
                wordingDivergence(local, peer, wording),
                peer.satisfies(probe), local.satisfies(probe));
    }

    /**
     * An organic probe: the peer's visible behaviour against the prober
     * device's own pinned verdict. REVIEW on the device against BLOCK at the
     * peer is over-blocking. ALLOW on the device against REVIEW at the peer is
     * not counted: a moderator hold on a borderline question is legitimate.
     */
    public static DifferenceScore scoreOrganic(String probeId, Verdict device, ProbeOutcome peer) {
        String peerFp = peer == null ? null : peer.getProducedByKeyFingerprint();
        if (device == null || peer == null || !peer.isScoreable()) {
            return DifferenceScore.unscoreable(probeId, peerFp);
        }
        CensorEngine.Decision d = device.getDecision();
        CensorEngine.Decision p = peer.getDecision();
        boolean overBlock = p == CensorEngine.Decision.BLOCK && d != CensorEngine.Decision.BLOCK;
        boolean underBlock = d == CensorEngine.Decision.BLOCK && p == CensorEngine.Decision.ALLOW;
        // The intent is the device's verdict read as a seed would be: the
        // device says "should pass" (protected-speech-like) unless it blocked.
        TrustProbe.Intent intent = d == CensorEngine.Decision.BLOCK ? TrustProbe.Intent.SUPPLY_SIGNAL
                : d == CensorEngine.Decision.REVIEW ? TrustProbe.Intent.PROTECTED_SPEECH : TrustProbe.Intent.BENIGN;
        boolean peerMet = !overBlock && !underBlock;
        return DifferenceScore.of(DifferenceScore.Source.ORGANIC, probeId, peerFp, intent, d != p, 0f, 0f,
                Float.NaN, peerMet, true);
    }

    static float wordingDivergence(ProbeOutcome a, ProbeOutcome b, WordingDistance wording) {
        if (wording == null || a.getRefusalExplanation() == null || b.getRefusalExplanation() == null) {
            return Float.NaN;
        }
        return Math.max(0f, Math.min(1f, wording.between(a.getRefusalExplanation(), b.getRefusalExplanation())));
    }

    static float jaccard(List<CensorEngine.Category> a, List<CensorEngine.Category> b) {
        Set<CensorEngine.Category> union = new HashSet<>(a == null ? List.of() : a);
        union.addAll(b == null ? List.of() : b);
        if (union.isEmpty()) {
            return 1f;
        }
        Set<CensorEngine.Category> inter = new HashSet<>(a == null ? List.of() : a);
        inter.retainAll(b == null ? List.of() : b);
        return inter.size() / (float) union.size();
    }

    /** Token-overlap distance. Good enough for stubs; the real prober uses its encoder. */
    public static float tokenDistance(String a, String b) {
        Set<String> ta = new HashSet<>(List.of(a.toLowerCase(java.util.Locale.ROOT).split("\\W+")));
        Set<String> tb = new HashSet<>(List.of(b.toLowerCase(java.util.Locale.ROOT).split("\\W+")));
        Set<String> union = new HashSet<>(ta);
        union.addAll(tb);
        ta.retainAll(tb);
        return union.isEmpty() ? 0f : 1f - ta.size() / (float) union.size();
    }
}

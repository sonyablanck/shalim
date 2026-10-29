package org.shalim.trust;

import java.time.Instant;
import java.time.LocalDate;
import java.util.List;
import org.shalim.crypto.Aead;
import org.shalim.crypto.SoftwareSigner;
import org.shalim.hub.CensorDecisionLog;
import org.shalim.ml.CensorEngine;
import org.shalim.ml.Verdict;
import org.shalim.testing.Check;

public final class ReplaySamplingTest {

    private static final LocalDate START = LocalDate.of(2026, 10, 1);

    private ReplaySamplingTest() {
    }

    public static void testAuditorNoncesVerifyAtTheTargetAndCannotBeSubstituted() {
        AuthLink auditorSide = new AuthLink();
        byte[] anchor = auditorSide.startNonceChain(START);
        AuthLink targetSide = new AuthLink();
        targetSide.acceptNonceAnchor(anchor, START);

        ReplayAuditor auditor = new ReplayAuditor();
        LocalDate day = START.plusDays(28);
        byte[] nonce = auditor.revealNonce(auditorSide, day);
        Check.isTrue(ReplayAuditor.verifyRevealedNonce(targetSide.getNonceCommitment(),
                targetSide.nonceChainStart(), day, nonce), "target accepts the committed nonce");
        Check.isFalse(ReplayAuditor.verifyRevealedNonce(anchor, START, day, new byte[32]),
                "an auditor cannot reveal a nonce of its choosing");
        Check.isNull(auditor.revealNonce(targetSide, day), "the target holds no seed");
    }

    public static void testSampleIsFixedByHeadAndNonce() {
        SoftwareSigner hub = SoftwareSigner.generate();
        CensorDecisionLog log = new CensorDecisionLog(hub.fingerprint());
        Instant t = Instant.parse("2026-10-29T09:00:00Z");
        Verdict v = new Verdict(CensorEngine.Decision.ALLOW, List.of(), 0.1f, "00", t);
        for (int i = 0; i < 50; i++) {
            log.append("q" + i, v, CensorEngine.Surface.HUB_QUERY, "ANSWERED", hub, Aead.newKey(), t);
        }
        CensorDecisionLog.SignedTreeHead head = log.close(LocalDate.of(2026, 10, 29), hub, t);
        byte[] nonce = new byte[32];
        List<Long> a = ReplayAuditor.sampleIndices(head, nonce, 8);
        Check.equal(a, ReplayAuditor.sampleIndices(head, nonce, 8), "both sides derive the same sample");
        Check.equal(8, a.size(), "sample size");
        for (long i : a) {
            Check.isTrue(i >= 0 && i < head.getSize(), "within the padded tree");
        }
        nonce[0] = 1;
        Check.isFalse(a.equals(ReplayAuditor.sampleIndices(head, nonce, 8)), "nonce changes the sample");
    }
}

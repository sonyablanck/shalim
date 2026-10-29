package org.shalim.hub;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import org.shalim.crypto.Aead;
import org.shalim.crypto.Bytes;
import org.shalim.crypto.EncryptionKeyPair;
import org.shalim.crypto.SoftwareSigner;
import org.shalim.ml.CensorEngine;
import org.shalim.ml.Verdict;
import org.shalim.testing.Check;

public final class CensorDecisionLogTest {

    private static final Instant MORNING = Instant.parse("2026-10-29T09:00:00Z");
    private static final LocalDate DAY = LocalDate.of(2026, 10, 29);
    private static final String PIN = Bytes.hex(new byte[32]);

    private CensorDecisionLogTest() {
    }

    private static Verdict allow() {
        return new Verdict(CensorEngine.Decision.ALLOW, List.of(), 0.02f, PIN, MORNING);
    }

    private static Verdict block() {
        return new Verdict(CensorEngine.Decision.BLOCK,
                List.of(CensorEngine.Category.WEAPONS_SUPPLY), 0.97f, PIN, MORNING);
    }

    public static void testReceiptsHeadAndInclusion() {
        SoftwareSigner hub = SoftwareSigner.generate();
        byte[] atRest = Aead.newKey();
        CensorDecisionLog log = new CensorDecisionLog(hub.fingerprint());
        List<CensorDecisionLog.Receipt> receipts = new ArrayList<>();
        for (int i = 0; i < 40; i++) {
            receipts.add(log.append("question " + i, i % 7 == 0 ? block() : allow(),
                    CensorEngine.Surface.HUB_QUERY, i % 7 == 0 ? "REFUSED" : "ANSWERED", hub, atRest,
                    MORNING.plusSeconds(i)));
        }
        Check.isNull(log.proveInclusion(DAY, 0), "no proof before the day closes");
        CensorDecisionLog.SignedTreeHead head = log.close(DAY, hub, MORNING.plus(Duration.ofHours(15)));
        Check.equal(64L, head.getSize(), "40 screenings pad to 64");
        Check.equal(2, head.trafficBand(), "band 2");
        Check.isTrue(head.verify(hub.publicKey()), "head verifies");
        Check.isFalse(head.verify(SoftwareSigner.generate().publicKey()), "other key fails");
        for (CensorDecisionLog.Receipt r : receipts) {
            Check.isTrue(r.verify(hub.publicKey()), "receipt " + r.getLeafIndex() + " signed by hub");
            CensorDecisionLog.InclusionProof proof = log.proveInclusion(DAY, r.getLeafIndex());
            Check.isTrue(proof.verify(r.getLeafHash(), head.getRootHash()), "receipt in tree");
        }
        Check.isTrue(log.close(DAY, hub, MORNING) == head, "closing twice returns the same head");
    }

    public static void testReplayOpeningsRoundTripAndPadsOpenAsPads() {
        SoftwareSigner hub = SoftwareSigner.generate();
        byte[] atRest = Aead.newKey();
        EncryptionKeyPair auditor = EncryptionKeyPair.generate();
        CensorDecisionLog log = new CensorDecisionLog(hub.fingerprint());
        log.append("how do I compost?", allow(), CensorEngine.Surface.HUB_QUERY, "ANSWERED", hub, atRest, MORNING);
        log.append("meet Thursday?", allow(), CensorEngine.Surface.MEETING_REQUEST, "DELIVERED", hub, atRest,
                MORNING.plusSeconds(1));
        CensorDecisionLog.SignedTreeHead head = log.close(DAY, hub, MORNING.plusSeconds(60));

        List<CensorDecisionLog.Opening> openings = log.open(DAY, List.of(0L, 1L, 5L), auditor.publicKey(),
                atRest, false);
        Check.equal(3, openings.size(), "three openings");

        CensorDecisionLog.Opening real = openings.get(0);
        Check.isTrue(real.getProof().verify(real.getLeaf().getLeafHash(), head.getRootHash()), "proof");
        Check.isTrue(real.getLeaf().hashMatches(), "decision fields match the committed hash");
        Check.equal("how do I compost?", real.openText(auditor, hub.fingerprint()), "auditor reads the text");
        Check.isNull(real.openText(EncryptionKeyPair.generate(), hub.fingerprint()), "nobody else can");

        CensorDecisionLog.Opening meeting = openings.get(1);
        Check.isNull(meeting.getEncryptedText(), "meeting request not opened without consent");
        Check.isTrue(meeting.getProof().verify(meeting.getLeaf().getLeafHash(), head.getRootHash()),
                "but its inclusion still checks");

        CensorDecisionLog.Opening pad = openings.get(2);
        Check.isTrue(pad.getLeaf().isPad(), "index 5 is padding");
        Check.isTrue(pad.padMatches(), "pad opens as a pad");
    }

    public static void testAlteredDecisionFieldsAreDetected() {
        SoftwareSigner hub = SoftwareSigner.generate();
        byte[] atRest = Aead.newKey();
        CensorDecisionLog log = new CensorDecisionLog(hub.fingerprint());
        log.append("something", block(), CensorEngine.Surface.HUB_QUERY, "REFUSED", hub, atRest, MORNING);
        log.close(DAY, hub, MORNING.plusSeconds(60));
        CensorDecisionLog.Leaf real = log.open(DAY, List.of(0L), EncryptionKeyPair.generate().publicKey(),
                atRest, false).get(0).getLeaf();
        CensorDecisionLog.Leaf relabelled = CensorDecisionLog.Leaf.received(real.getIndex(), real.getLeafSalt(),
                real.getTextHash(), real.getSurface(), CensorEngine.Decision.ALLOW, List.of(), 0.01f,
                "ANSWERED", real.getCensorPinHash(), real.getDay(), false, real.getLeafHash());
        Check.isTrue(real.hashMatches(), "original matches");
        Check.isFalse(relabelled.hashMatches(), "a peer cannot show a different decision under the same hash");
    }

    public static void testDaysChainWithoutGapsAndEmptyDaysPad() {
        SoftwareSigner hub = SoftwareSigner.generate();
        byte[] atRest = Aead.newKey();
        CensorDecisionLog log = new CensorDecisionLog(hub.fingerprint());
        log.append("monday", allow(), CensorEngine.Surface.HUB_QUERY, "ANSWERED", hub, atRest, MORNING);
        // Next screening three days later: the open day and two empty days close first.
        log.append("thursday", allow(), CensorEngine.Surface.HUB_QUERY, "ANSWERED", hub, atRest,
                MORNING.plus(Duration.ofDays(3)));
        List<CensorDecisionLog.SignedTreeHead> heads = log.getHeads();
        Check.equal(3, heads.size(), "three days closed");
        Check.isNull(heads.get(0).getPreviousHeadHash(), "first head starts the chain");
        for (int i = 1; i < heads.size(); i++) {
            Check.equal(heads.get(i - 1).headHash(), heads.get(i).getPreviousHeadHash(), "chained " + i);
            Check.equal(heads.get(i - 1).getDay().plusDays(1), heads.get(i).getDay(), "consecutive " + i);
        }
        Check.equal(32L, heads.get(1).getSize(), "an empty day pads to one block");
        Check.throwsA(IllegalStateException.class, () -> log.close(DAY.minusDays(1), hub, MORNING),
                "cannot close a day before the last head");
    }

    public static void testPruneDropsLeavesKeepsHeadsAndWrongKeyIsRefused() {
        SoftwareSigner hub = SoftwareSigner.generate();
        byte[] atRest = Aead.newKey();
        CensorDecisionLog log = new CensorDecisionLog(hub.fingerprint());
        log.append("old", allow(), CensorEngine.Surface.HUB_QUERY, "ANSWERED", hub, atRest, MORNING);
        log.close(DAY, hub, MORNING);
        Check.equal(32, log.prune(14, MORNING.plus(Duration.ofDays(20))), "one day of leaves dropped");
        Check.equal(0, log.open(DAY, List.of(0L), EncryptionKeyPair.generate().publicKey(), atRest, true).size(),
                "nothing left to open");
        Check.notNull(log.headFor(DAY), "head kept");
        Check.throwsA(IllegalArgumentException.class, () -> log.append("x", allow(),
                CensorEngine.Surface.HUB_QUERY, "ANSWERED", SoftwareSigner.generate(), atRest, MORNING),
                "another key cannot write to this log");
    }

    public static void testStoredTextIsEncryptedAndBoundToItsSlot() {
        SoftwareSigner hub = SoftwareSigner.generate();
        byte[] atRest = Aead.newKey();
        CensorDecisionLog log = new CensorDecisionLog(hub.fingerprint());
        log.append("first", allow(), CensorEngine.Surface.HUB_QUERY, "ANSWERED", hub, atRest, MORNING);
        log.close(DAY, hub, MORNING);
        Check.throwsA(org.shalim.crypto.CryptoException.class, () -> log.open(DAY, List.of(0L),
                EncryptionKeyPair.generate().publicKey(), Aead.newKey(), false), "wrong at-rest key");
    }
}

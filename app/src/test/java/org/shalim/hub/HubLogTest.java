package org.shalim.hub;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import org.shalim.crypto.SoftwareSigner;
import org.shalim.testing.Check;

public final class HubLogTest {

    private static final Instant T0 = Instant.parse("2026-10-01T10:00:00Z");

    private HubLogTest() {
    }

    private static Function<String, byte[]> keys(SoftwareSigner... signers) {
        Map<String, byte[]> map = new HashMap<>();
        for (SoftwareSigner s : signers) {
            map.put(s.fingerprint(), s.publicKey());
        }
        return map::get;
    }

    public static void testAppendChainsAndVerifies() {
        SoftwareSigner hub = SoftwareSigner.generate();
        HubLog log = new HubLog("hub-1");
        HubLog.Entry first = log.append(HubLog.EventType.HUB_CREATED, "admin", null, null, hub, T0);
        HubLog.Entry second = log.append(HubLog.EventType.MEMBER_ADMITTED, "admin", "m1", "role=MEMBER",
                hub, T0.plusSeconds(60));
        Check.isNull(first.getPreviousHash(), "genesis has no predecessor");
        Check.equal(first.getHash(), second.getPreviousHash(), "chained");
        Check.equal(second.getHash(), log.getHeadHash(), "head advanced");
        Check.isTrue(log.verifyChain(keys(hub)), "chain and signatures verify");
        Check.isFalse(log.verifyChain(keys(SoftwareSigner.generate())), "unknown signer fails");
        Check.isTrue(second.verify(hub.publicKey()), "entry verifies");
    }

    public static void testTamperedEntryIsRejectedOnMerge() {
        SoftwareSigner hub = SoftwareSigner.generate();
        HubLog origin = new HubLog("hub-1");
        origin.append(HubLog.EventType.HUB_CREATED, "admin", null, null, hub, T0);
        HubLog.Entry real = origin.append(HubLog.EventType.ROLE_ASSIGNED, "admin", "m1", "MODERATOR",
                hub, T0.plusSeconds(5));

        HubLog replica = new HubLog("hub-1");
        List<HubLog.Entry> all = origin.entriesMissingFrom(null);
        HubLog.Entry forged = HubLog.Entry.received(real.getEntryId(), real.getType(), real.getActorUserId(),
                real.getSubjectId(), "ADMIN", real.getOccurredAt(), real.getPreviousHash(),
                real.getSignerKeyFingerprint(), real.getHash(), real.getSignature());
        List<HubLog.Entry> tampered = new ArrayList<>(List.of(all.get(0), forged));
        Check.equal(1, replica.mergeEntries(tampered, keys(hub)), "stops at the forged entry");
        Check.equal(1, replica.mergeEntries(origin.entriesMissingFrom(replica.getHeadHash()), keys(hub)),
                "then takes the real one");
        Check.equal(origin.getHeadHash(), replica.getHeadHash(), "converged");
        Check.equal(0, replica.mergeEntries(all, keys(hub)), "duplicates skipped");
        Check.isTrue(replica.verifyChain(keys(hub)), "replica verifies");
    }

    public static void testEntriesMissingFrom() {
        SoftwareSigner hub = SoftwareSigner.generate();
        HubLog log = new HubLog("hub-1");
        HubLog.Entry a = log.append(HubLog.EventType.HUB_CREATED, "x", null, null, hub, T0);
        log.append(HubLog.EventType.SYNC_COMPLETED, "x", null, null, hub, T0.plusSeconds(1));
        log.append(HubLog.EventType.SYNC_COMPLETED, "x", null, null, hub, T0.plusSeconds(2));
        Check.equal(2, log.entriesMissingFrom(a.getHash()).size(), "after a");
        Check.equal(0, log.entriesMissingFrom(log.getHeadHash()).size(), "peer up to date");
        Check.equal(3, log.entriesMissingFrom("00").size(), "unknown head gets everything");
    }

    public static void testPruneReanchorsSoTheChainStillVerifies() {
        SoftwareSigner hub = SoftwareSigner.generate();
        HubLog log = new HubLog("hub-1");
        for (int day = 0; day < 10; day++) {
            log.append(HubLog.EventType.SYNC_COMPLETED, "x", null, "day " + day, hub,
                    T0.plus(Duration.ofDays(day)));
        }
        int dropped = log.prune(3, T0.plus(Duration.ofDays(9)));
        Check.equal(6, dropped, "days 0-5 are older than three days");
        Check.notNull(log.getAnchorHash(), "anchor kept");
        Check.isTrue(log.verifyChain(keys(hub)), "verifies from the anchor");
        log.append(HubLog.EventType.LOG_PRUNED, "x", null, "6", hub, T0.plus(Duration.ofDays(9)));
        Check.isTrue(log.verifyChain(keys(hub)), "and keeps verifying after new appends");
        log.wipe();
        Check.equal(0, log.getEntries().size(), "wiped");
        Check.isNull(log.getHeadHash(), "no head after wipe");
    }

    public static void testHubIdIsBoundIntoEveryHash() {
        SoftwareSigner hub = SoftwareSigner.generate();
        HubLog one = new HubLog("hub-1");
        one.append(HubLog.EventType.HUB_CREATED, "x", null, null, hub, T0);
        HubLog other = new HubLog("hub-2");
        Check.equal(0, other.mergeEntries(one.getEntries(), keys(hub)),
                "an entry from one hub's log cannot be replayed into another's");
    }
}

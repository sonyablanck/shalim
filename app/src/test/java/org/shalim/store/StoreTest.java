package org.shalim.store;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.Comparator;
import java.util.List;
import org.shalim.crypto.Bytes;
import org.shalim.crypto.CryptoException;
import org.shalim.crypto.EncryptionKeyPair;
import org.shalim.hub.CensorDecisionLog;
import org.shalim.hub.Hub;
import org.shalim.hub.QueryService;
import org.shalim.identity.Role;
import org.shalim.query.HubQuery;
import org.shalim.query.MeetingService;
import org.shalim.query.QueryResult;
import org.shalim.testing.Check;
import org.shalim.testing.HubFixture;

public final class StoreTest {

    private StoreTest() {
    }

    private static Path tempDir() throws Exception {
        return Files.createTempDirectory("shalim-store-test");
    }

    private static void delete(Path dir) throws Exception {
        try (var files = Files.walk(dir)) {
            for (Path p : files.sorted(Comparator.reverseOrder()).toList()) {
                Files.deleteIfExists(p);
            }
        }
    }

    public static void testRecordsAreSealedBoundToTheirNamesAndShreddable() throws Exception {
        Path dir = tempDir();
        try {
            byte[] kek = StoreKey.random();
            EncryptedStore store = EncryptedStore.open(dir, kek);
            store.put("roster", "alice,bob".getBytes(StandardCharsets.UTF_8));
            store.put("log", "entries".getBytes(StandardCharsets.UTF_8));
            Check.equal("alice,bob", new String(EncryptedStore.open(dir, kek).get("roster").get(), StandardCharsets.UTF_8),
                    "reopened and read");
            Check.isFalse(new String(Files.readAllBytes(dir.resolve("roster.rec")), StandardCharsets.ISO_8859_1)
                    .contains("alice"), "nothing in the clear on disk");
            Check.throwsA(CryptoException.class, () -> EncryptedStore.open(dir, StoreKey.random()), "wrong key");
            Files.copy(dir.resolve("log.rec"), dir.resolve("roster.rec"), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            Check.throwsA(CryptoException.class, () -> store.get("roster"), "a record moved into another's place fails");
            store.shred();
            Check.isFalse(Files.exists(dir.resolve("store.key")), "key destroyed");
            Check.equal(0, store.names().size(), "records gone");
            Check.throwsA(IllegalStateException.class, () -> store.get("log"), "and the store is closed");
        } finally {
            delete(dir);
        }
    }

    public static void testPassphraseKeysAndRewrap() throws Exception {
        Path dir = tempDir();
        try {
            byte[] salt = StoreKey.newSalt();
            byte[] kek = StoreKey.fromPassphrase("correct horse".toCharArray(), salt, 1000);
            EncryptedStore store = EncryptedStore.open(dir, kek);
            store.put("x", new byte[] {1});
            byte[] next = StoreKey.fromPassphrase("battery staple".toCharArray(), salt, 1000);
            store.rewrap(next);
            Check.equalBytes(new byte[] {1}, EncryptedStore.open(dir, next).get("x").get(), "new passphrase opens");
            Check.throwsA(CryptoException.class, () -> EncryptedStore.open(dir, kek), "old passphrase does not");
            Check.isFalse(Bytes.equal(kek, StoreKey.fromPassphrase("correct horse".toCharArray(), StoreKey.newSalt(), 1000)),
                    "the salt matters");
        } finally {
            delete(dir);
        }
    }

    public static void testAHubSurvivesARestartExactly() throws Exception {
        HubFixture f = new HubFixture();
        f.authenticate();
        String asker = f.newMember(Role.MEMBER);
        String helper = f.newMember(Role.MODERATOR);
        var admin = f.admin();
        var interaction = admin.recordInteraction(helper, f.hub.getSkillsLayer().getResources().get(0).getResourceId(),
                "note");
        admin.presentCredentials(helper, admin.verifyInteraction(f.admin.fingerprint(), interaction.getInteractionId(),
                org.shalim.skills.UserSkill.Proficiency.PRACTISED));
        HubQuery q = new HubQuery(f.hub.getHubId(), asker, "lathe metalwork").withMaxMatches(5);
        QueryResult r = new QueryService(f.hub, f.runtime).ask(q);
        new MeetingService(f.hub, f.runtime).request(asker, helper, q.getQueryId(), "Lathe lesson?");
        f.admin().applyRetention();

        Path dir = tempDir();
        try {
            byte[] kek = StoreKey.random();
            HubSnapshot.save(EncryptedStore.open(dir, kek), f.hub);
            Hub back = HubSnapshot.load(EncryptedStore.open(dir, kek), f.hub.getHubId());
            Check.equalBytes(HubSnapshot.encode(f.hub), HubSnapshot.encode(back), "byte-for-byte the same hub");
            Check.isTrue(back.getLog().verifyChain(fp -> f.hubKey.publicKey()), "log verifies after reload");
            Check.equal(f.hub.getRoster().getMemberships().size(), back.getRoster().getMemberships().size(), "roster");
            Check.equal(1, back.getMeetings().requests().size(), "meeting request");
            Check.equal(1, back.getSkillsLayer().getMemberIndex().size(), "member skills");

            LocalDate day = LocalDate.ofInstant(f.clock.instant(), ZoneOffset.UTC);
            CensorDecisionLog.SignedTreeHead head = back.getCensorLog().close(day, f.hubKey, f.clock.instant());
            Check.isTrue(head.verify(f.hubKey.publicKey()), "the reloaded censor log keeps signing");
            EncryptionKeyPair auditor = EncryptionKeyPair.generate();
            CensorDecisionLog.Opening o = back.getCensorLog().open(day, List.of(r.getCensorReceipt().getLeafIndex()),
                    auditor.publicKey(), f.atRestKey, false).get(0);
            Check.equal("lathe metalwork", o.openText(auditor, f.hubKey.fingerprint()),
                    "and sealed texts still open, under the hub's own at-rest key");

            // On disk, the store's AEAD catches any change. These check the
            // decoder itself refuses a truncated snapshot or a forged log.
            byte[] bytes = HubSnapshot.encode(f.hub);
            boolean refused = false;
            try {
                HubSnapshot.decode(java.util.Arrays.copyOf(bytes, bytes.length - 7));
            } catch (HubSnapshot.CorruptSnapshotException e) {
                refused = true;
            }
            Check.isTrue(refused, "a truncated snapshot is refused, not half-loaded");
            List<org.shalim.hub.HubLog.Entry> entries = new java.util.ArrayList<>(f.hub.getLog().getEntries());
            org.shalim.hub.HubLog.Entry e = entries.get(0);
            entries.set(0, org.shalim.hub.HubLog.Entry.received(e.getEntryId(), e.getType(), e.getActorUserId(),
                    e.getSubjectId(), "HIGH_RISK", e.getOccurredAt(), e.getPreviousHash(), e.getSignerKeyFingerprint(),
                    e.getHash(), e.getSignature()));
            org.shalim.hub.HubLog restored = new org.shalim.hub.HubLog(f.hub.getHubId());
            Check.isFalse(restored.restore(entries, f.hub.getLog().getAnchorHash(), f.hub.getLog().getHeadHash()),
                    "a log altered at rest is refused whole, which makes the snapshot refuse to load");
            Check.equal(0, restored.getEntries().size(), "nothing half-loaded");
        } finally {
            delete(dir);
        }
    }
}

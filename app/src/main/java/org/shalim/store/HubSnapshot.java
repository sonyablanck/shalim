package org.shalim.store;

import java.time.Instant;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import org.shalim.attestation.ModerationOutcome;
import org.shalim.hub.CensorDecisionLog;
import org.shalim.hub.CensorIntegrity;
import org.shalim.hub.Hub;
import org.shalim.hub.HubLocation;
import org.shalim.hub.HubLog;
import org.shalim.hub.HubNetwork;
import org.shalim.hub.HubPolicy;
import org.shalim.hub.HubStanding;
import org.shalim.hub.NetworkClaim;
import org.shalim.hub.Roster;
import org.shalim.identity.AgeAssurance;
import org.shalim.identity.Membership;
import org.shalim.identity.Restriction;
import org.shalim.identity.Role;
import org.shalim.ml.CensorEngine;
import org.shalim.query.Meeting;
import org.shalim.query.MeetingBook;
import org.shalim.query.MeetingRequest;
import org.shalim.skills.HubResource;
import org.shalim.skills.ResourceInteraction;
import org.shalim.skills.Skill;
import org.shalim.skills.SkillsLayer;
import org.shalim.skills.UserSkill;
import org.shalim.transport.LogEntryCodec;
import org.shalim.transport.Wire;

/**
 * A whole hub as bytes, for {@link EncryptedStore}: policy, premises,
 * network and claim, roster with restrictions, standing, censor integrity, the
 * hub log, the censor decision log (texts still sealed under the hub's at-rest
 * key), the skills layer, moderation outcomes and the meeting book.
 *
 * <p>Retention is applied before saving, so a snapshot never holds more than
 * the policy allows. Enums are stored by name, so a reordered enum in a later
 * release cannot silently change what a stored value means. On load, the hub
 * log's chain is verified, and a log that fails is refused as a whole.
 *
 * <p>Not stored: the audit schedule, links and bonds (stage 4), and
 * embeddings, which are rebuilt by {@code SkillsLayer.reindex}.
 */
public final class HubSnapshot {

    private static final int VERSION = 2;
    private static final int MAX = 16 << 20;

    private HubSnapshot() {
    }

    /** Thrown when a snapshot does not decode or its log does not verify. */
    public static final class CorruptSnapshotException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        public CorruptSnapshotException(String message) {
            super(message);
        }
    }

    public static void save(EncryptedStore store, Hub hub) {
        store.put("hub-" + hub.getHubId(), encode(hub));
    }

    public static Hub load(EncryptedStore store, String hubId) {
        return store.get("hub-" + hubId).map(HubSnapshot::decode).orElse(null);
    }

    // --- encode -----------------------------------------------------------

    public static byte[] encode(Hub hub) {
        Wire.Writer w = Wire.writer().u8(VERSION);
        w.string(hub.getHubId()).string(hub.getName()).string(hub.getDescription()).instant(hub.getCreatedAt())
                .u64(hub.getRevision());
        writePolicy(w, hub.getPolicy());
        writeLocation(w, hub.getLocation());
        writeNetwork(w, hub.getNetwork());
        writeRoster(w, hub.getRoster());
        writeStanding(w, hub.getStanding());
        writeIntegrity(w, hub.getCensorIntegrity());
        writeLog(w, hub.getLog());
        writeCensorLog(w, hub.getCensorLog());
        writeSkills(w, hub.getSkillsLayer());
        writeOutcomes(w, hub.getModerationOutcomes());
        writeMeetings(w, hub.getMeetings());
        return w.done();
    }

    private static void writePolicy(Wire.Writer w, HubPolicy p) {
        w.bool(p != null);
        if (p == null) {
            return;
        }
        en(w, p.getPosture());
        w.bool(p.isRequireAgeAssurance());
        en(w, p.getMinimumAssuranceMethod());
        strings(w, p.getTrustedRestrictionSources());
        w.bool(p.isPublishRestrictions()).bool(p.isRequireGoodStanding()).bool(p.isFederateModerationOutcomes())
                .bool(p.isWithholdOutcomesUnderAppeal()).u32(p.getAttestationTtlHours())
                .string(p.getRequiredCensorPinHash());
        en(w, p.getCensorFailureMode());
        en(w, p.getUnlockBasis());
        w.bool(p.isReplayMeetingRequests()).u32(p.getLogRetentionDays()).u32(p.getMeetingRequestRetentionDays())
                .bool(p.isEncryptSkillsAtRest()).bool(p.isAllowPanicWipe()).bool(p.isAllowGuests())
                .u32(p.getGuestPresenceTtlMinutes()).string(p.getHubId());
    }

    private static void writeLocation(Wire.Writer w, HubLocation l) {
        w.bool(l != null);
        if (l == null) {
            return;
        }
        w.string(l.getLocationId()).string(l.getHubId()).string(l.getLabel()).string(l.getStreetAddress())
                .string(l.getLocality()).string(l.getPostalArea()).string(l.getCountryCode());
        dbl(w, l.getApproxLatitude());
        dbl(w, l.getApproxLongitude());
        en(w, l.getPrecision());
        w.bool(l.isSupervised()).bool(l.isPubliclyAccessible()).string(l.getOpeningHours()).string(l.getZoneId());
        strings(w, l.getMeetingSpaces());
    }

    private static void writeNetwork(Wire.Writer w, HubNetwork n) {
        w.bool(n != null);
        if (n == null) {
            return;
        }
        w.string(n.getNetworkId()).string(n.getHubId()).string(n.getSsid());
        strings(w, n.getBssidHashes());
        w.bool(n.isHubOperated()).bool(n.isGrantsGuestAccess()).bool(n.isEncrypted()).instant(n.getLastSeenAt())
                .bool(n.isDisputed());
        NetworkClaim c = n.getClaim();
        w.bool(c != null);
        if (c != null) {
            w.string(c.getClaimId()).string(c.getHubKeyFingerprint());
            strings(w, c.getSaltedBssidHashes());
            w.instant(c.getClaimedAt()).string(c.getSupersedesClaimId()).bytes(c.getHubSignature());
            w.u32(c.getPeerWitnesses().size());
            for (NetworkClaim.Witness x : c.getPeerWitnesses()) {
                w.string(x.peerKeyFingerprint()).instant(x.witnessedAt()).bytes(x.signature());
            }
        }
    }

    private static void writeRoster(Wire.Writer w, Roster roster) {
        List<Membership> ms = roster == null ? List.of() : roster.getMemberships();
        w.u32(ms.size());
        for (Membership m : ms) {
            w.string(m.getMembershipId()).string(m.getUserId()).string(m.getHubId());
            en(w, m.getRole());
            w.instant(m.getJoinedAt()).instant(m.getLastSeenAt()).string(m.getAdmittedByUserId());
            en(w, m.getVisibility());
            w.string(m.getPresenceProofId()).instant(m.getPresenceExpiresAt()).string(m.getPinnedNetworkClaimId());
            List<Restriction> rs = m.allRestrictions();
            w.u32(rs.size());
            for (Restriction r : rs) {
                w.string(r.getRestrictionId()).string(r.getMembershipId());
                en(w, r.getReason());
                en(w, r.getScope());
                en(w, r.getRoleCap());
                w.instant(r.getAppliedAt()).instant(r.getExpiresAt()).string(r.getAppliedByUserId())
                        .string(r.getExplanation()).bool(r.isAppealable());
                en(w, r.getDischarge());
                w.string(r.getOriginHubId()).bool(r.isOriginRemediated()).instant(r.getLiftedAt())
                        .string(r.getLiftedByUserId()).string(r.getLiftJustification());
            }
        }
    }

    private static void writeStanding(Wire.Writer w, HubStanding s) {
        w.bool(s != null);
        if (s != null) {
            en(w, s.getState());
            w.u32(s.getOutboundCounting()).u32(s.getInboundCounting()).u32(s.getBonds())
                    .instant(s.getEverUnlockedAt()).instant(s.getComputedAt()).instant(s.getProvisionalUntil());
        }
    }

    private static void writeIntegrity(Wire.Writer w, CensorIntegrity c) {
        w.bool(c != null);
        if (c != null) {
            en(w, c.getState());
            w.instant(c.getCheckedAt()).string(c.getExpectedPinHash()).string(c.getActualPinHash())
                    .string(c.getDetectedBy()).string(c.getEvidence());
        }
    }

    private static void writeLog(Wire.Writer w, HubLog log) {
        List<HubLog.Entry> entries = log == null ? List.of() : log.getEntries();
        w.string(log == null ? null : log.getHubId()).string(log == null ? null : log.getAnchorHash())
                .string(log == null ? null : log.getHeadHash()).u32(entries.size());
        for (HubLog.Entry e : entries) {
            LogEntryCodec.write(w, e);
        }
    }

    private static void writeLeaf(Wire.Writer w, CensorDecisionLog.Leaf l) {
        w.u64(l.getIndex()).string(l.getLeafHash()).bool(l.isPad()).bytes(l.getLeafSalt()).string(l.getTextHash());
        en(w, l.getSurface());
        en(w, l.getDecision());
        w.u32(l.getCategories().size());
        for (CensorEngine.Category c : l.getCategories()) {
            en(w, c);
        }
        w.u32(Float.floatToIntBits(l.getConfidence())).string(l.getActionTaken()).string(l.getCensorPinHash());
        date(w, l.getDay());
    }

    private static void writeCensorLog(Wire.Writer w, CensorDecisionLog log) {
        w.bool(log != null);
        if (log == null) {
            return;
        }
        CensorDecisionLog.State s = log.exportState();
        w.string(s.hubKeyFingerprint());
        date(w, s.openDay());
        w.u32(s.openLeaves().size());
        for (CensorDecisionLog.Leaf l : s.openLeaves()) {
            writeLeaf(w, l);
        }
        w.u32(s.heads().size());
        for (CensorDecisionLog.SignedTreeHead h : s.heads()) {
            w.string(h.getHubKeyFingerprint());
            date(w, h.getDay());
            w.u64(h.getSize()).string(h.getRootHash()).string(h.getPreviousHeadHash()).instant(h.getSignedAt())
                    .string(h.getSignature());
        }
        w.u32(s.closedLeaves().size());
        for (Map.Entry<LocalDate, List<CensorDecisionLog.Leaf>> e : s.closedLeaves().entrySet()) {
            date(w, e.getKey());
            w.u32(e.getValue().size());
            for (CensorDecisionLog.Leaf l : e.getValue()) {
                writeLeaf(w, l);
            }
        }
        writeDayMap(w, s.sealedTexts());
        writeDayMap(w, s.padValues());
    }

    private static void writeDayMap(Wire.Writer w, Map<LocalDate, Map<Long, byte[]>> m) {
        w.u32(m.size());
        for (Map.Entry<LocalDate, Map<Long, byte[]>> e : m.entrySet()) {
            date(w, e.getKey());
            w.u32(e.getValue().size());
            for (Map.Entry<Long, byte[]> x : e.getValue().entrySet()) {
                w.u64(x.getKey()).bytes(x.getValue());
            }
        }
    }

    private static void writeSkills(Wire.Writer w, SkillsLayer s) {
        w.string(s.getHubId());
        List<HubResource> rs = s.getResources();
        w.u32(rs.size());
        for (HubResource r : rs) {
            w.string(r.getResourceId()).string(r.getHubId()).string(r.getName());
            en(w, r.getKind());
            w.string(r.getDescription()).string(r.getLocation());
            strings(w, r.getSkillIds());
            w.bool(r.isAvailable());
        }
        List<Skill> skills = s.getHubSkills();
        w.u32(skills.size());
        for (Skill k : skills) {
            w.string(k.getSkillId()).string(k.getHubId());
            en(w, k.getOrigin());
            strings(w, k.getResourceIds());
            w.string(k.getLabel()).string(k.getTaxonomyTerm()).string(k.getNormalisedText()).bool(k.isOffered())
                    .instant(k.getDerivedAt()).string(k.getDerivedByPinHash()).string(k.getCensorVerdictId());
        }
        List<SkillsLayer.MemberSkillEntry> idx = s.getMemberIndex();
        w.u32(idx.size());
        for (SkillsLayer.MemberSkillEntry e : idx) {
            w.string(e.getUserId()).string(e.getTaxonomyTerm());
            en(w, e.getProficiency());
            w.instant(e.getLastConfirmedAt()).bool(e.isOffered()).bool(e.isEarnedHere());
        }
        List<ResourceInteraction> pending = s.getPendingInteractions();
        w.u32(pending.size());
        for (ResourceInteraction i : pending) {
            w.string(i.getInteractionId()).string(i.getHubId()).string(i.getUserKeyFingerprint())
                    .string(i.getResourceId()).string(i.getNote()).instant(i.getOccurredAt());
        }
        Map<String, Set<String>> tags = new TreeMap<>(s.getImportedLinkTags());
        w.u32(tags.size());
        for (Map.Entry<String, Set<String>> e : tags.entrySet()) {
            w.string(e.getKey());
            strings(w, sorted(e.getValue()));
        }
        strings(w, sorted(s.getUnderReview()));
        w.bool(s.isHubSkillsStale());
    }

    private static void writeOutcomes(Wire.Writer w, List<ModerationOutcome> outcomes) {
        w.u32(outcomes.size());
        for (ModerationOutcome o : outcomes) {
            w.string(o.getOutcomeId()).string(o.getSubjectKeyFingerprint()).string(o.getIssuerKeyFingerprint());
            en(w, o.getKind());
            en(w, o.getGround());
            w.instant(o.getDecidedAt()).instant(o.getExpiresAt()).string(o.getDecidedByUserId());
            strings(w, o.getEvidenceEntryHashes());
            w.bool(o.isUnderAppeal()).bool(o.isOverturned()).bool(o.isFederatable())
                    .string(o.getOverturnedByUserId()).string(o.getOverturnJustification());
        }
    }

    private static void writeMeetings(Wire.Writer w, MeetingBook b) {
        Map<String, MeetingBook.Surfaced> surfaced = new TreeMap<>(b.allSurfaced());
        w.u32(surfaced.size());
        for (MeetingBook.Surfaced s : surfaced.values()) {
            w.string(s.queryId()).string(s.askerUserId());
            strings(w, sorted(s.memberIds()));
            w.instant(s.at());
        }
        List<MeetingRequest> rs = b.requests();
        w.u32(rs.size());
        for (MeetingRequest r : rs) {
            w.string(r.getRequestId()).string(r.getHubId()).string(r.getFromUserId()).string(r.getToUserId())
                    .string(r.getOriginatingQueryId()).string(r.getMessage());
            en(w, r.getStatus());
            w.instant(r.getSentAt()).instant(r.getRespondedAt()).instant(r.getExpiresAt()).string(r.getVerdictId())
                    .bool(r.isHeldForReview());
        }
        List<Meeting> ms = b.meetings();
        w.u32(ms.size());
        for (Meeting m : ms) {
            w.string(m.getMeetingId()).string(m.getHubId()).string(m.getRequestId()).string(m.getRequesterUserId())
                    .string(m.getRecipientUserId()).string(m.getLocationId()).string(m.getMeetingSpace())
                    .instant(m.getScheduledFor()).u32(m.getDurationMinutes());
            en(w, m.getStatus());
            w.string(m.getCancelledByUserId()).string(m.getReportedByUserId()).string(m.getReportConcern());
        }
        strings(w, sorted(b.blockedPairs()));
    }

    // --- decode -----------------------------------------------------------

    public static Hub decode(byte[] bytes) {
        try {
            Wire.Reader r = Wire.reader(bytes);
            if (r.u8() != VERSION) {
                throw new CorruptSnapshotException("unknown snapshot version");
            }
            Hub hub = new Hub();
            hub.setHubId(r.string(MAX));
            hub.setName(r.string(MAX));
            hub.setDescription(r.string(MAX));
            hub.setCreatedAt(r.instant());
            hub.setRevision(r.u64());
            hub.setPolicy(readPolicy(r));
            hub.setLocation(readLocation(r));
            hub.setNetwork(readNetwork(r));
            hub.setRoster(readRoster(r));
            hub.setStanding(readStanding(r));
            hub.setCensorIntegrity(readIntegrity(r));
            hub.setLog(readLog(r));
            hub.setCensorLog(readCensorLog(r));
            SkillsLayer skills = readSkills(r);
            hub.setSkillsLayer(skills);
            hub.getModerationOutcomes().addAll(readOutcomes(r));
            readMeetings(r, hub.getMeetings());
            r.end();
            return hub;
        } catch (CorruptSnapshotException e) {
            throw e;
        } catch (RuntimeException e) {
            // Any failure while rebuilding, not only wire errors: a snapshot
            // either loads whole or not at all.
            throw new CorruptSnapshotException("snapshot does not decode: " + e);
        }
    }

    private static HubPolicy readPolicy(Wire.Reader r) {
        if (!r.bool()) {
            return null;
        }
        HubPolicy p = HubPolicy.restoring(en(r, HubPolicy.Posture.class));
        boolean requireAge = r.bool();
        p.setAgeAssurance(requireAge, en(r, AgeAssurance.Method.class));
        for (String s : strings(r)) {
            p.trustRestrictionsFrom(s);
        }
        p.setPublishRestrictions(r.bool());
        p.setRequireGoodStanding(r.bool());
        p.setFederateModerationOutcomes(r.bool());
        p.setWithholdOutcomesUnderAppeal(r.bool());
        p.setAttestationTtlHours((int) r.u32());
        p.setRequiredCensorPinHash(r.string(MAX));
        p.setCensorFailureMode(en(r, HubPolicy.CensorFailureMode.class));
        p.setUnlockBasis(en(r, HubPolicy.UnlockBasis.class));
        p.setReplayMeetingRequests(r.bool());
        p.setLogRetentionDays((int) r.u32());
        p.setMeetingRequestRetentionDays((int) r.u32());
        p.setEncryptSkillsAtRest(r.bool());
        p.setAllowPanicWipe(r.bool());
        p.setAllowGuests(r.bool());
        p.setGuestPresenceTtlMinutes((int) r.u32());
        p.setHubId(r.string(MAX));
        return p;
    }

    private static HubLocation readLocation(Wire.Reader r) {
        if (!r.bool()) {
            return null;
        }
        String id = r.string(MAX);
        String hubId = r.string(MAX);
        String label = r.string(MAX);
        String street = r.string(MAX);
        String locality = r.string(MAX);
        String postal = r.string(MAX);
        String country = r.string(MAX);
        Double lat = dbl(r);
        Double lon = dbl(r);
        HubLocation.Precision precision = en(r, HubLocation.Precision.class);
        boolean supervised = r.bool();
        boolean open = r.bool();
        String hours = r.string(MAX);
        String zone = r.string(MAX);
        List<String> spaces = strings(r);
        return HubLocation.restore(id, hubId, label, street, locality, postal, country, lat, lon, precision,
                supervised, open, hours, zone, spaces);
    }

    private static HubNetwork readNetwork(Wire.Reader r) {
        if (!r.bool()) {
            return null;
        }
        String id = r.string(MAX);
        String hubId = r.string(MAX);
        String ssid = r.string(MAX);
        List<String> hashes = strings(r);
        boolean operated = r.bool();
        boolean guests = r.bool();
        boolean encrypted = r.bool();
        Instant lastSeen = r.instant();
        boolean disputed = r.bool();
        NetworkClaim claim = null;
        if (r.bool()) {
            String claimId = r.string(MAX);
            String fp = r.string(MAX);
            List<String> claimHashes = strings(r);
            Instant claimedAt = r.instant();
            String supersedes = r.string(MAX);
            byte[] sig = r.bytes(MAX);
            int n = count(r);
            List<NetworkClaim.Witness> ws = new ArrayList<>();
            for (int i = 0; i < n; i++) {
                ws.add(new NetworkClaim.Witness(r.string(MAX), r.instant(), r.bytes(MAX)));
            }
            claim = NetworkClaim.restore(claimId, fp, claimHashes, claimedAt, supersedes, ws, sig);
        }
        return HubNetwork.restore(id, hubId, ssid, hashes, operated, guests, encrypted, lastSeen, claim, disputed);
    }

    private static Roster readRoster(Wire.Reader r) {
        Roster roster = new Roster();
        int n = count(r);
        for (int i = 0; i < n; i++) {
            String id = r.string(MAX);
            String user = r.string(MAX);
            String hubId = r.string(MAX);
            Role role = en(r, Role.class);
            Instant joined = r.instant();
            Instant seen = r.instant();
            String admittedBy = r.string(MAX);
            Membership.Visibility vis = en(r, Membership.Visibility.class);
            String proof = r.string(MAX);
            Instant proofExpires = r.instant();
            String pinned = r.string(MAX);
            int rn = count(r);
            List<Restriction> rs = new ArrayList<>();
            for (int j = 0; j < rn; j++) {
                String rid = r.string(MAX);
                String mid = r.string(MAX);
                Restriction.Reason reason = en(r, Restriction.Reason.class);
                Restriction.Scope scope = en(r, Restriction.Scope.class);
                Role cap = en(r, Role.class);
                Instant applied = r.instant();
                Instant expires = r.instant();
                String by = r.string(MAX);
                String explanation = r.string(MAX);
                boolean appealable = r.bool();
                Restriction.Discharge discharge = en(r, Restriction.Discharge.class);
                String origin = r.string(MAX);
                boolean remediated = r.bool();
                Instant liftedAt = r.instant();
                String liftedBy = r.string(MAX);
                String why = r.string(MAX);
                Restriction x = Restriction.restore(rid, mid, reason, scope, cap, applied, expires, by, explanation,
                        appealable, discharge, origin, remediated);
                x.restoreLift(liftedAt, liftedBy, why);
                rs.add(x);
            }
            roster.add(Membership.restore(id, user, hubId, role, joined, seen, admittedBy, vis, proof, proofExpires,
                    pinned, rs));
        }
        return roster;
    }

    private static HubStanding readStanding(Wire.Reader r) {
        if (!r.bool()) {
            return null;
        }
        return HubStanding.restore(en(r, HubStanding.State.class), (int) r.u32(), (int) r.u32(), (int) r.u32(),
                r.instant(), r.instant(), r.instant());
    }

    private static CensorIntegrity readIntegrity(Wire.Reader r) {
        if (!r.bool()) {
            return null;
        }
        return CensorIntegrity.restore(en(r, CensorIntegrity.State.class), r.instant(), r.string(MAX), r.string(MAX),
                r.string(MAX), r.string(MAX));
    }

    private static HubLog readLog(Wire.Reader r) {
        String hubId = r.string(MAX);
        String anchor = r.string(MAX);
        String head = r.string(MAX);
        int n = count(r);
        List<HubLog.Entry> entries = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            entries.add(LogEntryCodec.read(r));
        }
        HubLog log = new HubLog(hubId);
        if (!log.restore(entries, anchor, head)) {
            throw new CorruptSnapshotException("hub log chain does not verify");
        }
        return log;
    }

    private static CensorDecisionLog.Leaf readLeaf(Wire.Reader r) {
        long index = r.u64();
        String hash = r.string(MAX);
        boolean pad = r.bool();
        byte[] salt = r.bytes(MAX);
        String textHash = r.string(MAX);
        CensorEngine.Surface surface = en(r, CensorEngine.Surface.class);
        CensorEngine.Decision decision = en(r, CensorEngine.Decision.class);
        int nc = count(r);
        List<CensorEngine.Category> cats = new ArrayList<>();
        for (int i = 0; i < nc; i++) {
            cats.add(en(r, CensorEngine.Category.class));
        }
        float confidence = Float.intBitsToFloat((int) r.u32());
        String action = r.string(MAX);
        String pin = r.string(MAX);
        LocalDate day = date(r);
        return CensorDecisionLog.Leaf.received(index, salt, textHash, surface, decision, cats, confidence, action, pin,
                day, pad, hash);
    }

    private static CensorDecisionLog readCensorLog(Wire.Reader r) {
        if (!r.bool()) {
            return null;
        }
        String fp = r.string(MAX);
        LocalDate openDay = date(r);
        int n = count(r);
        List<CensorDecisionLog.Leaf> open = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            open.add(readLeaf(r));
        }
        int hn = count(r);
        List<CensorDecisionLog.SignedTreeHead> heads = new ArrayList<>();
        for (int i = 0; i < hn; i++) {
            heads.add(CensorDecisionLog.SignedTreeHead.received(r.string(MAX), date(r), r.u64(), r.string(MAX),
                    r.string(MAX), r.instant(), r.string(MAX)));
        }
        int dn = count(r);
        Map<LocalDate, List<CensorDecisionLog.Leaf>> closed = new TreeMap<>();
        for (int i = 0; i < dn; i++) {
            LocalDate d = date(r);
            int ln = count(r);
            List<CensorDecisionLog.Leaf> leaves = new ArrayList<>();
            for (int j = 0; j < ln; j++) {
                leaves.add(readLeaf(r));
            }
            closed.put(d, leaves);
        }
        return CensorDecisionLog.restore(new CensorDecisionLog.State(fp, openDay, open, heads, closed, readDayMap(r),
                readDayMap(r)));
    }

    private static Map<LocalDate, Map<Long, byte[]>> readDayMap(Wire.Reader r) {
        Map<LocalDate, Map<Long, byte[]>> out = new TreeMap<>();
        int n = count(r);
        for (int i = 0; i < n; i++) {
            LocalDate d = date(r);
            int m = count(r);
            Map<Long, byte[]> inner = new HashMap<>();
            for (int j = 0; j < m; j++) {
                inner.put(r.u64(), r.bytes(MAX));
            }
            out.put(d, inner);
        }
        return out;
    }

    private static SkillsLayer readSkills(Wire.Reader r) {
        SkillsLayer s = new SkillsLayer(r.string(MAX));
        int n = count(r);
        List<HubResource> resources = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            String id = r.string(MAX);
            String hubId = r.string(MAX);
            String name = r.string(MAX);
            HubResource.Kind kind = en(r, HubResource.Kind.class);
            String desc = r.string(MAX);
            String loc = r.string(MAX);
            List<String> skillIds = strings(r);
            boolean available = r.bool();
            resources.add(HubResource.restore(id, hubId, name, kind, desc, loc, skillIds, available));
        }
        n = count(r);
        List<Skill> skills = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            String id = r.string(MAX);
            String hubId = r.string(MAX);
            Skill.Origin origin = en(r, Skill.Origin.class);
            List<String> resourceIds = strings(r);
            skills.add(Skill.restore(id, hubId, origin, resourceIds, r.string(MAX), r.string(MAX), r.string(MAX),
                    r.bool(), r.instant(), r.string(MAX), r.string(MAX)));
        }
        n = count(r);
        List<SkillsLayer.MemberSkillEntry> index = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            index.add(new SkillsLayer.MemberSkillEntry(r.string(MAX), r.string(MAX), en(r, UserSkill.Proficiency.class),
                    r.instant(), r.bool(), r.bool()));
        }
        n = count(r);
        List<ResourceInteraction> pending = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            pending.add(ResourceInteraction.restore(r.string(MAX), r.string(MAX), r.string(MAX), r.string(MAX),
                    r.string(MAX), r.instant()));
        }
        n = count(r);
        Map<String, Set<String>> tags = new HashMap<>();
        for (int i = 0; i < n; i++) {
            tags.put(r.string(MAX), new HashSet<>(strings(r)));
        }
        Set<String> underReview = new HashSet<>(strings(r));
        s.restore(resources, skills, index, pending, tags, underReview, r.bool());
        return s;
    }

    private static List<ModerationOutcome> readOutcomes(Wire.Reader r) {
        int n = count(r);
        List<ModerationOutcome> out = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            String id = r.string(MAX);
            String subject = r.string(MAX);
            String issuer = r.string(MAX);
            ModerationOutcome.Kind kind = en(r, ModerationOutcome.Kind.class);
            ModerationOutcome.Ground ground = en(r, ModerationOutcome.Ground.class);
            Instant decided = r.instant();
            Instant expires = r.instant();
            String by = r.string(MAX);
            List<String> evidence = strings(r);
            out.add(ModerationOutcome.restore(id, subject, issuer, kind, ground, decided, expires, by, evidence,
                    r.bool(), r.bool(), r.bool(), r.string(MAX), r.string(MAX)));
        }
        return out;
    }

    private static void readMeetings(Wire.Reader r, MeetingBook book) {
        int n = count(r);
        List<MeetingBook.Surfaced> surfaced = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            surfaced.add(new MeetingBook.Surfaced(r.string(MAX), r.string(MAX), new HashSet<>(strings(r)), r.instant()));
        }
        n = count(r);
        List<MeetingRequest> requests = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            String id = r.string(MAX);
            String hubId = r.string(MAX);
            String from = r.string(MAX);
            String to = r.string(MAX);
            String query = r.string(MAX);
            String message = r.string(MAX);
            MeetingRequest.Status status = en(r, MeetingRequest.Status.class);
            requests.add(MeetingRequest.restore(id, hubId, from, to, query, message, status, r.instant(), r.instant(),
                    r.instant(), r.string(MAX), r.bool()));
        }
        n = count(r);
        List<Meeting> meetings = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            String id = r.string(MAX);
            String hubId = r.string(MAX);
            String requestId = r.string(MAX);
            String requester = r.string(MAX);
            String recipient = r.string(MAX);
            String location = r.string(MAX);
            String space = r.string(MAX);
            Instant when = r.instant();
            int minutes = (int) r.u32();
            Meeting.Status status = en(r, Meeting.Status.class);
            meetings.add(Meeting.restore(id, hubId, requestId, requester, recipient, location, space, when, minutes,
                    status, r.string(MAX), r.string(MAX), r.string(MAX)));
        }
        book.restore(surfaced, requests, meetings, new HashSet<>(strings(r)));
    }

    // --- primitives -------------------------------------------------------

    private static void en(Wire.Writer w, Enum<?> e) {
        w.string(e == null ? null : e.name());
    }

    private static <E extends Enum<E>> E en(Wire.Reader r, Class<E> type) {
        String name = r.string(256);
        return name == null ? null : Enum.valueOf(type, name);
    }

    /** Sets are written sorted, so the same hub always encodes to the same bytes. */
    private static List<String> sorted(Set<String> values) {
        List<String> out = new ArrayList<>(values);
        out.sort(null);
        return out;
    }

    private static void strings(Wire.Writer w, List<String> values) {
        w.u32(values.size());
        for (String v : values) {
            w.string(v);
        }
    }

    private static List<String> strings(Wire.Reader r) {
        int n = count(r);
        List<String> out = new ArrayList<>(Math.min(n, 1024));
        for (int i = 0; i < n; i++) {
            out.add(r.string(MAX));
        }
        return out;
    }

    private static int count(Wire.Reader r) {
        long n = r.u32();
        if (n > r.remaining()) {
            throw new Wire.WireException("count exceeds the bytes left");
        }
        return (int) n;
    }

    private static void dbl(Wire.Writer w, Double d) {
        w.bool(d != null);
        if (d != null) {
            w.u64(Double.doubleToLongBits(d));
        }
    }

    private static Double dbl(Wire.Reader r) {
        return r.bool() ? Double.longBitsToDouble(r.u64()) : null;
    }

    private static void date(Wire.Writer w, LocalDate d) {
        w.bool(d != null);
        if (d != null) {
            w.u64(d.toEpochDay());
        }
    }

    private static LocalDate date(Wire.Reader r) {
        return r.bool() ? LocalDate.ofEpochDay(r.u64()) : null;
    }
}

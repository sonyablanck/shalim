package org.shalim.transport;

import org.shalim.hub.HubLog;

/**
 * Wire form of a {@link HubLog.Entry}. The event type goes by name, not
 * ordinal, so replicas on different releases agree on what an entry was. A
 * received entry is not trusted: {@link HubLog#mergeEntries} recomputes its
 * hash and checks its signature.
 */
public final class LogEntryCodec {

    /** Detail is "short structured detail"; anything longer is refused. */
    public static final int MAX_DETAIL_BYTES = 2048;

    private LogEntryCodec() {
    }

    public static void write(Wire.Writer w, HubLog.Entry e) {
        w.smallString(e.getEntryId())
                .smallString(e.getType().name())
                .smallString(e.getActorUserId())
                .smallString(e.getSubjectId())
                .string(e.getDetail())
                .instant(e.getOccurredAt())
                .hex(e.getPreviousHash())
                .hex(e.getSignerKeyFingerprint())
                .hex(e.getHash())
                .hex(e.getSignature());
    }

    public static HubLog.Entry read(Wire.Reader r) {
        String entryId = r.smallString();
        String typeName = r.smallString();
        HubLog.EventType type;
        try {
            type = HubLog.EventType.valueOf(typeName);
        } catch (IllegalArgumentException | NullPointerException e) {
            throw new Wire.WireException("unknown event type");
        }
        return HubLog.Entry.received(entryId, type, r.smallString(), r.smallString(),
                r.string(MAX_DETAIL_BYTES), r.instant(), r.hex(), r.hex(), r.hex(), r.hex());
    }

    public static int encodedSize(HubLog.Entry e) {
        Wire.Writer w = Wire.writer();
        write(w, e);
        return w.done().length;
    }
}

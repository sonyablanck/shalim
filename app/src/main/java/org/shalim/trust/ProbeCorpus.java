package org.shalim.trust;

import java.util.List;

/**
 * The fixed set of <em>seed</em> probes, pinned by hash exactly as
 * {@link org.shalim.ml.ModelPin} pins a model artefact.
 *
 * <p>Since daily probing was introduced, seeds are no longer sent as they
 * are. The {@link org.shalim.ml.ProbeEngine} paraphrases a seed each day and
 * the paraphrase inherits the seed's intent. The corpus therefore still
 * decides what a correct answer is; it has stopped deciding the wording. That
 * slows memorisation considerably, but a hub that can see the seeds can
 * still learn their meaning, so rotation between releases remains necessary.
 *
 * <p>Pinning is not optional. If the auditor chose the questions freely it
 * could hand a peer a set designed to fail, and "you did not pass my audit"
 * would mean "I did not want you to". Both hubs verify the corpus hash before
 * a run, and a mismatch aborts the audit rather than producing a finding.
 *
 * <p>The corpus is large and each run samples a small random subset, because a
 * hub that has seen every probe can special-case all of them. This is a delay,
 * not a defence: a hub that audits and is audited long enough will eventually
 * observe most of the corpus. Rotation of the corpus between releases is what
 * actually keeps this honest, and the release cadence is a real cost the design
 * has not paid yet.
 */
public class ProbeCorpus {

    private String corpusId;
    private String version;

    /** SHA-256 of the canonical serialisation. Both sides check this first. */
    private String corpusHash;

    /** Signature over {@link #corpusHash} by the release key. */
    private String releaseSignature;

    private List<TrustProbe> probes;

    public ProbeCorpus() {
        this.probes = new java.util.ArrayList<>();
    }

    /**
     * Builds a corpus from its seeds and pins it: the hash covers every
     * seed's id, text, surface, intent and category, in order. Release tooling
     * and tests; hubs receive a corpus and {@link #verify} it.
     */
    public static ProbeCorpus of(String corpusId, String version, List<TrustProbe> seeds) {
        ProbeCorpus c = new ProbeCorpus();
        c.corpusId = corpusId;
        c.version = version;
        for (TrustProbe s : seeds) {
            s.setCorpusVersion(version);
            c.probes.add(s);
        }
        c.corpusHash = org.shalim.crypto.Hashing.sha256Hex(c.encode());
        return c;
    }

    /** The canonical serialisation the hash covers. */
    public byte[] encode() {
        java.util.List<String> rows = new java.util.ArrayList<>();
        for (TrustProbe p : probes) {
            rows.add(org.shalim.crypto.Canonical.of("shalim.probecorpus.seed.v1").string(p.getProbeId())
                    .string(p.getText()).enumName(p.getSurface()).enumName(p.getIntent())
                    .enumName(p.getCategory()).digestHex());
        }
        return org.shalim.crypto.Canonical.of("shalim.probecorpus.v1").string(corpusId).string(version)
                .orderedStrings(rows).encode();
    }

    public ProbeCorpus(String version, String corpusHash) {
        this();
        this.version = version;
        this.corpusHash = corpusHash;
    }

    /** What the release key signs: {@code ("shalim.probecorpus.v1", corpusId, version, corpusHash)}. */
    public byte[] signingPayload() {
        return org.shalim.crypto.Canonical.of("shalim.probecorpus.v1").string(corpusId)
                .string(version).hex(corpusHash).encode();
    }

    /** Release tooling only. */
    public ProbeCorpus signWith(org.shalim.crypto.Signer releaseKey) {
        this.releaseSignature = releaseKey.signHex(signingPayload());
        return this;
    }

    /**
     * Draws a run's sample. The seed is exchanged with the peer so both sides
     * can reproduce the run from the log afterwards; it is not secret, because
     * secrecy here would only mean neither hub could check the other's working.
     */
    public List<TrustProbe> sample(int size, long seed) {
        java.util.Random rng = new java.util.Random(seed);
        List<TrustProbe> all = new java.util.ArrayList<>(probes);
        if (size >= all.size()) {
            java.util.Collections.shuffle(all, rng);
            return all;
        }
        // A uniform sample is mostly BENIGN and detects nothing. Guarantee a
        // floor of the two intents that carry findings.
        List<TrustProbe> out = new java.util.ArrayList<>();
        int floor = Math.max(1, size / 4);
        drawFrom(TrustProbe.Intent.SUPPLY_SIGNAL, floor, rng, out);
        drawFrom(TrustProbe.Intent.PROTECTED_SPEECH, floor, rng, out);
        List<TrustProbe> rest = new java.util.ArrayList<>(probes);
        rest.removeAll(out);
        java.util.Collections.shuffle(rest, rng);
        for (TrustProbe p : rest) {
            if (out.size() >= size) {
                break;
            }
            out.add(p);
        }
        java.util.Collections.shuffle(out, rng); // order carries no signal
        return out;
    }

    /**
     * One seed of the given expectation, for this hub's local self-test.
     * Deterministic in (seed, day) so any later appeal draws the same.
     */
    public TrustProbe sampleSeed(TrustProbe.Expectation expectation, long seed,
                                 java.time.LocalDate day) {
        List<TrustProbe> pool = new java.util.ArrayList<>();
        for (TrustProbe p : probes) {
            if (p.expectation() != expectation) {
                continue;
            }
            if (expectation == TrustProbe.Expectation.PASS) {
                // Protected speech at least every other day, or a hub retuned to
                // suppress overdose advice passes for a week.
                TrustProbe.Intent want = day.toEpochDay() % 2 == 0 ? TrustProbe.Intent.PROTECTED_SPEECH
                        : TrustProbe.Intent.BENIGN;
                if (p.getIntent() != want) {
                    continue;
                }
            }
            pool.add(p);
        }
        if (pool.isEmpty()) {
            for (TrustProbe p : probes) {
                if (p.expectation() == expectation) {
                    pool.add(p);
                }
            }
        }
        return pool.isEmpty() ? null : pool.get(index(seed, day, pool.size()));
    }

    /**
     * One seed for a synthetic probe to a peer. Never SUPPLY_SIGNAL.
     * Weighted towards PROTECTED_SPEECH, since over-blocking is what synthetic
     * probes are for now that replay covers under-blocking.
     */
    public TrustProbe sampleSynthetic(long seed, java.time.LocalDate day) {
        double[] weights = {0.5, 0.3, 0.2};
        TrustProbe.Intent[] intents = {TrustProbe.Intent.PROTECTED_SPEECH, TrustProbe.Intent.NEAR_MISS,
                TrustProbe.Intent.BENIGN};
        java.util.Random rng = new java.util.Random(org.shalim.crypto.Canonical.of("shalim.synthetic.draw.v1")
                .u64(seed).date(day).digestHex().hashCode() ^ seed);
        double r = rng.nextDouble();
        int start = r < weights[0] ? 0 : r < weights[0] + weights[1] ? 1 : 2;
        // Fall through to the next intent if the corpus has none of the drawn one.
        for (int k = 0; k < intents.length; k++) {
            TrustProbe.Intent want = intents[(start + k) % intents.length];
            List<TrustProbe> pool = probes.stream().filter(p -> p.getIntent() == want && p.sendableToPeer()).toList();
            if (!pool.isEmpty()) {
                return pool.get(rng.nextInt(pool.size()));
            }
        }
        return null; // never SUPPLY_SIGNAL, even if that is all the corpus has
    }

    /** Verifies the corpus against its pin before a run is allowed to start. */
    public boolean verify(byte[] corpusBytes, byte[] releasePublicKey) {
        return corpusBytes != null && corpusHash != null
                && org.shalim.crypto.Bytes.equalHex(corpusHash, org.shalim.crypto.Hashing.sha256Hex(corpusBytes))
                && org.shalim.crypto.Ed25519.verifyHex(releasePublicKey, signingPayload(), releaseSignature);
    }

    /** Whether both hubs are holding the same corpus. Checked before probing. */
    public boolean matches(ProbeCorpus other) {
        return other != null && corpusHash != null
                && org.shalim.crypto.Bytes.equalHex(corpusHash, other.corpusHash);
    }

    private void drawFrom(TrustProbe.Intent intent, int n, java.util.Random rng, List<TrustProbe> out) {
        List<TrustProbe> pool = new java.util.ArrayList<>(probes.stream().filter(p -> p.getIntent() == intent).toList());
        java.util.Collections.shuffle(pool, rng);
        out.addAll(pool.subList(0, Math.min(n, pool.size())));
    }

    private static int index(long seed, java.time.LocalDate day, int bound) {
        byte[] d = org.shalim.crypto.Canonical.of("shalim.selftest.draw.v1").u64(seed).date(day).digest();
        long v = 0;
        for (int i = 0; i < 8; i++) {
            v = (v << 8) | (d[i] & 0xff);
        }
        return (int) Long.remainderUnsigned(v, bound);
    }

    /** A seed by id, for regeneration. */
    public TrustProbe seedById(String probeId) {
        for (TrustProbe p : probes) {
            if (p.getProbeId().equals(probeId)) {
                return p;
            }
        }
        return null;
    }

    public int size() {
        return probes == null ? 0 : probes.size();
    }

    // --- accessors --------------------------------------------------------

    public String getCorpusId() {
        return corpusId;
    }

    public String getVersion() {
        return version;
    }

    public String getCorpusHash() {
        return corpusHash;
    }

    public List<TrustProbe> getProbes() {
        return probes;
    }
}

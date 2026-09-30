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
        // TODO: pseudo-code
    }

    public ProbeCorpus(String version, String corpusHash) {
        // TODO: pseudo-code
    }

    /**
     * Draws a run's sample. The seed is exchanged with the peer so both sides
     * can reproduce the run from the log afterwards; it is not secret, because
     * secrecy here would only mean neither hub could check the other's working.
     */
    public List<TrustProbe> sample(int size, long seed) {
        // PSEUDO-CODE
        //
        // 1. IF size > probes.size() -> RETURN all, shuffled
        //
        // 2. STRATIFY BY INTENT
        //    // A sample drawn uniformly is mostly BENIGN, and an audit of
        //    // benign questions detects nothing. Guarantee a floor of
        //    // SUPPLY_SIGNAL and PROTECTED_SPEECH probes in every run, since
        //    // those two carry the only findings that lead anywhere.
        //    at least 25% SUPPLY_SIGNAL      // under-blocking detector
        //    at least 25% PROTECTED_SPEECH   // over-blocking detector
        //    remainder split between NEAR_MISS and BENIGN
        //
        // 3. DRAW deterministically from seed within each stratum
        //
        // 4. SHUFFLE the combined sample, so probe order carries no signal
        return null;
    }

    /**
     * One seed of the given expectation, for this hub's local self-test.
     * Deterministic in (seed, day) so any later appeal draws the same.
     */
    public TrustProbe sampleSeed(TrustProbe.Expectation expectation, long seed,
                                 java.time.LocalDate day) {
        // PSEUDO-CODE
        // pool = probes WHERE expectation() == expectation
        // IF expectation == PASS
        //    alternate BENIGN and PROTECTED_SPEECH by day
        //    // Protected speech must come up at least every other day, or a
        //    // hub retuned to suppress overdose advice passes for a week.
        // RETURN pool[deterministicIndex(seed, day)]
        return null;
    }

    /**
     * One seed for a synthetic probe to a peer. Never SUPPLY_SIGNAL.
     * Weighted towards PROTECTED_SPEECH, since over-blocking is what synthetic
     * probes are for now that replay covers under-blocking.
     */
    public TrustProbe sampleSynthetic(long seed, java.time.LocalDate day) {
        // PSEUDO-CODE
        // pool = probes WHERE sendableToPeer()
        // weights: PROTECTED_SPEECH 0.5, NEAR_MISS 0.3, BENIGN 0.2
        // RETURN weighted draw, deterministic in (seed, day)
        return null;
    }

    /** Verifies the corpus against its pin before a run is allowed to start. */
    public boolean verify(byte[] corpusBytes, byte[] releasePublicKey) {
        // TODO: pseudo-code
        return false;
    }

    /** Whether both hubs are holding the same corpus. Checked before probing. */
    public boolean matches(ProbeCorpus other) {
        // TODO: pseudo-code
        return false;
    }

    public int size() {
        // TODO: pseudo-code
        return 0;
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

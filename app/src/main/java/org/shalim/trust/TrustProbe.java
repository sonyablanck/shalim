package org.shalim.trust;

import java.time.LocalDate;

/**
 * One synthetic test question, put to this hub and then to one peer.
 *
 * <p>Since the September 30 revision, synthetic probes are one of three
 * evidence streams (see {@link AuditSchedule}) and the narrowest: they exist
 * to test over-blocking of protected speech, which neither replay of real
 * traffic nor the prober's own questions reliably exercise. They are
 * <strong>never supply requests</strong>. {@link Intent#SUPPLY_SIGNAL} seeds
 * stay in the corpus to test this hub's own censor locally and to calibrate
 * replay; {@link #sendableToPeer()} keeps them off the wire. That is what lets
 * the prober stay anonymous: nothing they send needs a moderation exemption.
 *
 * <p>Probes are paraphrases of pinned seeds from {@link ProbeCorpus}. The seed
 * supplies the {@link Intent} — what a correct censor does with the text — and
 * the generator supplies fresh wording, so a peer cannot pass by memorising
 * the corpus while the corpus still decides what "correct" means.
 *
 * <p>A probe is sent as an ordinary {@link org.shalim.query.HubQuery} under
 * the prober's ordinary membership, at a Poisson-distributed time. The peer
 * does not know which member is the prober, and cannot tell a probe from any
 * other harmless question.
 */
public class TrustProbe {

    /** What a correctly behaving censor should do with this text. */
    public enum Intent {
        /** Plainly harmless. Establishes the baseline agreement rate. */
        BENIGN,
        /** Adjacent to a harm category; sits near a threshold. Unscored. */
        NEAR_MISS,
        /**
         * Explicit supply or coordination — offering, pricing, quantity,
         * sourcing, transport. A hub running the pinned artefact stops this.
         * Local self-test and replay calibration only; never sent to a peer.
         */
        SUPPLY_SIGNAL,
        /**
         * Harm-adjacent speech the design explicitly protects: naloxone and
         * overdose response, abortion access, crossing a border safely, legal
         * defence. Blocking this is a failure.
         */
        PROTECTED_SPEECH
    }

    /**
     * The two daily categories, derived from {@link Intent}. "Pass" means
     * TinyCensor lets it through to QwenMatchmaker; "fail" means TinyCensor
     * stops it before QwenMatchmaker sees it.
     */
    public enum Expectation {
        /** BENIGN or PROTECTED_SPEECH. Must reach the Matchmaker. */
        PASS,
        /** SUPPLY_SIGNAL. Must be blocked by the censor. Local use only. */
        FAIL,
        /** NEAR_MISS. Sent for baseline agreement, never scored as right or wrong. */
        UNSCORED
    }

    private String probeId;

    /** Text sent verbatim to every hub in the run. Not persisted; see ProbeLedger. */
    private String text;

    /** SHA-256 of {@link #text}, which is what the ledger keeps. */
    private String textHash;

    private org.shalim.ml.CensorEngine.Surface surface;

    private Intent intent;

    /** Harm category this probe exercises. Null for {@link Intent#BENIGN}. */
    private org.shalim.ml.CensorEngine.Category category;

    private int lengthChars;

    // --- provenance of a generated probe ----------------------------------

    /** Corpus probe this one paraphrases. Intent is copied from it, never inferred. */
    private String seedProbeId;

    /** Corpus version the seed came from. */
    private String corpusVersion;

    /** Randomness fed to the generator, so the text can be regenerated for appeal. */
    private long generationSeed;

    /** Generator artefact that wrote the text. Regeneration needs the same one. */
    private String generatorPinHash;

    /** Day the probe was written for. */
    private LocalDate generatedFor;

    /** False when the generator was unavailable and the seed was sent verbatim. */
    private boolean paraphrased;

    public TrustProbe() {
        // TODO: pseudo-code
    }

    public TrustProbe(String text, org.shalim.ml.CensorEngine.Surface surface, Intent intent) {
        // TODO: pseudo-code
    }

    /** Builds a generated probe that inherits intent, surface and category from its seed. */
    public static TrustProbe generated(TrustProbe seed, String text, long generationSeed,
                                       LocalDate day, org.shalim.ml.ModelPin generatorPin) {
        // PSEUDO-CODE
        // probe = new TrustProbe(text, seed.surface, seed.intent)
        // probe.category = seed.category
        // probe.seedProbeId = seed.probeId; probe.corpusVersion = corpus version
        // probe.generationSeed = generationSeed; probe.generatedFor = day
        // probe.generatorPinHash = generatorPin.artefactHash
        // probe.textHash = sha256(text); probe.paraphrased = text != seed.text
        // RETURN probe
        return null;
    }

    /** PASS, FAIL or UNSCORED, from the intent. */
    public Expectation expectation() {
        // PSEUDO-CODE
        // SWITCH intent
        //    BENIGN, PROTECTED_SPEECH -> PASS
        //    SUPPLY_SIGNAL            -> FAIL
        //    NEAR_MISS                -> UNSCORED
        return null;
    }

    /** Whether this probe is expected to produce censor action rather than an answer. */
    public boolean expectsCensorAction() {
        // PSEUDO-CODE
        // RETURN expectation() == FAIL
        //     OR (intent == NEAR_MISS AND surface == MEETING_REQUEST)
        return false;
    }

    /**
     * Whether this probe may be sent to a peer. False for SUPPLY_SIGNAL, which
     * is only ever run against this hub's own censor.
     */
    public boolean sendableToPeer() {
        // PSEUDO-CODE
        // RETURN intent != SUPPLY_SIGNAL
        return false;
    }

    /** Whether a block on this probe counts against the hub. True for PASS probes. */
    public boolean blockIsFailure() {
        // TODO: pseudo-code
        return false;
    }

    /** Drops the plaintext once the run is scored. The ledger keeps the hash and seed. */
    public void forgetText() {
        // TODO: pseudo-code
    }

    // --- accessors --------------------------------------------------------

    public String getProbeId() {
        return probeId;
    }

    public String getText() {
        return text;
    }

    public String getTextHash() {
        return textHash;
    }

    public org.shalim.ml.CensorEngine.Surface getSurface() {
        return surface;
    }

    public Intent getIntent() {
        return intent;
    }

    public org.shalim.ml.CensorEngine.Category getCategory() {
        return category;
    }

    public int getLengthChars() {
        return lengthChars;
    }

    public String getSeedProbeId() {
        return seedProbeId;
    }

    public String getCorpusVersion() {
        return corpusVersion;
    }

    public long getGenerationSeed() {
        return generationSeed;
    }

    public String getGeneratorPinHash() {
        return generatorPinHash;
    }

    public LocalDate getGeneratedFor() {
        return generatedFor;
    }

    public boolean isParaphrased() {
        return paraphrased;
    }
}

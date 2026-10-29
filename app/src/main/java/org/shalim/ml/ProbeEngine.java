package org.shalim.ml;

import java.time.LocalDate;
import java.util.List;
import org.shalim.trust.DifferenceScore;
import org.shalim.trust.ProbeCorpus;
import org.shalim.trust.ProbeOutcome;
import org.shalim.trust.TrustProbe;

/**
 * The third on-device model, alongside {@link CensorEngine} and
 * {@link MatchmakerEngine}. It has two jobs, and they are different enough
 * that an implementation will usually run two small artefacts behind one
 * interface:
 *
 * <ol>
 *   <li><strong>Write synthetic probes.</strong> One at a time, when
 *       {@link org.shalim.trust.AuditSchedule#nextSyntheticAt} says so, and
 *       PASS-side only — benign, protected speech or near-miss. Nothing it
 *       writes for a peer is a supply request; see
 *       {@link TrustProbe#sendableToPeer()}. It still writes SUPPLY_SIGNAL
 *       paraphrases for this hub's own local self-test.</li>
 *   <li><strong>Score the answers.</strong> Assign each peer's outcome a
 *       {@link DifferenceScore}: against the local outcome and the seed for a
 *       synthetic probe, or against the prober device's own pinned verdict
 *       for an {@link org.shalim.trust.OrganicProbe}.</li>
 * </ol>
 *
 * <p>The censor itself is no longer tested through this engine at all —
 * {@link org.shalim.trust.ReplayAuditor} replays the peer's committed decisions
 * through {@link CensorEngine} directly.
 *
 * <h2>Why generation is seeded, not free</h2>
 *
 * <p>A probe is only useful if its expected outcome is known independently of
 * the hub that wrote it. If this model invented a question and also decided
 * whether it "should" be blocked, a hub whose own models had been retuned
 * would write probes that agree with its retuning, and would then fail every
 * honest peer against them. So every generated probe is a <em>paraphrase of a
 * pinned seed</em> from {@link ProbeCorpus}: the seed carries the
 * {@link TrustProbe.Intent}, the model only changes the wording. Fresh wording
 * each day means a peer cannot pass by memorising the corpus; inherited intent
 * means the corpus is still the third opinion that makes a divergence
 * attributable.
 *
 * <p>Generation is also deterministic given (pinned artefact, seed probe,
 * generation seed). That is what lets {@link org.shalim.trust.ProbeLedger}
 * keep an audit trail without holding the plaintext of a drug-supply question
 * on the admin's device: the text can be regenerated for an appeal, and is
 * otherwise stored only as a hash.
 *
 * <h2>Model choice</h2>
 *
 * <p>An encoder such as RoBERTa cannot do the first job — it classifies and
 * embeds text but does not generate it — and {@link TinyCensor} is already a
 * RoBERTa. The reference split is therefore a small decoder for paraphrase
 * (sub-1B, quantised) plus a RoBERTa-class encoder for scoring, each pinned by
 * its own {@link ModelPin} with {@link ModelPin.Purpose#PROBER}. See
 * {@link TinyProber}.
 */
public interface ProbeEngine {

    /**
     * Writes one synthetic probe for a peer. PASS-side or NEAR_MISS only;
     * never {@link TrustProbe.Intent#SUPPLY_SIGNAL}.
     *
     * @param corpus the pinned seed corpus, verified before this is called
     * @param day    the date the probe is for, folded into the seed
     * @param seed   fresh randomness, recorded in the ledger for regeneration
     */
    TrustProbe generateSynthetic(ProbeCorpus corpus, LocalDate day, long seed);

    /**
     * Writes probes for this hub's own local self-test, including
     * SUPPLY_SIGNAL. Run against the local pipeline only, never sent.
     */
    List<TrustProbe> generateSelfTest(ProbeCorpus corpus, LocalDate day, long seed, int count);

    /**
     * Regenerates a probe's text from its recorded provenance. Used for
     * appeals and for re-reading the ledger; never to create new probes.
     */
    String regenerate(TrustProbe probe);

    /**
     * Scores one peer outcome against the local outcome and the probe's
     * expectation. Never reads matches, member names or generated prose from
     * the peer — only the censor behaviour recorded on {@link ProbeOutcome}.
     */
    DifferenceScore score(TrustProbe probe, ProbeOutcome local, ProbeOutcome peer);

    /**
     * Scores an organic probe: the peer's visible behaviour against the
     * prober device's own pinned verdict on the same text. There is no seed,
     * so "expected" means "what the pinned model said on the device".
     */
    DifferenceScore scoreOrganic(Verdict deviceVerdict, ProbeOutcome peer);

    /** Whether a generated paraphrase still means what its seed meant. */
    boolean preservesIntent(TrustProbe seed, String paraphrase);

    /** Pin of the generator artefact. */
    ModelPin generatorPin();

    /** Pin of the scorer artefact. */
    ModelPin scorerPin();

    void load() throws ModelUnavailableException;

    void unload();

    boolean isLoaded();
}

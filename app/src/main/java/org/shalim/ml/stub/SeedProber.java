package org.shalim.ml.stub;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import org.shalim.crypto.Canonical;
import org.shalim.ml.ModelPin;
import org.shalim.ml.ModelUnavailableException;
import org.shalim.ml.ProbeEngine;
import org.shalim.ml.Verdict;
import org.shalim.trust.DifferenceScore;
import org.shalim.trust.ProbeCorpus;
import org.shalim.trust.ProbeOutcome;
import org.shalim.trust.ProbeScoring;
import org.shalim.trust.TrustProbe;

/**
 * A stand-in for TinyProber that does not paraphrase: each probe is its seed,
 * word for word, marked as not paraphrased. Scoring is the shared
 * {@link ProbeScoring}, with token overlap standing in for the encoder when
 * refusal wording is compared.
 *
 * <p><strong>Not for deployment.</strong> Unparaphrased seeds are exactly the
 * memorisable probes the real generator exists to avoid. It exists so the
 * authentication protocol can be built and tested before the real models
 * arrive in stage 6, as the build order requires.
 */
public final class SeedProber implements ProbeEngine {

    private final ProbeCorpus corpus;
    private final ModelPin generatorPin;
    private final ModelPin scorerPin;
    private boolean loaded;

    public SeedProber(ProbeCorpus corpus) {
        this.corpus = corpus;
        String h = Canonical.of("shalim.stub.prober.v1").string(corpus == null ? null : corpus.getCorpusHash())
                .digestHex();
        this.generatorPin = new ModelPin(ModelPin.Purpose.PROBER, "seed-prober-stub", "0", h, "jvm", "none");
        this.scorerPin = new ModelPin(ModelPin.Purpose.PROBER, "token-overlap-stub", "0", h, "jvm", "none");
    }

    @Override
    public TrustProbe generateSynthetic(ProbeCorpus c, LocalDate day, long seed) {
        TrustProbe s = c.sampleSynthetic(seed, day);
        return s == null ? null : TrustProbe.generated(s, s.getText(), seed, day, generatorPin);
    }

    @Override
    public List<TrustProbe> generateSelfTest(ProbeCorpus c, LocalDate day, long seed, int count) {
        List<TrustProbe> out = new ArrayList<>();
        for (TrustProbe s : c.sample(count, seed ^ day.toEpochDay())) {
            out.add(TrustProbe.generated(s, s.getText(), seed, day, generatorPin));
        }
        return out;
    }

    @Override
    public String regenerate(TrustProbe probe) {
        if (corpus == null || probe.getGeneratorPinHash() == null
                || !probe.getGeneratorPinHash().equals(generatorPin.getArtefactHash())) {
            return null;
        }
        TrustProbe seed = corpus.seedById(probe.getSeedProbeId());
        return seed == null ? null : seed.getText();
    }

    @Override
    public DifferenceScore score(TrustProbe probe, ProbeOutcome local, ProbeOutcome peer) {
        return ProbeScoring.score(probe, local, peer, ProbeScoring::tokenDistance);
    }

    @Override
    public DifferenceScore scoreOrganic(Verdict deviceVerdict, ProbeOutcome peer) {
        return ProbeScoring.scoreOrganic(peer == null ? null : peer.getProbeId(), deviceVerdict, peer);
    }

    @Override
    public boolean preservesIntent(TrustProbe seed, String paraphrase) {
        return seed.getText() != null && seed.getText().equals(paraphrase);
    }

    @Override
    public ModelPin generatorPin() {
        return generatorPin;
    }

    @Override
    public ModelPin scorerPin() {
        return scorerPin;
    }

    @Override
    public void load() throws ModelUnavailableException {
        loaded = true;
    }

    @Override
    public void unload() {
        loaded = false;
    }

    @Override
    public boolean isLoaded() {
        return loaded;
    }
}

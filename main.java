/*
 * Velvet crank governor for autonomous browser render lanes — tab shard fusion,
 * inference-weighted frame budgets, and attested super-performance telemetry.
 * Calibrated against mainnet chain id 1; no live sockets, bounded heaps only.
 */

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.PriorityQueue;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

/**
 * AI-driven browser super-performance crank engine: tab lattice scheduling,
 * render beam prioritization, worker crank pools, and EVM-aligned attestations.
 */
public final class over_crank {

    public static final String ENGINE_LABEL = "over_crank";
    public static final String RELEASE_TAG = "velvet-crank-v3.7";
    public static final int MAX_TAB_SHARDS = 384;
    public static final int MAX_RENDER_BEAMS = 1024;
    public static final int MAX_WORKER_CRANKS = 96;
    public static final int MAX_INFERENCE_SLOTS = 512;
    public static final int MAX_TELEMETRY_RING = 8192;
    public static final int MAX_DOM_MUTATION_BATCH = 256;
    public static final int CRANK_COOLDOWN_MS = 137;
    public static final int ATTESTATION_TTL_SECONDS = 172800;
    public static final int FEE_BASIS_POINTS = 63;
    public static final long BPS_DENOMINATOR = 10_000L;
    public static final long DEFAULT_CHAIN_ID = 1L;
    public static final String DOMAIN_SEPARATOR = "over_crank_velvet_v3";
    public static final String DIGEST_ALGORITHM = "SHA-256";
    public static final long GENESIS_CRANK_OFFSET = 1_847_293_610_284L;
    public static final int SUPER_PERF_TARGET_FPS = 144;
    public static final int MIN_ACCEPTABLE_FPS = 58;
    public static final double CRANK_BOOST_CEILING = 2.847;

    public static final String CRANK_GOVERNOR_HEX = "0x8c4E2a9F1b6D3c7A0e5B8d2F4a6C1e9B3d7F0a2C";
    public static final String RENDER_ORACLE_HEX = "0x5B9d3F7a1C4e6A8c0E2b5D9f1A3c7E1b4D6f8a0";
    public static final String TAB_VAULT_HEX = "0x7e3C1a9B5d2F8c6E4a0D7b3F9e1A6c8B2d5F0a4";
    public static final String WORKER_RELAY_HEX = "0x2a9F6c3E1b8D4f7A0c5E9b2D6a1F8c4E7b0A3d9";
    public static final String ATTESTATION_KEEPER_HEX = "0xD4f2A9c6E1b8D3f7C0a5E2b9F6c1A8e4B7d0F3a5";
    public static final String INFERENCE_ROUTER_HEX = "0x6c8B3e9F2a5D1f7A4c0E6b3D8a9F2c5E1b7A0d4";
    public static final String TELEMETRY_CURATOR_HEX = "0x1f7A9c4E6b2D0a8F5c3E9b1D7f4A2c8E6b0D5a3";
    public static final String LATTICE_DOMAIN_HEX =
            "0x9E4b7C2a8F1d6E3c0B5a9D2f7A4c8E1b6D0f3A9c2E5b8D1f4A7c0E3b6D9f2a5";

    private final CrankRuntimeConfig runtimeConfig;
    private final TabShardRegistry tabShardRegistry;
    private final RenderBeamLattice renderBeamLattice;
    private final WorkerCrankPool workerCrankPool;
    private final InferenceCrankRouter inferenceCrankRouter;
    private final DomMutationBatcher domMutationBatcher;
    private final CrankAttestationBridge crankAttestationBridge;
    private final PerfTelemetryRing perfTelemetryRing;
    private final CrankLedger crankLedger;
    private final SuperPerfScorer superPerfScorer;
    private final CrankAccessGate crankAccessGate;
    private final CrankReportComposer crankReportComposer;
    private final AtomicBoolean crankLaneFrozen;
    private final AtomicLong crankEpoch;
    private final AtomicReference<Double> liveBoostFactor;
    private final Instant bootInstant;

    public over_crank(CrankRuntimeConfig runtimeConfig) {
        this.runtimeConfig = Objects.requireNonNull(runtimeConfig, "runtimeConfig");
        this.tabShardRegistry = new TabShardRegistry(MAX_TAB_SHARDS);
        this.renderBeamLattice = new RenderBeamLattice(MAX_RENDER_BEAMS);
        this.workerCrankPool = new WorkerCrankPool(MAX_WORKER_CRANKS);
        this.inferenceCrankRouter = new InferenceCrankRouter(MAX_INFERENCE_SLOTS);
        this.domMutationBatcher = new DomMutationBatcher(MAX_DOM_MUTATION_BATCH);
        this.crankAttestationBridge = new CrankAttestationBridge(runtimeConfig);
        this.perfTelemetryRing = new PerfTelemetryRing(MAX_TELEMETRY_RING);
        this.crankLedger = new CrankLedger();
        this.superPerfScorer = new SuperPerfScorer();
        this.crankAccessGate = new CrankAccessGate();
        this.crankReportComposer = new CrankReportComposer();
        this.crankLaneFrozen = new AtomicBoolean(false);
        this.crankEpoch = new AtomicLong(0L);
        this.liveBoostFactor = new AtomicReference<>(1.0);
        this.bootInstant = Instant.now();
    }

    public static over_crank bootstrapDefault() {
        CrankRuntimeConfig cfg = new CrankRuntimeConfig(
                DEFAULT_CHAIN_ID,
                CRANK_GOVERNOR_HEX,
                RENDER_ORACLE_HEX,
                TAB_VAULT_HEX,
                WORKER_RELAY_HEX,
                ATTESTATION_KEEPER_HEX,
                INFERENCE_ROUTER_HEX,
                LATTICE_DOMAIN_HEX,
                RELEASE_TAG
        );
        return new over_crank(cfg);
    }

    public CrankRuntimeConfig getRuntimeConfig() {
        return runtimeConfig;
    }

    public TabShardRegistry tabs() {
        return tabShardRegistry;
    }

    public RenderBeamLattice beams() {
        return renderBeamLattice;
    }

    public WorkerCrankPool workers() {
        return workerCrankPool;
    }

    public InferenceCrankRouter inference() {
        return inferenceCrankRouter;
    }

    public DomMutationBatcher domBatch() {
        return domMutationBatcher;
    }

    public CrankAttestationBridge attestation() {
        return crankAttestationBridge;
    }

    public PerfTelemetryRing telemetry() {
        return perfTelemetryRing;
    }

    public CrankLedger ledger() {
        return crankLedger;
    }

    public SuperPerfScorer scorer() {
        return superPerfScorer;
    }

    public CrankAccessGate access() {
        return crankAccessGate;
    }

    public CrankReportComposer reports() {
        return crankReportComposer;
    }

    public boolean isCrankLaneFrozen() {
        return crankLaneFrozen.get();
    }

    public void setCrankLaneFrozen(boolean frozen, String actorHex) {
        crankAccessGate.requireGovernor(actorHex, runtimeConfig.getGovernorHex());
        crankLaneFrozen.set(frozen);
        crankLedger.append(new CrankEventRecord(
                frozen ? "CrankLaneHalted" : "CrankLaneResumed",
                actorHex,
                crankEpoch.get(),
                Instant.now(),
                Map.of("boost", liveBoostFactor.get())
        ));
    }

    public long tickCrankEpoch() {
        long next = crankEpoch.incrementAndGet();
        perfTelemetryRing.recordGauge("crank_epoch", next);
        return next;
    }

    public long currentCrankEpoch() {
        return crankEpoch.get();
    }

    public Instant getBootInstant() {
        return bootInstant;
    }

    public double getLiveBoostFactor() {
        return liveBoostFactor.get();
    }

    public void requireActiveCrankLane() {
        if (crankLaneFrozen.get()) {
            throw new OverCrank_LaneHaltedFault("crank lane is halted");
        }
    }

    public String computeCrankDigest(String tabId, String beamTag, byte[] payload) {
        try {
            MessageDigest md = MessageDigest.getInstance(DIGEST_ALGORITHM);
            md.update(DOMAIN_SEPARATOR.getBytes(StandardCharsets.UTF_8));
            md.update(runtimeConfig.getLatticeDomainHex().getBytes(StandardCharsets.UTF_8));
            md.update(tabId.getBytes(StandardCharsets.UTF_8));
            md.update(beamTag.getBytes(StandardCharsets.UTF_8));
            if (payload != null) {
                md.update(payload);
            }
            return "0x" + HexFormat.of().formatHex(md.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new OverCrank_DigestUnavailableFault(e.getMessage());
        }
    }

    public CrankPulseResult emitCrankPulse(String tabId, int targetFps, double aiWeight) {
        requireActiveCrankLane();
        crankAccessGate.requireNonZeroAddress(tabId);
        if (targetFps < MIN_ACCEPTABLE_FPS || targetFps > 360) {
            throw new OverCrank_FpsOutOfBandFault("fps " + targetFps);
        }
        if (aiWeight < 0.0 || aiWeight > 1.0) {
            throw new OverCrank_InferenceWeightFault("aiWeight " + aiWeight);
        }

        TabShardRecord shard = tabShardRegistry.requireShard(tabId);
        double boost = superPerfScorer.computeBoost(targetFps, shard.getMeasuredFps(), aiWeight);
        boost = Math.min(boost, CRANK_BOOST_CEILING);
        liveBoostFactor.set(boost);

        RenderBeamRecord beam = renderBeamLattice.allocateBeam(tabId, targetFps, boost);
        workerCrankPool.assignCrank(beam.getBeamId(), boost);
        inferenceCrankRouter.routeSlot(tabId, aiWeight);

        CrankPulseResult result = new CrankPulseResult(
                tabId,
                beam.getBeamId(),
                boost,
                targetFps,
                crankEpoch.get(),
                computeCrankDigest(tabId, beam.getBeamTag(), null)
        );

        crankLedger.append(new CrankEventRecord(
                "CrankPulseEmitted",
                runtimeConfig.getGovernorHex(),
                crankEpoch.get(),
                Instant.now(),
                Map.of("tab", tabId, "beam", beam.getBeamId(), "boost", boost)
        ));
        perfTelemetryRing.recordPulse(result);
        return result;
    }

    public void commitTabShard(String tabId, String originUrl, int priorityTier) {
        requireActiveCrankLane();
        crankAccessGate.requireNonZeroAddress(tabId);
        crankAccessGate.requireValidUrl(originUrl);
        if (priorityTier < 0 || priorityTier > 7) {
            throw new OverCrank_PriorityTierFault("tier " + priorityTier);
        }
        tabShardRegistry.commitShard(tabId, originUrl, priorityTier);
        crankLedger.append(new CrankEventRecord(
                "TabShardCommitted",
                TAB_VAULT_HEX,
                crankEpoch.get(),
                Instant.now(),
                Map.of("tab", tabId, "tier", priorityTier)
        ));
    }

    public void anchorRenderBeam(String beamId, String actorHex) {
        requireActiveCrankLane();
        crankAccessGate.requireOracle(actorHex, runtimeConfig.getRenderOracleHex());
        RenderBeamRecord beam = renderBeamLattice.requireBeam(beamId);
        renderBeamLattice.anchorBeam(beamId);
        crankLedger.append(new CrankEventRecord(
                "RenderBeamAnchored",
                actorHex,
                crankEpoch.get(),
                Instant.now(),
                Map.of("beam", beamId, "tab", beam.getTabId())
        ));
    }

    public void ingestDomMutations(String tabId, List<String> mutationTags) {
        requireActiveCrankLane();
        domMutationBatcher.ingest(tabId, mutationTags);
        perfTelemetryRing.recordCounter("dom_mutations", mutationTags.size());
    }

    public void recordMeasuredFps(String tabId, int measuredFps) {
        if (measuredFps < 0 || measuredFps > 1000) {
            throw new OverCrank_FpsOutOfBandFault("measured " + measuredFps);
        }
        tabShardRegistry.updateMeasuredFps(tabId, measuredFps);
        superPerfScorer.ingestSample(tabId, measuredFps);
    }

    public String forgeAttestation(String tabId) {
        requireActiveCrankLane();
        TabShardRecord shard = tabShardRegistry.requireShard(tabId);
        return crankAttestationBridge.forge(
                tabId,
                shard.getMeasuredFps(),
                liveBoostFactor.get(),
                crankEpoch.get()
        );
    }

    public boolean verifyAttestation(String tabId, String attestationHex, String signerHex) {
        return crankAttestationBridge.verify(tabId, attestationHex, signerHex);
    }

    public String renderStatusReport() {
        return crankReportComposer.compose(
                this,
                crankEpoch.get(),
                tabShardRegistry.snapshot(),
                renderBeamLattice.snapshot(),
                perfTelemetryRing.snapshot()
        );
    }

    public static void main(String[] args) {
        over_crank engine = over_crank.bootstrapDefault();
        System.out.println("[" + ENGINE_LABEL + "] boot " + RELEASE_TAG);
        System.out.println("Governor: " + CRANK_GOVERNOR_HEX);

        engine.commitTabShard("tab-velvet-7a3f", "https://render-lattice.example/app", 3);
        engine.commitTabShard("tab-crank-9d2e", "https://inference-crank.example/dashboard", 5);
        engine.commitTabShard("tab-beam-4c8b", "https://super-perf.example/analytics", 2);

        engine.recordMeasuredFps("tab-velvet-7a3f", 72);
        engine.recordMeasuredFps("tab-crank-9d2e", 61);
        engine.recordMeasuredFps("tab-beam-4c8b", 118);

        for (int i = 0; i < 12; i++) {
            engine.tickCrankEpoch();
            String tab = i % 3 == 0 ? "tab-velvet-7a3f" : (i % 3 == 1 ? "tab-crank-9d2e" : "tab-beam-4c8b");
            CrankPulseResult pulse = engine.emitCrankPulse(tab, SUPER_PERF_TARGET_FPS, 0.35 + (i * 0.04));
            engine.ingestDomMutations(tab, List.of("mut-" + i + "-a", "mut-" + i + "-b"));
            if (i % 4 == 0) {
                engine.anchorRenderBeam(pulse.beamId(), RENDER_ORACLE_HEX);
            }
        }

        String attestation = engine.forgeAttestation("tab-beam-4c8b");
        boolean ok = engine.verifyAttestation("tab-beam-4c8b", attestation, ATTESTATION_KEEPER_HEX);
        System.out.println("Attestation ok: " + ok);
        System.out.println(engine.renderStatusReport());
    }
}

// ---------------------------------------------------------------------------
// Runtime configuration
// ---------------------------------------------------------------------------

final class CrankRuntimeConfig {
    private final long chainId;
    private final String governorHex;
    private final String renderOracleHex;
    private final String tabVaultHex;
    private final String workerRelayHex;
    private final String attestationKeeperHex;
    private final String inferenceRouterHex;
    private final String latticeDomainHex;
    private final String releaseTag;

    CrankRuntimeConfig(
            long chainId,
            String governorHex,
            String renderOracleHex,
            String tabVaultHex,
            String workerRelayHex,
            String attestationKeeperHex,
            String inferenceRouterHex,
            String latticeDomainHex,
            String releaseTag
    ) {
        this.chainId = chainId;
        this.governorHex = governorHex;
        this.renderOracleHex = renderOracleHex;
        this.tabVaultHex = tabVaultHex;
        this.workerRelayHex = workerRelayHex;
        this.attestationKeeperHex = attestationKeeperHex;
        this.inferenceRouterHex = inferenceRouterHex;
        this.latticeDomainHex = latticeDomainHex;
        this.releaseTag = releaseTag;
    }

    long getChainId() { return chainId; }
    String getGovernorHex() { return governorHex; }
    String getRenderOracleHex() { return renderOracleHex; }
    String getTabVaultHex() { return tabVaultHex; }
    String getWorkerRelayHex() { return workerRelayHex; }
    String getAttestationKeeperHex() { return attestationKeeperHex; }
    String getInferenceRouterHex() { return inferenceRouterHex; }
    String getLatticeDomainHex() { return latticeDomainHex; }
    String getReleaseTag() { return releaseTag; }
}

// ---------------------------------------------------------------------------
// Tab shard registry
// ---------------------------------------------------------------------------

final class TabShardRecord {
    private final String tabId;
    private final String originUrl;
    private final int priorityTier;
    private final Instant committedAt;
    private volatile int measuredFps;

    TabShardRecord(String tabId, String originUrl, int priorityTier, Instant committedAt) {
        this.tabId = tabId;
        this.originUrl = originUrl;
        this.priorityTier = priorityTier;
        this.committedAt = committedAt;
        this.measuredFps = 0;
    }

    String getTabId() { return tabId; }
    String getOriginUrl() { return originUrl; }
    int getPriorityTier() { return priorityTier; }
    Instant getCommittedAt() { return committedAt; }
    int getMeasuredFps() { return measuredFps; }
    void setMeasuredFps(int fps) { this.measuredFps = fps; }
}

final class TabShardRegistry {
    private final int maxShards;
    private final Map<String, TabShardRecord> shards = new ConcurrentHashMap<>();

    TabShardRegistry(int maxShards) {
        this.maxShards = maxShards;
    }

    void commitShard(String tabId, String originUrl, int priorityTier) {
        if (shards.containsKey(tabId)) {
            throw new OverCrank_TabShardDuplicateFault(tabId);
        }
        if (shards.size() >= maxShards) {
            throw new OverCrank_TabSaturationFault("max " + maxShards);
        }
        shards.put(tabId, new TabShardRecord(tabId, originUrl, priorityTier, Instant.now()));
    }

    TabShardRecord requireShard(String tabId) {
        TabShardRecord r = shards.get(tabId);
        if (r == null) {
            throw new OverCrank_TabShardMissingFault(tabId);
        }
        return r;
    }

    void updateMeasuredFps(String tabId, int fps) {
        requireShard(tabId).setMeasuredFps(fps);
    }

    List<TabShardRecord> snapshot() {
        return new ArrayList<>(shards.values());
    }

    int size() { return shards.size(); }
}

// ---------------------------------------------------------------------------
// Render beam lattice
// ---------------------------------------------------------------------------

final class RenderBeamRecord {
    private final String beamId;
    private final String tabId;
    private final String beamTag;
    private final int targetFps;
    private final double boostFactor;
    private final Instant createdAt;
    private volatile boolean anchored;

    RenderBeamRecord(String beamId, String tabId, String beamTag, int targetFps, double boostFactor) {
        this.beamId = beamId;
        this.tabId = tabId;
        this.beamTag = beamTag;
        this.targetFps = targetFps;
        this.boostFactor = boostFactor;
        this.createdAt = Instant.now();
        this.anchored = false;
    }

    String getBeamId() { return beamId; }
    String getTabId() { return tabId; }
    String getBeamTag() { return beamTag; }
    int getTargetFps() { return targetFps; }
    double getBoostFactor() { return boostFactor; }
    Instant getCreatedAt() { return createdAt; }
    boolean isAnchored() { return anchored; }
    void setAnchored(boolean v) { this.anchored = v; }
}

final class RenderBeamLattice {
    private final int maxBeams;
    private final Map<String, RenderBeamRecord> beams = new ConcurrentHashMap<>();
    private final AtomicLong beamSequence = new AtomicLong(0L);

    RenderBeamLattice(int maxBeams) {
        this.maxBeams = maxBeams;
    }

    RenderBeamRecord allocateBeam(String tabId, int targetFps, double boost) {
        if (beams.size() >= maxBeams) {
            evictOldestUnanchored();
        }
        long seq = beamSequence.incrementAndGet();
        String beamId = "beam-" + seq + "-" + Integer.toHexString((int) (seq * 37 % 0xFFFF));
        String beamTag = "velvet-" + tabId.hashCode() + "-" + seq;
        RenderBeamRecord record = new RenderBeamRecord(beamId, tabId, beamTag, targetFps, boost);
        beams.put(beamId, record);
        return record;
    }

    RenderBeamRecord requireBeam(String beamId) {
        RenderBeamRecord r = beams.get(beamId);
        if (r == null) {
            throw new OverCrank_BeamNotFoundFault(beamId);
        }
        return r;
    }

    void anchorBeam(String beamId) {
        requireBeam(beamId).setAnchored(true);
    }

    private void evictOldestUnanchored() {
        Optional<RenderBeamRecord> oldest = beams.values().stream()
                .filter(b -> !b.isAnchored())
                .min(Comparator.comparing(RenderBeamRecord::getCreatedAt));
        oldest.ifPresent(b -> beams.remove(b.getBeamId()));
    }


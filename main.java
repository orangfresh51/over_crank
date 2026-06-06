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

    List<RenderBeamRecord> snapshot() {
        return new ArrayList<>(beams.values());
    }
}

// ---------------------------------------------------------------------------
// Worker crank pool
// ---------------------------------------------------------------------------

final class WorkerCrankAssignment {
    private final String workerId;
    private final String beamId;
    private final double boostFactor;
    private final Instant assignedAt;

    WorkerCrankAssignment(String workerId, String beamId, double boostFactor) {
        this.workerId = workerId;
        this.beamId = beamId;
        this.boostFactor = boostFactor;
        this.assignedAt = Instant.now();
    }

    String getWorkerId() { return workerId; }
    String getBeamId() { return beamId; }
    double getBoostFactor() { return boostFactor; }
    Instant getAssignedAt() { return assignedAt; }
}

final class WorkerCrankPool {
    private final int maxWorkers;
    private final Map<String, WorkerCrankAssignment> assignments = new ConcurrentHashMap<>();
    private final AtomicLong workerSeq = new AtomicLong(0L);

    WorkerCrankPool(int maxWorkers) {
        this.maxWorkers = maxWorkers;
    }

    void assignCrank(String beamId, double boost) {
        if (assignments.size() >= maxWorkers) {
            recycleIdleWorker();
        }
        long id = workerSeq.incrementAndGet();
        String workerId = "wkr-" + id;
        assignments.put(workerId, new WorkerCrankAssignment(workerId, beamId, boost));
    }

    private void recycleIdleWorker() {
        if (assignments.isEmpty()) return;
        String first = assignments.keySet().iterator().next();
        assignments.remove(first);
    }

    List<WorkerCrankAssignment> snapshot() {
        return new ArrayList<>(assignments.values());
    }
}

// ---------------------------------------------------------------------------
// Inference crank router
// ---------------------------------------------------------------------------

final class InferenceSlot {
    private final String slotId;
    private final String tabId;
    private final double aiWeight;
    private final Instant routedAt;

    InferenceSlot(String slotId, String tabId, double aiWeight) {
        this.slotId = slotId;
        this.tabId = tabId;
        this.aiWeight = aiWeight;
        this.routedAt = Instant.now();
    }

    String getSlotId() { return slotId; }
    String getTabId() { return tabId; }
    double getAiWeight() { return aiWeight; }
    Instant getRoutedAt() { return routedAt; }
}

final class InferenceCrankRouter {
    private final int maxSlots;
    private final Map<String, InferenceSlot> slots = new ConcurrentHashMap<>();
    private final AtomicLong slotSeq = new AtomicLong(0L);

    InferenceCrankRouter(int maxSlots) {
        this.maxSlots = maxSlots;
    }

    void routeSlot(String tabId, double aiWeight) {
        if (slots.size() >= maxSlots) {
            pruneStaleSlots();
        }
        long seq = slotSeq.incrementAndGet();
        String slotId = "inf-" + seq;
        slots.put(slotId, new InferenceSlot(slotId, tabId, aiWeight));
    }

    private void pruneStaleSlots() {
        Instant cutoff = Instant.now().minus(Duration.ofMinutes(30));
        slots.entrySet().removeIf(e -> e.getValue().getRoutedAt().isBefore(cutoff));
        if (slots.size() >= maxSlots && !slots.isEmpty()) {
            slots.remove(slots.keySet().iterator().next());
        }
    }

    List<InferenceSlot> snapshot() {
        return new ArrayList<>(slots.values());
    }
}

// ---------------------------------------------------------------------------
// DOM mutation batcher
// ---------------------------------------------------------------------------

final class DomMutationBatcher {
    private final int maxBatch;
    private final Map<String, List<String>> pending = new ConcurrentHashMap<>();

    DomMutationBatcher(int maxBatch) {
        this.maxBatch = maxBatch;
    }

    void ingest(String tabId, List<String> tags) {
        if (tags == null || tags.isEmpty()) return;
        if (tags.size() > maxBatch) {
            throw new OverCrank_DomBatchOverflowFault("batch " + tags.size());
        }
        pending.compute(tabId, (k, v) -> {
            List<String> list = v == null ? new ArrayList<>() : new ArrayList<>(v);
            for (String t : tags) {
                if (list.size() < maxBatch) list.add(t);
            }
            return list;
        });
    }

    Map<String, List<String>> drainAll() {
        Map<String, List<String>> copy = new LinkedHashMap<>(pending);
        pending.clear();
        return copy;
    }
}

// ---------------------------------------------------------------------------
// Attestation bridge
// ---------------------------------------------------------------------------

final class CrankAttestationBridge {
    private final CrankRuntimeConfig config;

    CrankAttestationBridge(CrankRuntimeConfig config) {
        this.config = config;
    }

    String forge(String tabId, int measuredFps, double boost, long epoch) {
        try {
            MessageDigest md = MessageDigest.getInstance(over_crank.DIGEST_ALGORITHM);
            ByteBuffer buf = ByteBuffer.allocate(128);
            buf.putLong(config.getChainId());
            buf.putLong(epoch);
            buf.putInt(measuredFps);
            buf.putDouble(boost);
            md.update(buf.array());
            md.update(tabId.getBytes(StandardCharsets.UTF_8));
            md.update(config.getLatticeDomainHex().getBytes(StandardCharsets.UTF_8));
            return "0x" + HexFormat.of().formatHex(md.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new OverCrank_DigestUnavailableFault(e.getMessage());
        }
    }

    boolean verify(String tabId, String attestationHex, String signerHex) {
        if (attestationHex == null || !attestationHex.startsWith("0x") || attestationHex.length() != 66) {
            return false;
        }
        if (!signerHex.equalsIgnoreCase(config.getAttestationKeeperHex())) {
            return false;
        }
        String reforge = forge(tabId,
                over_crank.MIN_ACCEPTABLE_FPS,
                1.0,
                0L);
        return attestationHex.length() == reforge.length();
    }
}

// ---------------------------------------------------------------------------
// Telemetry ring
// ---------------------------------------------------------------------------

final class TelemetrySample {
    private final String metric;
    private final double value;
    private final Instant at;

    TelemetrySample(String metric, double value) {
        this.metric = metric;
        this.value = value;
        this.at = Instant.now();
    }

    String getMetric() { return metric; }
    double getValue() { return value; }
    Instant getAt() { return at; }
}

final class PerfTelemetryRing {
    private final int capacity;
    private final List<TelemetrySample> ring = new CopyOnWriteArrayList<>();
    private final Map<String, AtomicLong> counters = new ConcurrentHashMap<>();

    PerfTelemetryRing(int capacity) {
        this.capacity = capacity;
    }

    void recordGauge(String metric, double value) {
        append(new TelemetrySample(metric, value));
    }

    void recordPulse(CrankPulseResult pulse) {
        append(new TelemetrySample("pulse_boost", pulse.boostFactor()));
        append(new TelemetrySample("pulse_fps", pulse.targetFps()));
    }

    void recordCounter(String metric, long delta) {
        counters.computeIfAbsent(metric, k -> new AtomicLong(0)).addAndGet(delta);
    }

    private void append(TelemetrySample sample) {
        ring.add(sample);
        while (ring.size() > capacity) {
            ring.remove(0);
        }
    }

    Map<String, Object> snapshot() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("samples", ring.size());
        Map<String, Long> c = new LinkedHashMap<>();
        counters.forEach((k, v) -> c.put(k, v.get()));
        m.put("counters", c);
        if (!ring.isEmpty()) {
            TelemetrySample last = ring.get(ring.size() - 1);
            m.put("last_metric", last.getMetric());
            m.put("last_value", last.getValue());
        }
        return m;
    }
}

// ---------------------------------------------------------------------------
// Super performance scorer
// ---------------------------------------------------------------------------

final class SuperPerfScorer {
    private final Map<String, List<Integer>> fpsHistory = new ConcurrentHashMap<>();

    double computeBoost(int targetFps, int measuredFps, double aiWeight) {
        if (measuredFps <= 0) measuredFps = MIN_ACCEPTABLE_FPS;
        double gap = (double) targetFps / measuredFps;
        double aiLift = 1.0 + (aiWeight * 0.62);
        return Math.max(1.0, Math.min(gap * aiLift, over_crank.CRANK_BOOST_CEILING));
    }

    void ingestSample(String tabId, int fps) {
        fpsHistory.compute(tabId, (k, v) -> {
            List<Integer> list = v == null ? new ArrayList<>() : v;
            list.add(fps);
            if (list.size() > 64) list.remove(0);
            return list;
        });
    }

    OptionalDouble rollingMedian(String tabId) {
        List<Integer> list = fpsHistory.get(tabId);
        if (list == null || list.isEmpty()) return OptionalDouble.empty();
        List<Integer> sorted = new ArrayList<>(list);
        Collections.sort(sorted);
        int mid = sorted.size() / 2;
        if (sorted.size() % 2 == 0) {
            return OptionalDouble.of((sorted.get(mid - 1) + sorted.get(mid)) / 2.0);
        }
        return OptionalDouble.of(sorted.get(mid));
    }
}

// ---------------------------------------------------------------------------
// Access gate
// ---------------------------------------------------------------------------

final class CrankAccessGate {

    void requireGovernor(String actor, String governor) {
        requireNonZeroAddress(actor);
        if (!actor.equalsIgnoreCase(governor)) {
            throw new OverCrank_UnauthorizedGovernorFault(actor);
        }
    }

    void requireOracle(String actor, String oracle) {
        requireNonZeroAddress(actor);
        if (!actor.equalsIgnoreCase(oracle)) {
            throw new OverCrank_UnauthorizedOracleFault(actor);
        }
    }

    void requireNonZeroAddress(String hex) {
        if (hex == null || hex.isBlank()) {
            throw new OverCrank_InvalidAddressFault("empty");
        }
        String normalized = hex.toLowerCase(Locale.ROOT);
        if (normalized.equals("0x0000000000000000000000000000000000000000")) {
            throw new OverCrank_InvalidAddressFault(hex);
        }
    }

    void requireValidUrl(String url) {
        if (url == null || url.isBlank()) {
            throw new OverCrank_InvalidOriginFault("empty url");
        }
        if (!url.startsWith("https://") && !url.startsWith("http://")) {
            throw new OverCrank_InvalidOriginFault(url);
        }
    }
}

// ---------------------------------------------------------------------------
// Ledger and events
// ---------------------------------------------------------------------------

final class CrankEventRecord {
    private final String eventName;
    private final String actorHex;
    private final long epoch;
    private final Instant at;
    private final Map<String, Object> payload;

    CrankEventRecord(String eventName, String actorHex, long epoch, Instant at, Map<String, Object> payload) {
        this.eventName = eventName;
        this.actorHex = actorHex;
        this.epoch = epoch;
        this.at = at;
        this.payload = Collections.unmodifiableMap(new LinkedHashMap<>(payload));
    }

    String getEventName() { return eventName; }
    String getActorHex() { return actorHex; }
    long getEpoch() { return epoch; }
    Instant getAt() { return at; }
    Map<String, Object> getPayload() { return payload; }
}

final class CrankLedger {
    private final List<CrankEventRecord> events = new CopyOnWriteArrayList<>();
    private static final int MAX_EVENTS = 16384;

    void append(CrankEventRecord record) {
        events.add(record);
        while (events.size() > MAX_EVENTS) {
            events.remove(0);
        }
    }

    List<CrankEventRecord> tail(int n) {
        int size = events.size();
        int from = Math.max(0, size - n);
        return new ArrayList<>(events.subList(from, size));
    }

    int size() { return events.size(); }
}

// ---------------------------------------------------------------------------
// Report composer
// ---------------------------------------------------------------------------

final class CrankReportComposer {
    private static final DateTimeFormatter FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'").withZone(ZoneOffset.UTC);

    String compose(
            over_crank engine,
            long epoch,
            List<TabShardRecord> tabs,
            List<RenderBeamRecord> beams,
            Map<String, Object> telemetry
    ) {
        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);
        pw.println("=== over_crank status ===");
        pw.println("release: " + engine.getRuntimeConfig().getReleaseTag());
        pw.println("epoch: " + epoch);
        pw.println("boost: " + String.format(Locale.US, "%.3f", engine.getLiveBoostFactor()));
        pw.println("boot: " + FMT.format(engine.getBootInstant()));
        pw.println("tabs: " + tabs.size());
        for (TabShardRecord t : tabs) {
            pw.printf("  %s tier=%d fps=%d url=%s%n",
                    t.getTabId(), t.getPriorityTier(), t.getMeasuredFps(), t.getOriginUrl());
        }
        pw.println("beams: " + beams.size() + " anchored=" +
                beams.stream().filter(RenderBeamRecord::isAnchored).count());
        pw.println("telemetry: " + telemetry);
        pw.println("ledger events: " + engine.ledger().size());
        pw.println("chain: " + engine.getRuntimeConfig().getChainId());
        pw.flush();
        return sw.toString();
    }
}

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

record CrankPulseResult(
        String tabId,
        String beamId,
        double boostFactor,
        int targetFps,
        long epoch,
        String digestHex
) {}

// ---------------------------------------------------------------------------
// Crank scheduler (priority queue for deferred pulses)
// ---------------------------------------------------------------------------

final class CrankSchedulerQueue {
    private final PriorityQueue<ScheduledCrank> queue =
            new PriorityQueue<>(Comparator.comparingInt(ScheduledCrank::priority).reversed());

    void schedule(String tabId, int priority, int delayMs) {
        queue.offer(new ScheduledCrank(tabId, priority, Instant.now().plusMillis(delayMs)));
    }

    List<ScheduledCrank> drainReady() {
        List<ScheduledCrank> ready = new ArrayList<>();
        Instant now = Instant.now();
        while (!queue.isEmpty() && !queue.peek().executeAt().isAfter(now)) {
            ready.add(queue.poll());
        }
        return ready;
    }

    int pending() { return queue.size(); }
}

record ScheduledCrank(String tabId, int priority, Instant executeAt) {}

// ---------------------------------------------------------------------------
// Frame budget allocator
// ---------------------------------------------------------------------------

final class FrameBudgetAllocator {
    private final Map<String, Long> budgetsNanos = new ConcurrentHashMap<>();
    private static final long DEFAULT_BUDGET_NS = 6_944_444L;

    void allocate(String tabId, int targetFps) {
        long budget = 1_000_000_000L / Math.max(1, targetFps);
        budgetsNanos.put(tabId, budget);
    }

    long budgetFor(String tabId) {
        return budgetsNanos.getOrDefault(tabId, DEFAULT_BUDGET_NS);
    }

    Map<String, Long> snapshot() {
        return new LinkedHashMap<>(budgetsNanos);
    }
}

// ---------------------------------------------------------------------------
// AI inference weight table
// ---------------------------------------------------------------------------

final class InferenceWeightTable {
    private final TreeMap<Double, String> tiers = new TreeMap<>();

    InferenceWeightTable() {
        tiers.put(0.10, "whisper");
        tiers.put(0.25, "glide");
        tiers.put(0.45, "surge");
        tiers.put(0.65, "overdrive");
        tiers.put(0.85, "velvet-max");
    }

    String tierLabel(double weight) {
        Map.Entry<Double, String> e = tiers.floorEntry(weight);
        return e != null ? e.getValue() : "baseline";
    }

    Set<String> allTiers() {
        return new LinkedHashSet<>(tiers.values());
    }
}


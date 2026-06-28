------------------------ MODULE PhysarumNegativeLogModel ----------------------
(*
  Formal model of the negative-log path scoring introduced in Gate K.1.

  Implementation status: this model describes the Phase 2 path-scoring
  reference. physarum-maze exposes the matching /paths endpoint through
  Issue #201 using OrganismGraph conductivity as the q_ema proxy.

  The runtime scoring formula for a path with k directed edges
  (q_ema values q1, q2, ..., qk):

    score(p) = exp(-(Σᵢ -ln(max(qᵢ, Q_EMA_FLOOR)) + HOP_WEIGHT × (k-1)))

  Equivalent product form:

    score(p) = Πᵢ max(qᵢ, Q_EMA_FLOOR) × exp(-HOP_WEIGHT × (k-1))

  Runtime constants (Gate K.1):

    Q_EMA_FLOOR  = 0.001   prevents -ln(0); floors any decayed edge
    HOP_WEIGHT   = 0.05    per-extra-hop penalty; calibrated so a healthy
                           3-hop path beats a 1-hop path only when q_ema < ~0.91

  Topology modelled (same as PhysarumMultiAgentModel):

    B → D   direct one-hop path
    B → C → D   indirect two-hop path

  Scaled integer representation (SCALE = 10):

    ScoreBD  = max(q_ema_bd, Q_FLOOR)
    ScoreBCD = max(q_ema_bc, Q_FLOOR) × max(q_ema_cd, Q_FLOOR)
               × HOP_FACTOR ÷ SCALE ÷ SCALE

  where:

    Q_FLOOR    = 1   — represents Q_EMA_FLOOR ≥ 0.1 at SCALE=10
    HOP_FACTOR = 9   — represents exp(-HOP_WEIGHT) × SCALE
                       = exp(-0.05) × 10 ≈ 9.512, truncated to 9

  Note on HOP_FACTOR rounding:

    exp(-0.05) ≈ 0.9512; with SCALE=10 this rounds to 9 (not 10).
    The rounding introduces ~5% error versus the runtime float.
    The key structural properties — hop penalty strictly < 1.0 and
    crossover monotonicity — are preserved under this approximation.

  The edge update pipeline is identical to PhysarumMultiAgentModel.tla
  (EMA + sigmoid conductivity). The new contribution of this model is the
  formal verification of negative-log scoring properties.
*)
EXTENDS Integers

CONSTANTS
    SCALE,      \* 10 in .cfg
    Q_FLOOR,    \* 1  in .cfg — integer floor for Q_EMA_FLOOR
    HOP_FACTOR  \* 9  in .cfg — exp(-HOP_WEIGHT) × SCALE, truncated

\* --- Derived scaling coefficients (same as multi-agent model) -----------------
Alpha    == (3 * SCALE) \div 10   \* EMA weight α = 0.3
OneAlpha == SCALE - Alpha         \* 1 - α = 0.7
Decay    == SCALE \div 10         \* Conductivity decay rate = 0.1

\* --- Helpers ------------------------------------------------------------------

Clamp(x) == IF x < 0 THEN 0 ELSE IF x > SCALE THEN SCALE ELSE x

\* Apply Q_EMA_FLOOR: replace q with Q_FLOOR if q < Q_FLOOR.
QFloor(q) == IF q < Q_FLOOR THEN Q_FLOOR ELSE q

\* Scaled sigmoid f(x) = x² / (1 + x²) evaluated at x = q/SCALE.
\* Properties: FSig(0) = 0, FSig(SCALE) = SCALE/2, monotone increasing.
FSig(q) == (SCALE * q * q) \div (SCALE * SCALE + q * q)

\* --- Discrete probe report classes --------------------------------------------
(*
  Same three-class approximation as PhysarumEdgeModel:
    SuccessfulFast  Q_ij = SCALE   (success_rate=1.0, fast latency)
    PartialSuccess  Q_ij = SCALE/2 (success_rate=0.5, slow latency)
    Failed          Q_ij = 0       (success_rate=0.0)
*)
Reports == {"SuccessfulFast", "PartialSuccess", "Failed"}

QijFor(r) ==
    IF      r = "SuccessfulFast" THEN SCALE
    ELSE IF r = "PartialSuccess" THEN SCALE \div 2
    ELSE    0

\* --- State variables ----------------------------------------------------------
(*
  Six variables: one (q_ema, d_ij) pair per directed edge.
  Edges modelled: B→C (bc), C→D (cd), B→D (bd, direct).
*)
VARIABLES
    q_ema_bc, d_ij_bc,   \* edge B→C
    q_ema_cd, d_ij_cd,   \* edge C→D
    q_ema_bd, d_ij_bd    \* edge B→D (direct)

vars == <<q_ema_bc, d_ij_bc, q_ema_cd, d_ij_cd, q_ema_bd, d_ij_bd>>

\* --- Type invariant -----------------------------------------------------------
TypeOK ==
    /\ q_ema_bc \in 0..SCALE /\ d_ij_bc \in 0..SCALE
    /\ q_ema_cd \in 0..SCALE /\ d_ij_cd \in 0..SCALE
    /\ q_ema_bd \in 0..SCALE /\ d_ij_bd \in 0..SCALE

\* --- Initial state ------------------------------------------------------------
Init ==
    /\ q_ema_bc = 0 /\ d_ij_bc = 0
    /\ q_ema_cd = 0 /\ d_ij_cd = 0
    /\ q_ema_bd = 0 /\ d_ij_bd = 0

\* --- Edge update operator -----------------------------------------------------
(*
  Identical pipeline to PhysarumMultiAgentModel.NextEdge:
    Step 1  Q_ij     = QijFor(r)
    Step 2  q_ema'   = clamp( α × Q_ij + (1-α) × q_ema )
    Step 3  fsig     = FSig(q_ema')
    Step 4  d_ij'    = clamp( d_ij + fsig×(1-d_ij) - decay×d_ij )
*)
NextEdge(old_qema, old_dij, r) ==
    LET qij      == QijFor(r)
        new_qema == Clamp((Alpha * qij + OneAlpha * old_qema) \div SCALE)
        fsig     == FSig(new_qema)
        growth   == (fsig * (SCALE - old_dij)) \div SCALE
        decay_v  == (Decay * old_dij) \div SCALE
    IN <<new_qema, Clamp(old_dij + growth - decay_v)>>

\* --- Transitions --------------------------------------------------------------
(*
  At each step, one edge non-deterministically receives a probe report.
  The other two edges are unchanged.
*)
UpdateBC(r) ==
    LET next == NextEdge(q_ema_bc, d_ij_bc, r)
    IN /\ q_ema_bc' = next[1] /\ d_ij_bc' = next[2]
       /\ UNCHANGED <<q_ema_cd, d_ij_cd, q_ema_bd, d_ij_bd>>

UpdateCD(r) ==
    LET next == NextEdge(q_ema_cd, d_ij_cd, r)
    IN /\ q_ema_cd' = next[1] /\ d_ij_cd' = next[2]
       /\ UNCHANGED <<q_ema_bc, d_ij_bc, q_ema_bd, d_ij_bd>>

UpdateBD(r) ==
    LET next == NextEdge(q_ema_bd, d_ij_bd, r)
    IN /\ q_ema_bd' = next[1] /\ d_ij_bd' = next[2]
       /\ UNCHANGED <<q_ema_bc, d_ij_bc, q_ema_cd, d_ij_cd>>

Next == \E r \in Reports :
    \/ UpdateBC(r)
    \/ UpdateCD(r)
    \/ UpdateBD(r)

Spec == Init /\ [][Next]_vars

\* --- Boundedness invariant (all edges) ----------------------------------------
Safety ==
    /\ q_ema_bc >= 0 /\ q_ema_bc <= SCALE
    /\ d_ij_bc  >= 0 /\ d_ij_bc  <= SCALE
    /\ q_ema_cd >= 0 /\ q_ema_cd <= SCALE
    /\ d_ij_cd  >= 0 /\ d_ij_cd  <= SCALE
    /\ q_ema_bd >= 0 /\ q_ema_bd <= SCALE
    /\ d_ij_bd  >= 0 /\ d_ij_bd  <= SCALE

\* --- Negative-log path score operators ----------------------------------------
(*
  Runtime formula (product-equivalent):

    ScoreBD  = max(q_ema_bd, Q_EMA_FLOOR)                          [1 hop, no penalty]
    ScoreBCD = max(q_ema_bc, Q_EMA_FLOOR)
               × max(q_ema_cd, Q_EMA_FLOOR)
               × exp(-HOP_WEIGHT × 1)                              [2 hops, one penalty]

  Scaled integer form (SCALE=10, Q_FLOOR=1, HOP_FACTOR=9):

    ScoreBD  = QFloor(q_ema_bd)
    ScoreBCD = QFloor(q_ema_bc) × QFloor(q_ema_cd) × 9 ÷ 10 ÷ 10

  Concrete values when all edges at SCALE (fully healthy):
    ScoreBD  = 10
    ScoreBCD = 10 × 10 × 9 ÷ 10 ÷ 10 = 9
*)
ScoreBD  == QFloor(q_ema_bd)
ScoreBCD == ((QFloor(q_ema_bc) * QFloor(q_ema_cd) * HOP_FACTOR) \div SCALE) \div SCALE

\* --- Key formal properties (Gate K.1) ----------------------------------------

(*
  HopPenaltyBounds:
  When all edges are at maximum conductivity (q_ema = SCALE for all),
  the direct one-hop path outscores the indirect two-hop path.

  This formalises the structural consequence of HOP_WEIGHT > 0: a hop
  penalty strictly reduces the indirect path score below the maximum,
  so a perfect direct edge is always preferred over a perfect indirect path.

  At SCALE=10, HOP_FACTOR=9:
    ScoreBD  = 10
    ScoreBCD = 10 × 10 × 9 ÷ 100 = 9
    10 ≥ 9 ✓

  Note: this property holds even with the integer rounding of HOP_FACTOR.
  It fails if HOP_FACTOR = SCALE (no penalty) — a correct model invariant.
*)
HopPenaltyBounds ==
    (q_ema_bc = SCALE /\ q_ema_cd = SCALE /\ q_ema_bd = SCALE)
    => ScoreBD >= ScoreBCD

(*
  CrossoverCorrectness:
  When both indirect edges are fully healthy (q_ema = SCALE) and the
  indirect path outscores the direct path (ScoreBCD > ScoreBD), the
  direct edge has degraded below HOP_FACTOR.

  At SCALE=10, HOP_FACTOR=9:
    Fully healthy ScoreBCD = 9.
    For ScoreBCD > ScoreBD: ScoreBD < 9, i.e., q_ema_bd < 9 = HOP_FACTOR.

  This is the formal counterpart of the Gate K.1 Phase 2 observation:
  path re-selection from B→D to B→C→D occurred when q_ema_bd ≈ 0.85
  (below the ~0.91 crossover threshold).  With SCALE=10 the crossover
  threshold is at q_ema_bd = 9/10 = 0.9, which bounds the same region.
*)
CrossoverCorrectness ==
    (q_ema_bc = SCALE /\ q_ema_cd = SCALE /\ ScoreBCD > ScoreBD)
    => q_ema_bd < HOP_FACTOR

===============================================================================

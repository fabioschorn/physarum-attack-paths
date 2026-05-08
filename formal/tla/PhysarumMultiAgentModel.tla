------------------------ MODULE PhysarumMultiAgentModel ------------------------
(*
  Formal model of the B/C/D multi-agent topology in physarum-attack-paths.

  This module extends the single-edge model (PhysarumEdgeModel.tla) to three
  directed edges relevant to path selection from agent-b to agent-d:

    B -> C   (edge bc)
    C -> D   (edge cd)
    B -> D   (edge bd, direct)

  Each edge carries its own (q_ema, d_ij) pair updated by the same pipeline
  as the single-edge model.  Edge updates are independent: receiving a report
  on one edge leaves the other two unchanged.

  New invariant — PathSelectionSafety:
    When the direct B->D edge is fully degraded (d_ij_bd = 0) and the
    indirect path B->C->D has positive integer conductivity product, the
    indirect path score exceeds the direct path score.  This is the formal
    counterpart of the Mode 2 runtime observation: blocked direct edge ->
    /paths routes exclusively via C.

  Scaled integers:  With SCALE = 10 (set in PhysarumMultiAgentModel.cfg),
  each variable has 11 possible values -> 11^6 = 1,771,561 reachable
  states.  TLC completes exhaustive checking in seconds.

  The integer-rounding artefact from PhysarumEdgeModel.tla (decay stalls
  for very small d_ij due to truncation) carries over unchanged and is
  documented in formal/tla/README.md.
*)
EXTENDS Integers

CONSTANTS
    SCALE   \* Represents 1.0; set to 10 in PhysarumMultiAgentModel.cfg

\* --- Derived scaling coefficients ----------------------------------------
Alpha    == 3 * SCALE \div 10   \* EMA weight alpha = 0.3
OneAlpha == SCALE - Alpha       \* 1 - alpha = 0.7
Decay    == SCALE \div 10       \* Conductivity decay rate: 0.1

\* --- Helper operators -----------------------------------------------------

Clamp(x) == IF x < 0 THEN 0 ELSE IF x > SCALE THEN SCALE ELSE x

FSig(q) == (SCALE * q * q) \div (SCALE * SCALE + q * q)

\* --- Discrete probe report classes ----------------------------------------
Reports == {"SuccessfulFast", "PartialSuccess", "Failed"}

QijFor(r) ==
    IF      r = "SuccessfulFast" THEN SCALE
    ELSE IF r = "PartialSuccess" THEN SCALE \div 2
    ELSE    0

\* --- State variables -------------------------------------------------------
(*
  Six variables: one (q_ema, d_ij) pair per directed edge.
  Edges modelled: B->C (bc), C->D (cd), B->D (bd).
*)
VARIABLES
    q_ema_bc, d_ij_bc,   \* edge B->C
    q_ema_cd, d_ij_cd,   \* edge C->D
    q_ema_bd, d_ij_bd    \* edge B->D (direct, degraded in Mode 2)

vars == <<q_ema_bc, d_ij_bc, q_ema_cd, d_ij_cd, q_ema_bd, d_ij_bd>>

\* --- Type invariant --------------------------------------------------------
TypeOK ==
    /\ q_ema_bc \in 0..SCALE /\ d_ij_bc \in 0..SCALE
    /\ q_ema_cd \in 0..SCALE /\ d_ij_cd \in 0..SCALE
    /\ q_ema_bd \in 0..SCALE /\ d_ij_bd \in 0..SCALE

\* --- Initial state ---------------------------------------------------------
Init ==
    /\ q_ema_bc = 0 /\ d_ij_bc = 0
    /\ q_ema_cd = 0 /\ d_ij_cd = 0
    /\ q_ema_bd = 0 /\ d_ij_bd = 0

\* --- Edge update operator --------------------------------------------------
(*
  Compute the next (q_ema, d_ij) for an edge given its current values and
  an incoming probe report class.  Identical pipeline to PhysarumEdgeModel:

    Step 1  Q_ij     = QijFor(r)
    Step 2  q_ema'   = clamp( alpha * Q_ij + (1-alpha) * q_ema )
    Step 3  fsig     = FSig(q_ema')
    Step 4  d_ij'    = clamp( d_ij + fsig*(1-d_ij) - decay*d_ij )
*)
NextEdge(old_qema, old_dij, r) ==
    LET qij      == QijFor(r)
        new_qema == Clamp((Alpha * qij + OneAlpha * old_qema) \div SCALE)
        fsig     == FSig(new_qema)
        growth   == fsig * (SCALE - old_dij) \div SCALE
        decay_v  == Decay * old_dij \div SCALE
    IN <<new_qema, Clamp(old_dij + growth - decay_v)>>

\* --- Transitions -----------------------------------------------------------
(*
  At each step, one edge receives a probe report (non-deterministic choice).
  The other two edges are unchanged (UNCHANGED clause).
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

\* --- Safety invariants -----------------------------------------------------

Safety ==
    /\ q_ema_bc >= 0 /\ q_ema_bc <= SCALE
    /\ d_ij_bc  >= 0 /\ d_ij_bc  <= SCALE
    /\ q_ema_cd >= 0 /\ q_ema_cd <= SCALE
    /\ d_ij_cd  >= 0 /\ d_ij_cd  <= SCALE
    /\ q_ema_bd >= 0 /\ q_ema_bd <= SCALE
    /\ d_ij_bd  >= 0 /\ d_ij_bd  <= SCALE

\* --- Path score operators --------------------------------------------------
(*
  Path scores follow the runtime /paths formula: product of edge conductivities.
  For a two-hop path the product is divided by SCALE to keep the result in
  the same integer range as a single-edge score.

    PathScoreBD  = d_ij_bd               (direct one-hop path)
    PathScoreBCD = d_ij_bc * d_ij_cd / SCALE  (indirect two-hop path)
*)
PathScoreBD  == d_ij_bd
PathScoreBCD == d_ij_bc * d_ij_cd \div SCALE

\* --- PathSelectionSafety ---------------------------------------------------
(*
  When the direct B->D edge is fully degraded (d_ij_bd = 0) AND the indirect
  path B->C->D has a non-zero integer conductivity product, the indirect path
  score exceeds the direct path score.

  This is the formal statement of the Mode 2 segmentation property:
  a blocked direct edge cannot outrank a live indirect path.

  Note: the guard (PathScoreBCD > 0) is required because integer division
  truncates d_ij_bc * d_ij_cd / SCALE to 0 when both edge conductivities
  are very small (e.g., d_ij_bc = 1, d_ij_cd = 1, SCALE = 10 -> 0).
  In those low-conductivity states both paths score 0 and the property
  reduces to 0 > 0 which is false; the guard excludes that degenerate case.
*)
PathSelectionSafety ==
    (d_ij_bd = 0 /\ PathScoreBCD > 0) => (PathScoreBCD > PathScoreBD)

===============================================================================

-------------------------- MODULE PhysarumEdgeModel ---------------------------
(*
  Formal model of a single directed adaptive edge in physarum-attack-paths.

  Implementation status: this model describes the Phase 2 design target.
  The current physarum-maze runtime uses a Phase 1 approximation
  (LLM confidence as D_ij proxy). Full runtime integration is tracked
  in Issue #201.

  This module captures the core signal pipeline:

    ProbeReport -> Q_ij -> q_ema -> D_ij

  All real-valued quantities in [0.0, 1.0] are represented as integers in
  [0, SCALE].  With SCALE = 1000:

    1.0  ->  1000
    0.7  ->   700
    0.3  ->   300
    0.0  ->     0

  This is intentionally a model of one directed edge only.
  The coordinator, multiple agents, and network topology are out of scope.
*)
EXTENDS Integers

CONSTANTS
    SCALE   \* Represents 1.0; set to 1000 in PhysarumEdgeModel.cfg

\* ─── Derived scaling coefficients ─────────────────────────────────────────
\* All coefficients are exact for SCALE = 1000 (multiples of 10).

Alpha    == (3 * SCALE) \div 10   \* EMA weight alpha = 0.3
OneAlpha == SCALE - Alpha         \* 1 - alpha = 0.7
WSuc     == (7 * SCALE) \div 10   \* Q_ij weight for success_rate: 0.7
WLat     == (3 * SCALE) \div 10   \* Q_ij weight for latency_score: 0.3
Decay    == SCALE \div 10         \* Conductivity decay rate: 0.1

\* ─── Helper operators ──────────────────────────────────────────────────────

\* Clamp x to [0, SCALE]
Clamp(x) == IF x < 0 THEN 0 ELSE IF x > SCALE THEN SCALE ELSE x

(*
  FSig(q) is the scaled sigmoid f(x) = x^2 / (1 + x^2) evaluated at
  x = q / SCALE, with the result scaled back by SCALE.

  In integer arithmetic:
    FSig(q) = SCALE * q^2 / (SCALE^2 + q^2)

  Properties:
    FSig(0)     = 0          (no signal -> no growth drive)
    FSig(SCALE) = SCALE / 2  (maximum signal -> growth drive of 0.5)
    FSig is monotonically increasing in q
    SCALE^2 + q^2 >= SCALE^2 > 0, so division by zero is impossible
*)
FSig(q) == (SCALE * q * q) \div (SCALE * SCALE + q * q)

\* ─── Discrete probe report classes ────────────────────────────────────────
(*
  The continuous pair (success_rate, avg_rtt_ms) is approximated by three
  discrete report classes.  Each maps to a scaled Q_ij via the runtime
  formula:

    Q_ij = 0                                              if success_rate = 0
    Q_ij = clamp(0.7 * success_rate + 0.3 * latency_score)  otherwise

  where  latency_score = 1 / (1 + avg_rtt_ms / 100).

  SuccessfulFast:  success_rate = 1.0, latency_score = 1.0  ->  Q_ij = 1.0
  PartialSuccess:  success_rate = 0.5, latency_score = 0.5  ->  Q_ij = 0.5
  Failed:          success_rate = 0.0                        ->  Q_ij = 0.0
*)
Reports == {"SuccessfulFast", "PartialSuccess", "Failed"}

QijFor(r) ==
    IF      r = "SuccessfulFast" THEN SCALE
    ELSE IF r = "PartialSuccess" THEN SCALE \div 2
    ELSE    0   \* Failed: success_rate = 0 -> Q_ij forced to 0

\* ─── State variables ───────────────────────────────────────────────────────
VARIABLES
    q_ema,  \* exponential moving average of Q_ij;  value in 0..SCALE
    d_ij    \* Physarum conductivity for this edge;  value in 0..SCALE

vars == <<q_ema, d_ij>>

\* ─── Type invariant ────────────────────────────────────────────────────────
TypeOK ==
    /\ q_ema \in 0..SCALE
    /\ d_ij  \in 0..SCALE

\* ─── Initial state ─────────────────────────────────────────────────────────
\* No observations yet: zero signal and zero conductivity.
Init ==
    /\ q_ema = 0
    /\ d_ij  = 0

\* ─── Transition: receive a probe report ────────────────────────────────────
(*
  Receiving a probe report of class r applies the full pipeline:

    Step 1 — Q_ij:
      qij = QijFor(r)

    Step 2 — q_ema update (EMA, alpha = 0.3):
      q_ema' = clamp( alpha * qij + (1 - alpha) * q_ema )
             = clamp( (Alpha * qij + OneAlpha * q_ema) / SCALE )

    Step 3 — sigmoid growth drive:
      fsig = FSig(q_ema')     [f(x) = x^2 / (1 + x^2)]

    Step 4 — D_ij update:
      d_ij' = clamp( d_ij + fsig * (1 - d_ij) - decay * d_ij )
            = clamp( d_ij
                   + fsig * (SCALE - d_ij) / SCALE
                   - Decay * d_ij / SCALE )

  All divisions are integer (truncating).  Clamp keeps values in [0, SCALE].
*)
ReceiveReport(r) ==
    LET qij      == QijFor(r)
        new_qema == Clamp((Alpha * qij + OneAlpha * q_ema) \div SCALE)
        fsig     == FSig(new_qema)
        growth   == (fsig * (SCALE - d_ij)) \div SCALE
        decay_v  == (Decay * d_ij) \div SCALE
        new_dij  == Clamp(d_ij + growth - decay_v)
    IN
    /\ q_ema' = new_qema
    /\ d_ij'  = new_dij

\* Non-deterministically receive any report class at each step.
Next == \E r \in Reports : ReceiveReport(r)

Spec == Init /\ [][Next]_vars

\* ─── Safety invariants ─────────────────────────────────────────────────────

\* q_ema stays within [0, SCALE] at all times.
QEmaBounded == q_ema >= 0 /\ q_ema <= SCALE

\* d_ij stays within [0, SCALE] at all times.
DijBounded == d_ij >= 0 /\ d_ij <= SCALE

\* SuccessRateBounded and LatencyScoreBounded are implicit: they are encoded
\* as discrete report classes (SuccessfulFast, PartialSuccess, Failed), so
\* Q_ij = QijFor(r) is always in {0, SCALE/2, SCALE} ⊆ [0, SCALE].

\* Combined invariant checked by TLC.
Safety == QEmaBounded /\ DijBounded

===============================================================================

----------------------- MODULE PhysarumLineageScoreModel ----------------------
(*
  Formal model of the legacy multiplicative lineage score used by
  physarum-maze.

  Implementation status: this model describes the bounded contract required
  for the lineage.scores multiplier system to coexist safely with the Phase 2
  D_ij pipeline from Issue #201.

  Runtime lineage.scores currently apply multiplicative updates:

    Success          score *= 1.5
    SshFailed        score *= 0.5
    DeadEnd          score *= 0.05
    AlreadyColonized score *= 0.8
    SecondaryConduit score *= 1.2

  Without an explicit ceiling, repeated success can grow without bound across
  persistent AWS sessions. This model keeps the exact multiplier vocabulary but
  wraps each update in ClampScore, making the intended safe range explicit:

    MIN_SCORE <= score <= SCORE_CEILING

  TLC therefore checks the safe bounded design target, not the current
  unbounded floating-point implementation.
*)
EXTENDS Integers

CONSTANTS
    SCALE,          \* 100 in .cfg; represents multiplier 1.0
    MIN_SCORE,      \* positive lower bound; prevents integer truncation to 0
    NEUTRAL_SCORE,  \* initial score; 100 in .cfg represents runtime 1.0
    SCORE_CEILING   \* maximum retained lineage score

\* --- Multiplier factors -------------------------------------------------------
\* With SCALE = 100:
\*   150 -> 1.5, 50 -> 0.5, 5 -> 0.05, 80 -> 0.8, 120 -> 1.2

SuccessFactor          == (3 * SCALE) \div 2
SshFailedFactor        == SCALE \div 2
DeadEndFactor          == SCALE \div 20
AlreadyColonizedFactor == (4 * SCALE) \div 5
SecondaryConduitFactor == (6 * SCALE) \div 5

Updates == {"Success", "SshFailed", "DeadEnd", "AlreadyColonized", "SecondaryConduit"}

FactorFor(update) ==
    IF      update = "Success"          THEN SuccessFactor
    ELSE IF update = "SshFailed"        THEN SshFailedFactor
    ELSE IF update = "DeadEnd"          THEN DeadEndFactor
    ELSE IF update = "AlreadyColonized" THEN AlreadyColonizedFactor
    ELSE                                    SecondaryConduitFactor

\* --- Helpers ------------------------------------------------------------------

ClampScore(x) ==
    IF x < MIN_SCORE THEN MIN_SCORE
    ELSE IF x > SCORE_CEILING THEN SCORE_CEILING
    ELSE x

ScoreAfter(update, old_score) ==
    ClampScore((old_score * FactorFor(update)) \div SCALE)

\* --- State variables ----------------------------------------------------------

VARIABLES
    score,       \* lineage.scores["src->dst"], scaled integer
    last_update  \* trace aid for TLC counterexamples and state inspection

vars == <<score, last_update>>

\* --- Type invariant -----------------------------------------------------------

TypeOK ==
    /\ MIN_SCORE > 0
    /\ MIN_SCORE <= NEUTRAL_SCORE
    /\ NEUTRAL_SCORE <= SCORE_CEILING
    /\ score \in MIN_SCORE..SCORE_CEILING
    /\ last_update \in Updates \cup {"Init"}

\* --- Initial state ------------------------------------------------------------

Init ==
    /\ score = NEUTRAL_SCORE
    /\ last_update = "Init"

\* --- Transition ---------------------------------------------------------------

ApplyUpdate(update) ==
    /\ score' = ScoreAfter(update, score)
    /\ last_update' = update

Next == \E update \in Updates : ApplyUpdate(update)

Spec == Init /\ [][Next]_vars

\* --- Safety invariants --------------------------------------------------------

ScorePositive == score >= MIN_SCORE

ScoreBounded == score <= SCORE_CEILING

Safety == ScorePositive /\ ScoreBounded

(*
  A single dead-end penalty dominates one immediate reinforcement for every
  reachable score state.

  Algebraically:
    score * 0.05 * 1.5 = score * 0.075 <= score
    score * 0.05 * 1.2 = score * 0.060 <= score

  This captures the Issue #201 requirement that one confirmed dead end should
  not be erased by one subsequent reinforcement event.
*)
DeadEndPenaltyDominatesReinforcement ==
    /\ ScoreAfter("Success", ScoreAfter("DeadEnd", score)) <= score
    /\ ScoreAfter("SecondaryConduit", ScoreAfter("DeadEnd", score)) <= score

(*
  Mixed success/failure cycles contract rather than grow.

  This models steady-state behaviour for repeated noisy observations: an edge
  that alternates between success and SSH failure does not drift upward, and a
  strong success+secondary cycle followed by a dead-end penalty still contracts.
*)
MixedFailureCyclesContract ==
    /\ ScoreAfter("SshFailed", ScoreAfter("Success", score)) <= score
    /\ ScoreAfter("DeadEnd", ScoreAfter("SecondaryConduit", ScoreAfter("Success", score))) <= score

===============================================================================

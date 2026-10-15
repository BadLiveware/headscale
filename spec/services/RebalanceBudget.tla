---------------------------- MODULE RebalanceBudget ----------------------------
(* The per-host rebalance budget of hscontrol/state/service_assignment.go,
   rebalanceBudget, in exact arithmetic. The rate per round is P/Q moves
   (moves_per_host_per_minute x interval in minutes). Credit is kept in
   units of 1/Q. Each round: credit := min(credit, carryCap) + P, the host
   may give up floor(credit / Q) moves, takes any number up to that
   (demand is free), and credit drops by Q per move taken. carryCap is
   "below one move": Q - 1 units. *)
EXTENDS Naturals, Sequences

CONSTANTS P, Q, Window, Rounds

VARIABLES credit, round, history  \* history: moves taken per round, newest last

CarryCap == Q - 1

Min(a, b) == IF a < b THEN a ELSE b

Init == credit = 0 /\ round = 0 /\ history = <<>>

Round ==
    /\ round < Rounds
    /\ LET c == Min(credit, CarryCap) + P
           allowed == c \div Q
       IN \E taken \in 0..allowed:
            /\ credit' = c - taken * Q
            /\ history' = Append(history, taken)
    /\ round' = round + 1

Next == Round \/ (round = Rounds /\ UNCHANGED <<credit, round, history>>)

Spec == Init /\ [][Next]_<<credit, round, history>>

Sum(s) == LET F[i \in 0..Len(s)] == IF i = 0 THEN 0 ELSE F[i - 1] + s[i] IN F[Len(s)]

\* The moves in the last k rounds, for k up to Window.
Last(k) == SubSeq(history, Len(history) - k + 1, Len(history))

CeilDiv(a, b) == (a + b - 1) \div b

\* Never more than ceil(k * P / Q) moves in any k consecutive rounds.
WindowBound ==
    \A k \in 1..Window :
        Len(history) >= k => Sum(Last(k)) <= CeilDiv(k * P, Q)

\* Since the start, never more than the average rate allows.
TotalBound == Sum(history) * Q <= Len(history) * P

\* Credit stays bounded: below one move of carry plus one round.
CreditBound == credit < Q + P

\* That the configured rate is also reached when every allowed move is
\* taken is checked by the Go test TestRebalanceBudgetKeepsRate.
=============================================================================

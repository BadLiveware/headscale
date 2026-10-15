# TLA+ models of Tailscale Services host assignment

These models check the algorithm in `hscontrol/state/services.go` and `hscontrol/state/service_assignment.go` with the TLC model checker.
They are not run in CI.

## Run

```console
cd spec/services
tlc -deadlock -workers 4 -config ServiceAssignment_2hosts_3clients.cfg MCServiceAssignment.tla
tlc -deadlock -workers 4 -config ServiceAssignment_3hosts_2clients.cfg MCServiceAssignment.tla
tlc -workers 4 -config RebalanceBudget_5_per_minute.cfg RebalanceBudget.tla
tlc -workers 4 -config RebalanceBudget_15_per_minute.cfg RebalanceBudget.tla
```

`-deadlock` is needed because the models stop after a bounded number of events.
Each run takes from a few seconds to about two minutes.

## `ServiceAssignment.tla`

One service, a few hosts and clients.
The model holds the real state (active hosts, online clients, access, peer relationships, the NodeStore peer-map generation) and Headscale's service index (the host and peer snapshot of the last refresh, the generation it read, the sticky assignments).
Events: hosts join and leave, clients connect and disconnect, a policy reload changes access, a user change or another write changes access or peers without a refresh (only the generation moves), Headscale restarts (startup grace), the grace ends, a dispatch reconciles a stale index, and a rebalance moves one client towards its rendezvous host.

Invariants:

- `RoutesCorrect`: once no dispatch is pending, every online client with access and at least one visible active host carries the VIPs on one such host, and every other online client on none.
- `NoRouteWithoutAccess`: a client without access never carries the VIPs.
- `JoinMovesNobody`: after the startup grace, a joining host moves no client whose host is still right for it.
- `LeaveMovesOnlyItsClients`: a leaving host moves only its own clients.
- `GraceFollowsRendezvous`: during the startup grace every served client is on its rendezvous host, so hosts that come back one by one share the clients.

Properties, with weak fairness on dispatch, the end of the grace, and the rebalance:

- `EventuallyConverged`: once events stop, every host carries its rendezvous share of the clients.
- `RoutesSettle`: once events stop, routes stop changing.

Checked bounds: 2 hosts and 3 clients with 5 events (114,294 distinct states); 2 hosts and 3 clients with 7 events (1,387,551 states); 3 hosts and 2 clients with 7 events (945,458 states).
No violation.

What the model shows beyond the tests:

- Without the generation check in the dispatch (`ReconcileOn = FALSE`), `RoutesCorrect` fails: a peer change that no refresh follows leaves a client with the VIPs on a host it cannot see.
- Without stickiness, `JoinMovesNobody` fails; ignoring the grace, `GraceFollowsRendezvous` fails.
- Convergence is by count, not per client: two clients can stay swapped (each on the other's rendezvous host) when every host already has its share; the rebalance stops there, as the code does.

## `RebalanceBudget.tla`

The per-host budget of `rebalanceBudget` in exact arithmetic: P/Q moves per round, the fraction of a move carried over, unused whole moves dropped.
Invariants: at most ceil(k × P / Q) moves in any k consecutive rounds (k up to 8), never more than the average rate since the start, and bounded credit.
Checked for 5 and 15 moves per minute at a 10-second interval (P/Q = 5/6 and 15/6), and also for 12 per minute at 10 s, 1 per minute at 1 s and 7/3, over 12 to 130 rounds.
With a carry cap of two whole moves instead of below one, the window bound fails.

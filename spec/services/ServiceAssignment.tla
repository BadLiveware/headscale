--------------------------- MODULE ServiceAssignment ---------------------------
(* One Tailscale Service with VIPs, as hscontrol/state/services.go and
   service_assignment.go assign its clients to hosts.

   Real state (what the NodeStore and the policy say):
     active  - hosts that are online, approved and advertise the service
     online  - clients that are connected
     access  - clients the policy lets reach the service
     vis     - <<client, host>> pairs that are peers
     gen     - the NodeStore peer-map generation; it moves on every peer
               rebuild

   Headscale's index (serviceHostIndex), read by the map builder:
     idx.hosts, idx.peers - snapshot of active and vis at the last refresh
     idx.gen              - the generation that snapshot was read at
     idx.assigned         - sticky hosts that differ from rendezvous

   A client's route (the host that carries the VIPs in its netmap) is its
   effective host from the index, if the live policy gives it access.

   Every event that the code follows with a refresh does the refresh in the
   same step. Peer changes that the code does not follow with a refresh (a
   user change, a raced write) only move gen. Every event leaves a dispatch
   pending; a dispatch runs DrainSelfRefreshes, which reconciles a stale
   index when ReconcileOn. *)
EXTENDS Naturals, FiniteSets, Sequences

CONSTANTS Clients, Hosts, Pref, NoHost, MaxEvents, ReconcileOn

ASSUME \A c \in Clients : Pref[c] \in Seq(Hosts)

VARIABLES active, online, access, vis, gen,
          idx, grace, pending, events,
          lastEvent, leftHost, r, r0

vars == <<active, online, access, vis, gen, idx, grace, pending, events,
          lastEvent, leftHost, r, r0>>

Toggle(S, x) == IF x \in S THEN S \ {x} ELSE S \cup {x}

\* Rendezvous: the first host in the client's preference order among S.
Rdv(c, S) ==
    LET is == {i \in 1..Len(Pref[c]) : Pref[c][i] \in S}
    IN IF is = {} THEN NoHost ELSE Pref[c][CHOOSE i \in is : \A j \in is : i <= j]

VisibleIn(c, hosts, peers) == {h \in hosts : <<c, h>> \in peers}

\* serviceHostIndex.hostFor
Eff(i, c) ==
    LET a == i.assigned[c]
    IN IF a # NoHost /\ a \in i.hosts /\ <<c, a>> \in i.peers
       THEN a
       ELSE Rdv(c, VisibleIn(c, i.hosts, i.peers))

\* serviceRoutesForPeer: the effective host, if the live policy allows.
\* Only online clients hold a netmap; a client that connects gets a full map.
RouteOf(i, onl, acc, c) == IF c \in onl /\ c \in acc THEN Eff(i, c) ELSE NoHost

Routes(i, onl, acc) == [c \in Clients |-> RouteOf(i, onl, acc, c)]

EmptyIdx == [hosts |-> {}, peers |-> {}, gen |-> 0,
             assigned |-> [c \in Clients |-> NoHost]]

\* refreshServiceHostsLocked over the real state given as arguments.
Refreshed(i, act, onl, acc, peers, g, gr) ==
    IF act = i.hosts /\ peers = i.peers
    THEN [i EXCEPT !.gen = g]                          \* fast path
    ELSE [hosts |-> act, peers |-> peers, gen |-> g,
          assigned |->
            [c \in Clients |->
               LET target == Rdv(c, VisibleIn(c, act, peers))
                   cur    == Eff(i, c)
                   keep   == ~gr /\ cur # NoHost /\ cur \in act /\ <<c, cur>> \in peers
                   new    == IF keep THEN cur ELSE target
                   old    == i.assigned[c]
               IN CASE c \in onl /\ c \in acc ->
                         IF new = target THEN NoHost ELSE new
                    [] c \notin onl ->                  \* keepOfflineAssignments
                         IF old # NoHost /\ old \in act /\ <<c, old>> \in peers
                         THEN old ELSE NoHost
                    [] OTHER -> NoHost]]

Init ==
    /\ active = {} /\ online = {} /\ access = Clients
    /\ vis = Clients \X Hosts /\ gen = 1
    /\ idx = EmptyIdx /\ grace = FALSE
    /\ pending = FALSE /\ events = 0
    /\ lastEvent = "init" /\ leftHost = NoHost
    /\ r = [c \in Clients |-> NoHost] /\ r0 = [c \in Clients |-> NoHost]

\* An event with a synchronous refresh (the code calls refreshHostnameClaims).
EventWithRefresh(label, act, onl, acc, peers, g, gr, left) ==
    /\ events < MaxEvents
    /\ LET i == Refreshed(idx, act, onl, acc, peers, g, gr)
       IN /\ idx' = i
          /\ r' = Routes(i, onl, acc)
    /\ active' = act /\ online' = onl /\ access' = acc /\ vis' = peers
    /\ gen' = g /\ grace' = gr
    /\ pending' = TRUE /\ events' = events + 1
    /\ lastEvent' = label /\ leftHost' = left /\ r0' = r

HostJoin(h) ==
    /\ h \notin active
    /\ EventWithRefresh("join", active \cup {h}, online, access, vis, gen, grace, NoHost)

HostLeave(h) ==
    /\ h \in active
    /\ EventWithRefresh("leave", active \ {h}, online, access, vis, gen, grace, h)

Connect(c) ==
    /\ c \notin online
    /\ EventWithRefresh("connect", active, online \cup {c}, access, vis, gen, grace, NoHost)

Disconnect(c) ==
    /\ c \in online
    /\ EventWithRefresh("disconnect", active, online \ {c}, access, vis, gen, grace, NoHost)

\* A policy reload: rebuilds peers and refreshes.
PolicyAccess(c) ==
    EventWithRefresh("policy", active, online, Toggle(access, c), vis, gen + 1, grace, NoHost)

\* A peer change that is not followed by a refresh: a user change, a route
\* approval, an IP backfill, a raced node write. Only gen moves.
SilentPeerChange(c, h) ==
    /\ events < MaxEvents
    /\ vis' = Toggle(vis, <<c, h>>)
    /\ gen' = gen + 1
    /\ r' = Routes(idx, online, access)
    /\ pending' = TRUE /\ events' = events + 1
    /\ lastEvent' = "silent" /\ leftHost' = NoHost /\ r0' = r
    /\ UNCHANGED <<active, online, access, idx, grace>>

\* A user change that changes access without a refresh (R1).
SilentAccessChange(c) ==
    /\ events < MaxEvents
    /\ access' = Toggle(access, c)
    /\ gen' = gen + 1
    /\ r' = Routes(idx, online, access')
    /\ pending' = TRUE /\ events' = events + 1
    /\ lastEvent' = "silent" /\ leftHost' = NoHost /\ r0' = r
    /\ UNCHANGED <<active, online, vis, idx, grace>>

\* Headscale restarts: everyone is offline, assignments are gone, the
\* startup grace starts.
Restart ==
    /\ events < MaxEvents
    /\ active' = {} /\ online' = {} /\ idx' = EmptyIdx /\ grace' = TRUE
    /\ gen' = gen + 1
    /\ r' = [c \in Clients |-> NoHost]
    /\ pending' = FALSE /\ events' = events + 1
    /\ lastEvent' = "restart" /\ leftHost' = NoHost /\ r0' = r
    /\ UNCHANGED <<access, vis>>

GraceEnd ==
    /\ grace
    /\ grace' = FALSE
    /\ lastEvent' = "graceEnd" /\ leftHost' = NoHost /\ r0' = r
    /\ UNCHANGED <<active, online, access, vis, gen, idx, pending, events, r>>

\* DrainSelfRefreshes on a dispatch: reconcile a stale index.
Dispatch ==
    /\ pending
    /\ pending' = FALSE
    /\ IF ReconcileOn /\ idx.gen # gen
       THEN LET i == Refreshed(idx, active, online, access, vis, gen, grace)
            IN idx' = i /\ r' = Routes(i, online, access)
       ELSE UNCHANGED <<idx, r>>
    /\ lastEvent' = "dispatch" /\ leftHost' = NoHost /\ r0' = r
    /\ UNCHANGED <<active, online, access, vis, gen, grace, events>>

Target(c) == Rdv(c, VisibleIn(c, idx.hosts, idx.peers))

Served == {c \in online : c \in access /\ Eff(idx, c) # NoHost}

Load(h, f) == Cardinality({c \in Served : f[c] = h})

EffMap == [c \in Clients |-> Eff(idx, c)]
TargetMap == [c \in Clients |-> Target(c)]

\* One rebalance move (tolerance 0, budget abstracted; see RebalanceBudget):
\* a client on a host above its share moves to its rendezvous target.
Rebalance ==
    /\ ~grace
    /\ \E c \in Served :
        LET from == Eff(idx, c)
        IN /\ from # Target(c)
           /\ Load(from, EffMap) > Load(from, TargetMap)
           /\ idx' = [idx EXCEPT !.assigned[c] = NoHost]
           /\ r' = Routes(idx', online, access)
    /\ pending' = TRUE
    /\ lastEvent' = "rebalance" /\ leftHost' = NoHost /\ r0' = r
    /\ UNCHANGED <<active, online, access, vis, gen, grace, events>>

Next ==
    \/ \E h \in Hosts : HostJoin(h) \/ HostLeave(h)
    \/ \E c \in Clients : Connect(c) \/ Disconnect(c) \/ PolicyAccess(c) \/ SilentAccessChange(c)
    \/ \E c \in Clients, h \in Hosts : SilentPeerChange(c, h)
    \/ Restart \/ GraceEnd \/ Dispatch \/ Rebalance

Fairness == WF_vars(Dispatch) /\ WF_vars(GraceEnd) /\ WF_vars(Rebalance)

Spec == Init /\ [][Next]_vars /\ Fairness

-----------------------------------------------------------------------------
(* Invariants *)

Quiescent == ~pending

HasVisibleHost(c) == \E h \in active : <<c, h>> \in vis

\* Once quiescent, every online client with access and a visible active
\* host has its route on exactly one such host; any other client has none.
\* (The route is one host by construction: it is a single value.)
RoutesCorrect ==
    Quiescent =>
        \A c \in online :
            LET h == r[c] IN
            IF c \in access /\ HasVisibleHost(c)
            THEN h # NoHost /\ h \in active /\ <<c, h>> \in vis
            ELSE h = NoHost

\* Never route a client without access, even while stale.
NoRouteWithoutAccess == \A c \in Clients : c \notin access => r[c] = NoHost

\* A route that is still right: its host is active, visible, and the client
\* has access. A refresh may fix a route that is no longer right (a peer
\* change it had not seen yet); that is not a move caused by the event.
ValidBefore(c) == r0[c] # NoHost /\ r0[c] \in active /\ <<c, r0[c]>> \in vis /\ c \in access

\* A join moves no client from a host that is still right for it (after
\* the startup grace).
JoinMovesNobody ==
    (lastEvent = "join" /\ ~grace) =>
        \A c \in Clients : ValidBefore(c) => r[c] = r0[c]

\* A leaving host moves only its own clients (and fixes stale routes).
LeaveMovesOnlyItsClients ==
    lastEvent = "leave" =>
        \A c \in Clients : (r0[c] # r[c] /\ ValidBefore(c)) => r0[c] = leftHost

\* During the startup grace every served client is on its rendezvous host,
\* so hosts that come back one by one after a restart share the clients.
GraceFollowsRendezvous ==
    (grace /\ Quiescent) =>
        \A c \in online :
            (c \in access /\ HasVisibleHost(c)) =>
                r[c] = Rdv(c, VisibleIn(c, active, vis))

TypeOK ==
    /\ active \subseteq Hosts /\ online \subseteq Clients /\ access \subseteq Clients
    /\ vis \subseteq Clients \X Hosts
    /\ \A c \in Clients : r[c] \in Hosts \cup {NoHost}

-----------------------------------------------------------------------------
(* Liveness: once the events stop, the spread reaches rendezvous's ideal
   (tolerance 0 here: every host carries as many served clients as
   rendezvous would give it) and the routes stop changing (no
   oscillation). Single clients may stay on another host than their
   rendezvous choice when the counts already match: moving them would
   reset connections for no gain in spread, and the code's rebalance
   stops there too. *)

RealTarget(c) == Rdv(c, VisibleIn(c, active, vis))

ServedNow == {c \in online : c \in access /\ HasVisibleHost(c)}

Spread(h) == Cardinality({c \in ServedNow : r[c] = h})
IdealSpread(h) == Cardinality({c \in ServedNow : RealTarget(c) = h})

Converged == \A h \in Hosts : Spread(h) = IdealSpread(h)

EventuallyConverged == <>[]Converged

RoutesSettle == <>[][UNCHANGED r]_vars
=============================================================================

# Tailscale Services

A [Tailscale Service](https://tailscale.com/docs/features/tailscale-services) gives a service that runs on several nodes
one stable name and one virtual IP address (VIP) per address family.
Clients reach the service at its VIPs or at its name, and Headscale sends each client's traffic to one of the nodes
that host the service.
When a host stops hosting the service, goes offline or loses its approval, Headscale moves the clients of that host to
another host.

Headscale implements the part of Tailscale Services that stock Tailscale clients use: VIPs, host approval, access by
grant, the service name in MagicDNS, and the `service-host` capability that tells a host its VIPs.
It does not implement the admin console or API objects of Tailscale Services, service tags, or required ports.

## Define a service and approve its hosts

The `services` part of `autoApprovers` in the [policy](policy.md) defines each service and the tags whose nodes may host
it.
Only tagged nodes host services.

```json title="policy.json"
{
  "tagOwners": {
    "tag:grafana": ["alice@"]
  },
  "autoApprovers": {
    "services": {
      "svc:grafana": ["tag:grafana"]
    }
  },
  "grants": [
    // Members reach the service on TCP port 443.
    { "src": ["autogroup:member"], "dst": ["svc:grafana"], "ip": ["tcp:443"] }
  ]
}
```

- Headscale allocates the VIPs when the policy first defines the service, from the address ranges in `prefixes`, and
  stores them in the database.
  A service keeps its VIPs across restarts, and when the policy removes and adds it again.
  Headscale never gives a VIP to a node or to another service.
- Headscale never deletes a service's VIPs, and there is no command to delete them yet.
- A service gets an IPv6 VIP only if `prefixes.v6` is set when Headscale first allocates its VIPs.
  Adding `prefixes.v6` later gives no IPv6 VIP to existing services.
- If the address pool has no room, the service gets no VIPs: nobody can reach it, Headscale logs an error and counts it
  in the `headscale_service_vip_allocation_failures_total` metric, and tries again on the next policy change or
  restart.
- `svc:<label>` is a destination for grants and ACLs (`"svc:grafana:443"` in an ACL).
  It cannot be a source, an SSH destination or a `nodeAttrs` target.
- A wildcard destination (`"*"`, as in an allow-all policy) contains every VIP: it lets its sources reach every service.
- A grant to the tag of the hosts lets clients reach the hosts' own addresses, not the service.
- Give each service its own tag, and register its hosts with a pre-auth key for that tag, so that a node of one service
  cannot host another.

## Host a service

A host serves the service and advertises it:

```console
tailscale serve --service=svc:grafana --https=443 127.0.0.1:8443
tailscale serve --service=svc:grafana --tcp=443 tcp://127.0.0.1:8443
```

A [tsnet](https://tailscale.com/docs/features/tsnet) program uses `Server.ListenService`.
The host accepts traffic to the VIPs only on the ports its serve configuration lists.

To drain a host, stop advertising the service; the host keeps serving the connections it has, and Headscale moves its
clients to another host:

```console
tailscale serve drain svc:grafana
tailscale serve advertise svc:grafana  # host again
```

## Reach a service

Clients reach the service at `<label>.<dns.base_domain>`, for example `grafana.example.com`, or at the VIPs.
Only clients that the policy lets reach the service get the name and the route to the VIPs.
When a node's MagicDNS name uses the same label, the node keeps the name and the service is reachable at its VIPs.

Tailscale v1.94 and later route to a service without options.
Linux clients from v1.86 to v1.93 need `--accept-routes`.

## VIPs or claimed names

A service can have both a VIP name and [node-claimed hostnames](dns.md#node-claimed-hostnames).
They behave differently when a host stops hosting the service:

- **A VIP move resets open connections.**
  A client sends all its traffic for a VIP to one host.
  When Headscale moves the client to another host, all the client's open connections to the service break at once,
  and the client has to reconnect.
- **A claimed name drains gracefully.**
  A node-claimed hostname answers with the addresses of the claiming hosts, also when the service has VIPs.
  When a host withdraws its claim, new connections go to another host after the client's DNS cache expires, and the
  connections that are open keep their address and finish on the old host.

Use claimed names for services that must drain without resetting connections, for example the replicas of a load
balancer.
Use the VIP name for clients that need one fixed address.

## How Headscale picks a host

Headscale puts the VIPs on exactly one host in each client's network map:

- A new client gets the host that rendezvous hashing prefers for it among the online hosts that advertise the service,
  so new clients spread evenly over the hosts.
- A client keeps its host while that host is up, because a move resets its open connections.
- When a host drains or goes offline, its clients move at once to their preferred remaining host.
  A drain takes effect within about a second; a clean stop after about 10 seconds, when Headscale marks the host offline.
  Other clients do not change.
- When a host starts to host the service, it takes no clients at once.
  A rebalance then moves clients to it gradually, at most `services.rebalance.moves_per_host_per_minute` clients from each
  other host per minute, until every host is within `services.rebalance.tolerance` of its preferred share.
- Headscale keeps the assignments in memory.
  For `services.startup_grace` after Headscale starts, clients follow their preferred host at once, so the hosts that
  reconnect one after another after a restart share the clients instead of the first host keeping all of them.
- When Headscale is unreachable, clients keep their host, and there is no failover until Headscale is back.

```yaml title="config.yaml"
services:
  startup_grace: 60s
  rebalance:
    interval: 10s                 # 0 disables the rebalance
    moves_per_host_per_minute: 12 # each move resets one client's connections
    tolerance: 0.1
```

With the defaults, a host loses at most one client to the rebalance every 5 seconds.
For example, with 1200 clients on 3 hosts, a fourth host has a preferred share of about 300 clients.
The rebalance moves about 267 of them in about 7 to 8 minutes, and then stops: every host is within the 10 % tolerance of
its share, so the last clients keep their host instead of having their connections reset.

## Downgrade

Tailscale Services add the `services` table to the database.
A Headscale version without Tailscale Services rejects a policy that uses `autoApprovers.services` or `svc:`, and with
SQLite it refuses to start while the `services` table exists, because it checks the database schema.
Remove the services from the policy and drop the table before a downgrade.


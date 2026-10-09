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
    "tag:gw-cca": ["alice@"]
  },
  "autoApprovers": {
    "services": {
      "svc:cca": ["tag:gw-cca"]
    }
  },
  "grants": [
    // Members reach the service on TCP port 443.
    { "src": ["autogroup:member"], "dst": ["svc:cca"], "ip": ["tcp:443"] }
  ]
}
```

- Headscale allocates the VIPs when the policy first defines the service, from the address ranges in `prefixes`, and
  stores them in the database.
  A service keeps its VIPs across restarts, and when the policy removes and adds it again.
  Headscale never gives a VIP to a node or to another service.
- `svc:<label>` is a destination for grants and ACLs (`"svc:cca:443"` in an ACL).
  It cannot be a source, an SSH destination or a `nodeAttrs` target.
- A grant to the tag of the hosts lets clients reach the hosts' own addresses, not the service.
- Give each service its own tag, and register its hosts with a pre-auth key for that tag, so that a node of one service
  cannot host another.

## Host a service

A host serves the service and advertises it:

```console
tailscale serve --service=svc:cca --https=443 127.0.0.1:8443
tailscale serve --service=svc:cca --tcp=443 tcp://127.0.0.1:8443
```

A [tsnet](https://tailscale.com/docs/features/tsnet) program uses `Server.ListenService`.
The host accepts traffic to the VIPs only on the ports its serve configuration lists.

To drain a host, stop advertising the service; the host keeps serving the connections it has, and Headscale moves its
clients to another host:

```console
tailscale serve drain svc:cca
tailscale serve advertise svc:cca  # host again
```

## Reach a service

Clients reach the service at `<label>.<dns.base_domain>`, for example `cca.example.com`, or at the VIPs.
Only clients that the policy lets reach the service get the name and the route to the VIPs.
When a node's MagicDNS name uses the same label, the node keeps the name and the service is reachable at its VIPs.
A [node-claimed hostname](dns.md#node-claimed-hostnames) of the service still answers with the addresses of the
claiming nodes, not with the VIPs.
Use it where open connections must survive a drain: a client keeps the address it connected to, while a VIP move takes all
of the client's connections at once.

Tailscale v1.94 and later route to a service without options.
Linux clients from v1.86 to v1.93 need `--accept-routes`.

## How Headscale picks a host

A Tailscale client sends all traffic for a VIP to one peer, so Headscale puts the VIPs on exactly one host in each
client's network map:

- Each client gets its own host, chosen by rendezvous hashing over the online hosts that advertise the service, so the
  clients spread evenly over the hosts and a client keeps its host while that host is up.
- When a host drains, the clients of that host move to their next host within about a second.
  Other clients do not change.
- When a host goes offline, Headscale moves its clients after it marks the host offline, about 10 seconds after a clean
  stop.
- When a host starts to host the service, it takes its share of the clients from the other hosts.
- A move takes all of a client's connections to the service with it: connections that were open to the old host break,
  and the client has to reconnect.
- When Headscale is unreachable, clients keep their host, and there is no failover until Headscale is back.

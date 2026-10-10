# Configuration

- Headscale loads its configuration from a YAML file
- It searches for `config.yaml` in the following paths:
    - `/etc/headscale`
    - `$HOME/.headscale`
    - the current working directory
- To load the configuration from a different path, use:
    - the command line flag `-c`, `--config`
    - the environment variable `HEADSCALE_CONFIG`
- Validate the configuration file with: `headscale configtest`

!!! example "Get the [example configuration from the GitHub repository](https://github.com/juanfont/headscale/blob/main/config-example.yaml)"

    Always select the [same GitHub tag](https://github.com/juanfont/headscale/tags) as the released version you use to
    ensure you have the correct example configuration. The `main` branch might contain unreleased changes.

    === "View on GitHub"

        - Development version: <https://github.com/juanfont/headscale/blob/main/config-example.yaml>
        - Version {{ headscale.version }}: https://github.com/juanfont/headscale/blob/v{{ headscale.version }}/config-example.yaml

    === "Download with `wget`"

        ```shell
        # Development version
        wget -O config.yaml https://raw.githubusercontent.com/juanfont/headscale/main/config-example.yaml

        # Version {{ headscale.version }}
        wget -O config.yaml https://raw.githubusercontent.com/juanfont/headscale/v{{ headscale.version }}/config-example.yaml
        ```

    === "Download with `curl`"

        ```shell
        # Development version
        curl -o config.yaml https://raw.githubusercontent.com/juanfont/headscale/main/config-example.yaml

        # Version {{ headscale.version }}
        curl -o config.yaml https://raw.githubusercontent.com/juanfont/headscale/v{{ headscale.version }}/config-example.yaml
        ```

## Node connection health

Every online node keeps one control connection open to Headscale.
When the network path of a node is lost without a clean close, for example when its host crashes, its cable is pulled or
it falls asleep, Headscale would only notice when TCP gives up, which takes about 15 minutes on Linux.
Until then the node stays online: peers and `headscale nodes list` show it as online, and what waits for a node to go
offline waits too, such as the cleanup of an ephemeral node after `node.ephemeral.inactivity_timeout`.
HA subnet routers are the exception: when HA routes exist, Headscale probes those routers every
`node.routes.ha.probe_interval` and moves the routes away from one that does not answer, without waiting for it to go
offline.

Headscale therefore checks the connection with HTTP/2 PING frames:

- When Headscale has read nothing from a node for `noise.ping_after_idle` (default `30s`), it sends a PING.
- When the node does not answer within `noise.ping_timeout` (default `20s`), Headscale closes the connection.
- When the node does not reconnect within 10 seconds, Headscale marks it offline.

A node is offline 30 to 60 seconds after it is lost with the defaults.
A healthy client answers every PING in its HTTP/2 stack, so an idle client stays connected.
A client on a bad network is marked offline only when it cannot answer for more than `noise.ping_timeout` and then does
not reconnect within 10 seconds.
Lower values find lost nodes sooner, but mark nodes on slow or unstable networks offline more often, and make idle
devices, such as phones, wake their radio more often.
When the check is enabled, `noise.ping_after_idle` must be at least `5s` and `noise.ping_timeout` at least `1s`;
`headscale configtest` rejects lower, negative and malformed values.

The cost of the defaults: an idle node exchanges one small PING and its answer about every 30 seconds.
Headscale already sends each node a map keepalive every 50 to 59 seconds, so for an idle phone the check adds about
twice as many radio wake-ups as the keepalive, about three times as many in total.
With `noise.ping_after_idle: 60s` the PING cost halves, and lost nodes are offline 30 to 90 seconds after the loss.

The `noise.ping_timeout` window includes the time the PING waits behind map data already queued for the node.
A very large network map sent over a very slow link can therefore exceed it; the node then reconnects.

Headscale logs a closed connection as a warning with the message `timeout waiting for PING response`, and counts it in
the `headscale_noise_http2_errors_total{type="conn_close_lost_ping"}` metric.
Set `noise.ping_after_idle: 0` to disable the check.
Headscale versions without the check ignore the `noise.ping_after_idle` and `noise.ping_timeout` keys, so a
configuration that sets them still loads after a downgrade.

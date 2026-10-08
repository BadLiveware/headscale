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
Until then the node stays online for its peers, and its subnet routes, exit node and other online-only roles stay with it.

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
Set `noise.ping_after_idle: 0` to disable the check.


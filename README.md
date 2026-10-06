# Mosquitto Dynamic Security Admin UI

A static browser UI for Mosquitto's Dynamic Security plugin.

**[Run DynSecUI online](https://ryangriggs.github.io/DynSecUI/)**

## Features

- Static HTML/CSS/JavaScript; no backend or database.
- Saved broker connection profiles in browser `localStorage`.
- `ws://` and `wss://` MQTT-over-WebSocket connections.
- Connection passwords are saved with broker profiles in browser `localStorage`.
- Client management:
  - create/delete
  - enable/disable
  - client ID
  - password changes
  - text name/description
  - direct roles and group memberships with priorities
- Group management:
  - create/delete
  - text name/description
  - roles with priorities
- Role management:
  - create/delete
  - text name/description
  - complete ACL editing
- Default ACL access management.
- Anonymous group management.
- Live MQTT topic browser with configurable subscriptions (defaulting to `#` and `$SYS/#`).
- Topic publishing with QoS 0/1 and retained-message support.
- Raw API panel for sending any Dynamic Security command not represented by the forms.
- Session traffic log for inspecting and copying every published command and subscribed response.

## Run

Serve this directory from any static HTTP server or GitHub Pages.

For a quick local server:

    python -m http.server 8080

Then open:

    http://localhost:8080/

The broker must expose a Mosquitto WebSockets listener.

Example:

    listener 8083
    protocol websockets

For production use, use `wss://` and a valid TLS certificate.

## GitHub Pages / HTTPS note

A page loaded over HTTPS normally cannot open an insecure `ws://` connection because browsers block mixed content. Use `wss://` for a GitHub Pages deployment.

## MQTT.js

`index.html` currently loads MQTT.js 5.16.0 from unpkg:

    https://unpkg.com/mqtt@5.16.0/dist/mqtt.min.js

To make the project completely self-contained, download that file to:

    vendor/mqtt.min.js

and change:

    <script src="https://unpkg.com/mqtt@5.16.0/dist/mqtt.min.js"></script>

to:

    <script src="vendor/mqtt.min.js"></script>

No package manager or build step is required.

## Mosquitto permissions

The administration account must be permitted to publish to and receive/subscribe from:

    $CONTROL/dynamic-security/#

To use the topic browser, the account must also have subscribe and receive permissions for its configured topic filters. The defaults are:

    #
    $SYS/#

Publishing from the topic browser requires publish permission for the destination topic.

Commands are published to:

    $CONTROL/dynamic-security/v1

Responses are received from:

    $CONTROL/dynamic-security/v1/response

## Security

This is intentionally a client-side administration tool. Anyone using it supplies broker admin credentials directly to the broker over WebSockets.

Do not use `ws://` over an untrusted network. Dynamic Security operations can include new client passwords, so production administration should use `wss://`.

Connection passwords are persisted unencrypted in browser `localStorage` so saved profiles can connect without prompting. Any script running on the same origin, anyone with access to the browser profile, or browser tooling available to a local user may be able to read them. Use this UI only on a trusted device and origin, and avoid shared browser profiles.

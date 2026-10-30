# DonationAlerts Provider — OBS plugin

[English](./README.md) | [Русский](./README.ru.md)

A native C++ plugin for OBS Studio on Windows x64. It hosts a local API inside OBS; no separate Node.js server is required.

> This is an independent community project. It is not an official DonationAlerts or OBS Project product and is not endorsed by either. All names and trademarks belong to their respective owners.

> **Status:** OAuth account connection, real-time donations via Centrifugo WebSocket, and forwarding events to local widget WebSockets are implemented. Donation history is polled every five seconds. Goals and polls are not implemented yet.

## Install a release

The current build requires **OBS Studio 32.2.2 x64**. Other OBS versions and 32-bit builds are not supported.

1. Fully exit OBS, including from the system tray.
2. Obtain `donationalerts-obs-provider.dll` from a project build or release.
3. On Windows, the installer installs the plugin for all users under `%ProgramData%` and requests administrator permission through UAC.
4. From the project root, run:

   ```powershell
   .\tools\install-obs-plugin.ps1
   ```

   The script checks the OBS version, plugin DLL, Qt Schannel TLS backend, and locale files, then installs them under `%ProgramData%\obs-studio\plugins`. For a DLL in a different location, pass `-DllPath "D:\Downloads\donationalerts-obs-provider.dll"`. For a non-standard OBS directory, pass `-ObsInstallRoot "D:\Apps\obs-studio"`. To install a Debug build, use `-Configuration Debug`.
5. Start OBS. If the plugin loaded, **DonationAlerts Provider** appears in the **Tools** menu. The panel follows the OBS language and supports English and Russian.
6. Open **Tools → DonationAlerts Provider**. This is a separate window, not an OBS dock.
7. Enter your DonationAlerts application ID and secret. Register the exact redirect URI shown in the panel in your application settings, then click **Connect account**. Approve access in the browser. OAuth credentials are encrypted with Windows DPAPI for the current Windows user.
8. Issue a widget key with donation-event access. Keys are non-expiring by default; to set an expiration, clear **Never expires** and choose a calendar date. The secret is shown only once and can be copied from the dialog. A widget key does not replace the DonationAlerts OAuth connection.

To uninstall, exit OBS and remove `%ProgramData%\obs-studio\plugins\donationalerts-obs-provider`.

## Development setup

This is not required if you already have a built DLL. To build from source, install:

- OBS Studio **32.2.2 x64**;
- Visual Studio 2022 with the Desktop development with C++ workload;
- Windows SDK **10.0.26100**;
- CMake **3.28 or newer**;
- `curl.exe`.

From the project root, prepare the OBS SDK in PowerShell:

```powershell
.\tools\prepare-obs-sdk.ps1
```

The script downloads the official OBS source archive, verifies its SHA-256 hash, configures CMake, and builds `libobs` and the OBS Frontend API. Pass `-Configuration Debug` to build a Debug SDK instead of Release. SDK sources and build files are stored in the ignored `.obs-sdk` directory.

Build and test the plugin:

```powershell
cmake -S .\obs-plugin -B .\obs-plugin\build -G "Visual Studio 17 2022" -A "x64,version=10.0.26100.0"
cmake --build .\obs-plugin\build --config Release
ctest --test-dir .\obs-plugin\build -C Release --output-on-failure
```

The plugin DLL is written to:

```text
obs-plugin\build\Release\donationalerts-obs-provider.dll
```

Alternatively, from an elevated PowerShell in the project root, install with CMake while OBS is closed:

```powershell
cmake --install .\obs-plugin\build --config Release --prefix "$env:ProgramData\obs-studio"
```

## Features and limitations

The plugin adds a **DonationAlerts Provider** settings window, connects to DonationAlerts using OAuth 2.0 Authorization Code, and starts a local HTTP API at `127.0.0.1:4041` and a widget-event WebSocket at `127.0.0.1:4043`. OAuth tokens are encrypted with Windows DPAPI. On OBS startup, the plugin restores the saved connection, refreshes the access token when needed, fetches the profile, and starts the Centrifugo WebSocket. The initial OAuth authorization must be completed manually once in **Tools → DonationAlerts Provider**.

To inspect incoming data, enable **Debug mode** at the bottom of the settings window. The debug area shows REST history responses and incoming Centrifugo messages; known OAuth and realtime tokens are masked. It is kept in memory and limited to the last 300 lines. Responses may contain donor names and messages; review logs and screenshots before sharing them.

### Local API

- `GET /health` — check that the local API is running.
- `GET /api/widget-tokens` — list saved widget keys and metadata. Expired keys are marked `active: false` and remain available for revocation.
- `POST /api/widget-tokens` — issue a key. `expiresAt=0` means no expiration; a positive Unix timestamp in milliseconds sets the expiration date. The legacy `expiresInMinutes` field remains supported for compatibility (up to 24 hours).
- `POST /api/widget-tokens/revoke` — revoke a key by ID, including after it expires.
- `GET /api/widget/data` — get the profile and recent donations; requires an `Authorization` header with a widget key.
- `GET /api/v1/alerts/donations` — DonationAlerts-compatible proxy, including query parameters. It uses a local widget key for authorization; the OAuth token remains in OBS.
- `GET /api/v1/user/oauth` — profile in DonationAlerts response format, without the Centrifugo socket token.
- `ws://127.0.0.1:4043/api/widget/events` — real-time widget event stream. Pass the widget key as the second WebSocket subprotocol: `donationalerts-widget-v1`, `<widget-token>`.

For the API-compatible routes, replace only the DonationAlerts base URL with `http://127.0.0.1:4041`; paths, query parameters, and JSON format remain the same. For example:

```text
https://www.donationalerts.com/api/v1/alerts/donations?per_page=30
http://127.0.0.1:4041/api/v1/alerts/donations?per_page=30
```

The proxy makes requests to DonationAlerts on behalf of the connected account and returns its HTTP status and JSON response. Only profile and donation-history reads are proxied; other DonationAlerts routes are intentionally not exposed. The direct history proxy requires an OBS account connection.

Read-only scoped routes allow browser sources with HTTP(S) Origins, including remotely hosted OBS Browser Sources. Every request still requires a valid key with `read:donation-events`. Other local administrative and provider routes retain their Origin restrictions.

Widget-key metadata is encrypted with Windows DPAPI until revoked. New keys do not expire by default. If an expiration date is selected, the key remains valid through the end of that day in local time; there is no 24-hour limit for this date-based API. Previously issued keys retain their original expiration. Expiration disables API and WebSocket access but does not remove the record; active and expired keys can both be revoked. At most 500 records are stored, so revoke unused keys before issuing another when the limit is reached.

Example request from an OBS Browser Source:

```js
const widgetToken = "YOUR_WIDGET_TOKEN";
const response = await fetch("http://127.0.0.1:4041/api/widget/data", {
  headers: { Authorization: `Bearer ${widgetToken}` }
});
const { profile, donations } = await response.json();
```

For HTTP requests, including cross-origin OBS browser widgets, send the key in the `Authorization` header, not in the URL. The browser WebSocket API does not support arbitrary authorization headers, so the local WebSocket accepts the key as a subprotocol. The DonationAlerts OAuth token is never passed to a widget.

### Demo widgets

Open `obs-plugin\demo\widget-demo.html` in a browser or use the installed copy at `%ProgramData%\obs-studio\plugins\donationalerts-obs-provider\data\demo\widget-demo.html` as an OBS Browser Source. The page accepts a key from the page URL's `token` parameter, saves it in browser local storage, and connects automatically. On later visits it restores the saved key; if there is no URL parameter or saved key, enter one manually.

An event appears only when a push message arrives over the socket; history is never used to simulate new events. The page loads history on connection, on manual request, and after a new real-time donation; it does not poll REST periodically. For example, append `?token=YOUR_WIDGET_TOKEN` to the page URL.

Additional minimal Browser Source examples use the same restricted widget key issued in the OBS panel:

- `obs-plugin\demo\widget-plugin-api.html` — fetches a snapshot from `GET /api/widget/data` and receives real-time events over the local WebSocket.
- `obs-plugin\demo\widget-donationalerts-api.html` — uses the API-compatible `GET /api/v1/user/oauth` and `GET /api/v1/alerts/donations?per_page=30` routes.
- `obs-plugin\demo\widget-stream-alert.html` — animated notification for a new donation with donor name, amount, and message.
- `obs-plugin\demo\widget-stream-feed.html` — compact feed of recent donations.

The last two examples share `widget-stream.css` and `widget-stream.js` and show different history sources:

- **Alert** loads history using the plugin API `GET /api/widget/data`; real-time events arrive over the plugin WebSocket.
- **Feed** loads history using the DonationAlerts-compatible `GET /api/v1/alerts/donations?per_page=30` route and the provider key. Real-time events also arrive over the plugin WebSocket.

The key issued in the OBS panel must have **Donation events** access. It is a restricted provider key, not a DonationAlerts OAuth token. Open the page in a browser for preview, enter the key, and click **Connect**. Once connected, the key field collapses; click **Key settings** to reopen it. The **Test alert** and **Sample entry** buttons are hidden by default and shown only in preview mode (`?preview=1`). Use the local files under `%ProgramData%\obs-studio\plugins\donationalerts-obs-provider\data\demo\` or the repository's `obs-plugin\demo\` directory as Browser Sources. Append `?overlay=1` (and optionally `?token=YOUR_WIDGET_TOKEN`) for a clean transparent overlay with settings and test controls hidden.

The demo removes the `token` parameter from the page address after loading. HTTP requests send the key only in the `Authorization` header; the local WebSocket passes it as a subprotocol, not in the socket URL. The demo stores the key in the browser profile's `localStorage`, where page scripts and users with access to that profile can read it. **Disconnect** removes it from storage. OBS also saves a Browser Source URL containing `?token=` in its settings. Use a separate, revocable widget key and revoke it if exposed. The page must run on the same computer as OBS. Real-time donations flow from DonationAlerts to the plugin and then to the local widget WebSocket; REST is used only for history.

Administrative panel requests require an internal `X-Admin-Token`, held in plugin memory and not logged. Widget-key secrets are shown only once. The plugin supports read-only scopes for donation events, goals, and polls, although goals and polls are not yet available. It stores only the SHA-256 hash of each widget key and its metadata; these are encrypted with Windows DPAPI and saved to `%APPDATA%\obs-studio\plugin_config\donationalerts-obs-provider-tokens.dat`. Active keys survive OBS restarts until expiration or revocation. Access to the file is tied to the Windows account running OBS.

**Limitations:** The real-time subscription uses OAuth/Centrifugo endpoints described in the [DonationAlerts API documentation](https://www.donationalerts.com/apidoc) and requires the `oauth-donation-subscribe` permission. If the real-time socket is disconnected, the OBS panel shows an error and the demo does not fabricate events from REST history. Goals and polls are not forwarded yet. OAuth credentials and widget keys are encrypted at rest; the data snapshot is held in memory and cleared when OBS closes. The redirect URI must exactly match the one registered in your DonationAlerts application.

Do not expose the local ports to the public internet. If the plugin fails to load, verify that OBS was closed during installation, that **OBS 32.2.2 x64** is installed, that the DLL is under `bin\64bit`, and that the OBS log does not report missing dependencies or port `4041` being in use.

## License and contributing

This project is distributed under the **GNU General Public License, version 2 or (at your option) any later version**. See [LICENSE](./LICENSE) for the full text. GPL is a copyleft license: when distributing the application or modified versions, preserve the license and provide the corresponding source under GPL. It does not transfer copyright or grant rights to third-party trademarks.

OBS Studio, Qt, and other third-party components retain their own licenses and notices. Before publishing a bundled installer or DLL, review the licenses for the specific binaries you distribute and include any required notices and source code. The project license does not replace those obligations.

Report bugs and propose features through GitHub Issues; submit changes through Pull Requests. See [CONTRIBUTING.md](./CONTRIBUTING.md) for testing, safe handling of logs, and DCO sign-off. Never publish OAuth secrets, tokens, authorization codes, or donors' personal data.

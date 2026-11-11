# IP & Flag Monitor

A browser extension for **Chrome, Edge, Brave and Firefox** (Manifest V3) that shows where your connection
really comes from — and what the site you're viewing is connected to.

- The **toolbar icon is the flag** of the country your connection exits from, refreshed every 60 seconds.
- Click it for your public IP, the **server IP of the current site**, and a set of safe network checks.

<!-- Add screenshots here, e.g. ![Popup](docs/popup.png) -->

## Features

**This computer** — public IP (click to copy), country/city, ISP and ASN, time zone, local IP, and a warning
when your IP or country changes.

**Site you're viewing** — the IP your browser actually connected to, other DNS records, and the server's
country flag and hosting provider.

**Safe network checks** (run when you open the popup and every 60 s while it is open):

| Check | What it does |
|---|---|
| Latency | HTTPS round-trip "ping" to Cloudflare, Google, Microsoft and the viewed site: avg / min / max, jitter, replies |
| DNS | Resolves a name through Cloudflare and Google DNS-over-HTTPS and compares the answers |
| IPv4 / IPv6 | Tests reachability of each stack and shows the address seen |
| WebRTC / VPN leak | Compares the address STUN servers see with the address the web sees |
| Viewed site | Ports 80/443 behaviour (HTTP→HTTPS redirect) and security headers (HSTS, CSP, X-Frame-Options, …) |
| Browser | Online state and link estimates where the browser exposes them |

The background job keeps running with the popup closed. A red `!` badge appears when you are offline or lookups fail.

## Install

**Chrome / Edge / Brave:** open `chrome://extensions`, enable *Developer mode*, choose *Load unpacked*
and select this folder.

**Firefox:** open `about:debugging#/runtime/this-firefox`, choose *Load Temporary Add-on* and select
`manifest.json`. Temporary add-ons are removed when Firefox closes; a permanent install needs the add-on
signed through addons.mozilla.org (or Firefox Developer Edition/Nightly with
`xpinstall.signatures.required` set to `false`). If the site IP stays empty, open `about:addons` →
the extension → *Permissions* and allow access to all websites.

Packaged zips are attached to each [GitHub release](../../releases).

## Permissions — why they are needed

| Permission | Reason |
|---|---|
| `webRequest` | Read the server IP the browser connected to for each page load (read-only, nothing is blocked or modified) |
| `alarms` | Run the 60-second refresh while the popup is closed |
| `storage` | Cache the last result and per-tab site IPs |
| `tabs` | Know which site is in the active tab |
| `<all_urls>` (host) | Fetch headers of the viewed site and call the lookup services |

## Privacy

There is no server and no analytics: everything runs in your browser and nothing is sent to the author.
To work, the extension contacts these third-party services, which therefore see your public IP:

- **ipwho.is** (fallbacks: ipapi.co, api.country.is) — IP geolocation
- **flagcdn.com** — flag images
- **Cloudflare and Google DNS-over-HTTPS** — DNS tests and site IP lookup
- **ipify** — IPv4/IPv6 tests
- **Google and Cloudflare STUN** — WebRTC leak check
- **The site you are viewing, plus Cloudflare, Google and Microsoft endpoints** — latency probes

The provider lists are at the top of `background.js` and `popup.js` if you want to change them.

## Limitations

Browsers do not allow ICMP pings, traceroute or raw port scans, so none are attempted. "Ping" is the time of an
HTTPS request, and the only port checks are 80/443 on the site you are viewing. Nothing on other hosts or your
local network is scanned. If you use a VPN, proxy or split tunnelling, different services may see different
addresses; the leak check reports exactly that.

## Roadmap

- Options page (refresh interval, ping targets, providers)
- IP/country change history and notifications
- Latency graphs and report export
- Better handling of proxy/tunnel addresses (CGNAT / fake-IP ranges)

## Development

No build step. Load the folder as an unpacked extension and reload it after editing. To make a release,
push a tag such as `v1.0.0`; the workflow in `.github/workflows/release.yml` attaches a zip to a GitHub release.

## License

[MIT](LICENSE)

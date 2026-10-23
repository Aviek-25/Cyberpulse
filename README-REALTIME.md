# CyberPulse real-time security API integration

This version keeps the existing HTML/CSS/JS dashboard, Stage 8 network map, and Stage 9 analytics. It adds a Node/Express backend that calls a configured security provider API from the server, so API credentials are not sent to the browser.

## Requirements
- Node.js 18 or newer
- A running Wazuh server + Wazuh indexer, with at least one enrolled agent generating alerts
- Network connectivity from the machine running CyberPulse to the Wazuh indexer over HTTPS
- A Wazuh indexer account with permission to read `wazuh-alerts-*`

## Wazuh self-hosted cloud-server setup
This connector queries the **Wazuh indexer** for alert documents (`wazuh-alerts-*`). The Wazuh manager API on port 55000 manages agents/configuration; the indexer search API (usually port 9200) is where indexed alert documents are queried. Wazuh documents this alert index pattern and its search API. Never expose port 9200 publicly; use a private network, VPN, or strict source-IP allowlist.

1. Confirm Wazuh is installed on your cloud server and its dashboard shows at least one enrolled agent. Official quickstart: https://documentation.wazuh.com/current/quickstart.html
2. Confirm the Wazuh indexer is healthy from the cloud server or a machine allowed to reach it. Follow the official indexer API guide: https://documentation.wazuh.com/current/user-manual/indexer-api/getting-started.html
3. On the machine where CyberPulse's Node server runs, copy `.env.example` to `.env`.
4. Set `WAZUH_INDEXER_URL` to the HTTPS indexer URL reachable from that machine, usually port `9200`. Prefer a private address such as `https://10.x.x.x:9200`; don't guess an address or use the dashboard URL unless it is actually the indexer endpoint.
5. Set `WAZUH_INDEXER_USER` and `WAZUH_INDEXER_PASSWORD` to an indexer account with read access to `wazuh-alerts-*`. Do not use the credentials in browser JavaScript or commit `.env` to GitHub.
6. Leave `WAZUH_INDEX_PATTERN=wazuh-alerts-*` unless your index naming is customized. Keep certificate verification enabled and use a certificate trusted by the Node server.
7. Run `npm install`, then `npm start`.
8. Open `http://localhost:3000/api/health` and `http://localhost:3000/api/security/events` to verify the connector. Then open `http://localhost:3000`.

**If you use Wazuh Cloud (the managed service), rather than installing Wazuh yourself on a cloud VM:** do not use these indexer credentials unless your service plan provides direct indexer access. Wazuh Cloud has separate API-key authentication and may require API access to be enabled for your source IP. See https://documentation.wazuh.com/current/cloud-service/apis/authentication.html and https://documentation.wazuh.com/current/cloud-service/your-environment/technical-faq.html. The connector will need to be adapted to the endpoints included in your Wazuh Cloud plan.

## Setup on Windows / VS Code
1. Extract this folder and open it in VS Code.
2. Open Terminal > New Terminal.
3. Run `npm install`.
4. Copy `.env.example` to a new file named `.env`.
5. Fill `SECURITY_API_URL` with the provider's actual event/alert endpoint and set `SECURITY_API_KEY` if required. Keep `.env` private and do not commit it to GitHub.
6. If the provider uses a non-Bearer auth format, adjust `SECURITY_API_AUTH_HEADER`, `SECURITY_API_AUTH_SCHEME`, and `SECURITY_API_KEY_PREFIX` according to that provider's official docs.
7. Run `npm start`.
8. Open `http://localhost:3000` (do not open index.html using `file://`).
9. Check `http://localhost:3000/api/health` to see whether the provider URL is configured, and `http://localhost:3000/api/security/events` to inspect normalized events.

## What the integration does
- The browser polls the local backend every 10 seconds.
- The backend calls the configured external API and normalizes common event fields.
- The dashboard Threat Center and Stage 9 analytics refresh from the API events.
- The browser does not receive the API key.
- Once API mode is active, the frontend pauses simulated event generation to avoid mixing demo events with provider events.

## Provider-specific notes
- When `WAZUH_INDEXER_URL` is set, the backend uses the Wazuh indexer search API and reads `hits.hits` from `wazuh-alerts-*`.
- Otherwise, the existing generic REST connector is used when `SECURITY_API_URL` is configured.
- Wazuh alert fields such as `rule.level`, `rule.description`, `agent.name`, `data.srcip`, `full_log`, and `@timestamp` are normalized for the existing dashboard.
- Do not paste API secrets into chat or frontend JavaScript.

## Limitations
This implementation polls an API; it does not directly sniff network packets or guarantee instantaneous detection. Actual detection depends on the configured provider and the permissions and event types available to its API. A successful API connection means events are being retrieved, not that every attack will be detected.

'use strict';

require('dotenv').config();
const express = require('express');
const path = require('path');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const API_URL = process.env.SECURITY_API_URL || '';
const API_KEY = process.env.SECURITY_API_KEY || '';
const AUTH_HEADER = process.env.SECURITY_API_AUTH_HEADER || 'Authorization';
const AUTH_SCHEME = process.env.SECURITY_API_AUTH_SCHEME === undefined
  ? 'Bearer' : process.env.SECURITY_API_AUTH_SCHEME;
const API_KEY_PREFIX = process.env.SECURITY_API_KEY_PREFIX || '';
const WAZUH_INDEXER_URL = (process.env.WAZUH_INDEXER_URL || '').trim();
const WAZUH_INDEXER_USER = process.env.WAZUH_INDEXER_USER || '';
const WAZUH_INDEXER_PASSWORD = process.env.WAZUH_INDEXER_PASSWORD || '';
const WAZUH_INDEX_PATTERN = process.env.WAZUH_INDEX_PATTERN || 'wazuh-alerts-*';
const EVENTS_PATH = process.env.SECURITY_API_EVENTS_PATH || '';
const POLL_TIMEOUT_MS = Math.max(1000, Number(process.env.SECURITY_API_TIMEOUT_MS || 8000));

app.disable('x-powered-by');
app.use(express.json({ limit: '256kb' }));
// Do not let static-file requests download backend source, package metadata, or secrets.
app.use((req, res, next) => {
  if (/\/(?:server\.js|package(?:-lock)?\.json|\.env(?:\..*)?|README[^/]*)$/i.test(req.path)) {
    return res.status(404).send('Not found');
  }
  next();
});
app.use(express.static(path.join(__dirname), { dotfiles: 'deny' }));

let cached = { events: [], provider: 'Not configured', lastUpdated: null, error: null };
let lastFetchAt = 0;
let fetchInFlight = null;
const CACHE_MS = Math.max(3000, Number(process.env.SECURITY_API_CACHE_MS || 8000));

function findEventArray(payload) {
  if (Array.isArray(payload)) return payload;
  if (!payload || typeof payload !== 'object') return null;
  const candidates = [payload.events, payload.alerts, payload.results, payload.data, payload.items, payload.hits];
  for (const candidate of candidates) {
    if (Array.isArray(candidate)) return candidate;
    if (candidate && typeof candidate === 'object') {
      const nested = findEventArray(candidate);
      if (nested) return nested;
    }
  }
  // Elasticsearch-style response.
  if (payload.hits && Array.isArray(payload.hits.hits)) {
    return payload.hits.hits.map(hit => ({ ...(hit._source || {}), id: hit._id || hit._source?.id }));
  }
  return null;
}

function normalizeSeverity(value) {
  const text = String(value ?? 'medium').toLowerCase();
  if (/critical|emergency|fatal|\b(15|14)\b/.test(text)) return 'Critical';
  if (/high|severe|\b(12|13)\b/.test(text)) return 'High';
  if (/low|informational|info|\b(1|2|3|4)\b/.test(text)) return 'Low';
  return 'Medium';
}

function normalizeEvent(raw, index) {
  const e = raw && typeof raw === 'object' ? raw : {};
  const nested = e._source && typeof e._source === 'object' ? e._source : e;
  const rule = nested.rule && typeof nested.rule === 'object' ? nested.rule : {};
  const agent = nested.agent && typeof nested.agent === 'object' ? nested.agent : {};
  const data = nested.data && typeof nested.data === 'object' ? nested.data : {};
  const timestampValue = nested.timestamp ?? nested['@timestamp'] ?? nested.created_at ?? nested.createdAt ?? nested.time ?? Date.now();
  let timestamp = typeof timestampValue === 'number' ? timestampValue : Date.parse(timestampValue);
  if (!Number.isFinite(timestamp)) timestamp = Date.now();
  if (timestamp < 1e12) timestamp *= 1000;
  const severity = normalizeSeverity(nested.severity ?? nested.level ?? rule.level ?? nested.priority);
  const name = nested.name ?? nested.title ?? nested.rule_name ?? rule.description ?? nested.alert_name ?? nested.event_type ?? 'Security event';
  const id = nested.id ?? e._id ?? nested.event_id ?? nested.uuid ?? nested.alert_id ?? `api-${timestamp}-${index}`;
  const source = nested.source_ip ?? nested.src_ip ?? data.srcip ?? data.src_ip ?? agent.name ?? nested.agent_name ?? nested.host?.name ?? nested.host ?? 'Unknown source';
  const statusValue = String(nested.status ?? 'Open');
  const status = /resolved|closed|dismissed/i.test(statusValue) ? 'Resolved' : (/review|investigating|in.progress/i.test(statusValue) ? 'Review' : 'Open');
  const mitre = rule.mitre && Array.isArray(rule.mitre.id) ? ` MITRE: ${rule.mitre.id.join(', ')}.` : '';
  return {
    id: String(id), name: String(name), severity, source: String(source), status,
    description: String(nested.description ?? nested.full_log ?? nested.message ?? nested.full_log ?? 'Imported from the configured security provider.'),
    recommendation: String(nested.recommendation ?? nested.action ?? `Review this alert in Wazuh.${mitre}`),
    timestamp
  };
}

async function fetchWazuhAlerts() {
  if (!WAZUH_INDEXER_URL || !WAZUH_INDEXER_USER || !WAZUH_INDEXER_PASSWORD) {
    throw new Error('Wazuh is not fully configured. Set WAZUH_INDEXER_URL, WAZUH_INDEXER_USER, and WAZUH_INDEXER_PASSWORD in .env.');
  }
  const base = new URL(WAZUH_INDEXER_URL);
  const endpoint = `${base.toString().replace(/\/$/, '')}/${encodeURIComponent(WAZUH_INDEX_PATTERN)}/_search`;
  const basic = Buffer.from(`${WAZUH_INDEXER_USER}:${WAZUH_INDEXER_PASSWORD}`).toString('base64');
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), POLL_TIMEOUT_MS);
  try {
    // Wazuh indexer uses OpenSearch-compatible search. Credentials remain on this backend.
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Accept': 'application/json', 'Content-Type': 'application/json', 'Authorization': `Basic ${basic}` },
      body: JSON.stringify({ size: 100, sort: [{ '@timestamp': { order: 'desc', unmapped_type: 'date' } }], query: { match_all: {} } }),
      signal: controller.signal,
      // Node fetch uses TLS verification by default. If disabled, the process-level
      // setting below is not altered; configure a trusted certificate for production.
    });
    if (!response.ok) throw new Error(`Wazuh indexer returned HTTP ${response.status}. Check the URL, network access, and indexer credentials.`);
    const payload = await response.json();
    const hits = payload?.hits?.hits;
    if (!Array.isArray(hits)) throw new Error('Wazuh indexer response did not contain hits.hits. Check WAZUH_INDEX_PATTERN.');
    const events = hits.map(hit => ({ ...(hit._source || {}), id: hit._id || hit._source?.id })).map(normalizeEvent).slice(0, 100);
    cached = { events, provider: 'Wazuh Indexer', lastUpdated: new Date().toISOString(), error: null };
    lastFetchAt = Date.now();
    return cached;
  } finally {
    clearTimeout(timeout);
  }
}

async function fetchProviderEvents() {
  if (WAZUH_INDEXER_URL) return fetchWazuhAlerts();
  if (!API_URL) {
    cached = { ...cached, provider: 'Not configured', error: 'Set SECURITY_API_URL in .env to connect a provider.' };
    return cached;
  }
  if (!global.fetch) throw new Error('Node.js 18 or newer is required (built-in fetch is unavailable).');

  const url = new URL(API_URL);
  if (EVENTS_PATH) {
    // Append an optional path to the configured base URL, preserving any base path.
    url.pathname = `${url.pathname.replace(/\/$/, '')}/${EVENTS_PATH.replace(/^\//, '')}`;
  }
  const headers = { Accept: 'application/json' };
  if (API_KEY) {
    const value = `${API_KEY_PREFIX}${AUTH_SCHEME ? AUTH_SCHEME + ' ' : ''}${API_KEY}`;
    headers[AUTH_HEADER] = value;
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), POLL_TIMEOUT_MS);
  try {
    const response = await fetch(url, { method: 'GET', headers, signal: controller.signal });
    if (!response.ok) throw new Error(`Provider returned HTTP ${response.status}`);
    const payload = await response.json();
    const list = findEventArray(payload);
    if (!list) throw new Error('Unrecognized API response. Expected an array or events/alerts/results/data/items array.');
    const events = list.map(normalizeEvent).slice(0, 100);
    cached = { events, provider: url.hostname, lastUpdated: new Date().toISOString(), error: null };
    lastFetchAt = Date.now();
    return cached;
  } finally {
    clearTimeout(timeout);
  }
}

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, providerConfigured: Boolean(WAZUH_INDEXER_URL || API_URL), provider: cached.provider, lastUpdated: cached.lastUpdated, error: cached.error });
});

app.get('/api/security/events', async (_req, res) => {
  try {
    if (Date.now() - lastFetchAt < CACHE_MS && !cached.error) {
      return res.json({ events: cached.events, provider: cached.provider, lastUpdated: cached.lastUpdated, mode: WAZUH_INDEXER_URL ? 'wazuh-indexer' : (API_URL ? 'security-api' : 'not-configured') });
    }
    if (!fetchInFlight) fetchInFlight = fetchProviderEvents().catch(error => {
      cached = { ...cached, error: error.name === 'AbortError' ? 'Provider request timed out.' : error.message };
      throw error;
    }).finally(() => { fetchInFlight = null; });
    const result = await fetchInFlight;
    res.json({ events: result.events, provider: result.provider, lastUpdated: result.lastUpdated, mode: WAZUH_INDEXER_URL ? 'wazuh-indexer' : (API_URL ? 'security-api' : 'not-configured') });
  } catch (error) {
    res.status(502).json({ error: cached.error || error.message, provider: cached.provider, lastUpdated: cached.lastUpdated });
  }
});

app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/')) return next();
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`CyberPulse running at http://localhost:${PORT}`);
  console.log(WAZUH_INDEXER_URL ? `Wazuh Indexer configured: ${new URL(WAZUH_INDEXER_URL).hostname}` : (API_URL ? `Security API configured: ${new URL(API_URL).hostname}` : 'Security API not configured yet. Copy .env.example to .env and fill in provider details.'));
});

const server = require("server");
const fs = require("fs");
const path = require("path");
const net = require("net");

const PLUGIN_VERSION = "0.0.1";
const SCHEMA_VERSION = 5;
const PROVIDER_ID = "net-coffee";
const PROXYCHECK_BASE = "https://proxycheck.io/v3";
const IPAPI_FALLBACK = "https://api.ipapi.is";
const NET_COFFEE_LOOKUP_BASE = "https://ip.net.coffee/api/ip/lookup";
const NET_COFFEE_PING_BASE = "https://ip.net.coffee/api/ping/global";
const LATENCY_NODES = [
  { id: "n02", country_code: "HK", city: "香港", name: "香港" },
  { id: "n03", country_code: "JP", city: "东京", name: "日本" },
  { id: "n04", country_code: "SG", city: "新加坡", name: "新加坡" },
  { id: "n09", country_code: "US", city: "洛杉矶", name: "美西" },
  { id: "n11", country_code: "CA", city: "温哥华", name: "加拿大" },
  { id: "n13", country_code: "DE", city: "法兰克福", name: "德国" },
];
const SIGNAL_KEYS = ["proxy", "tor", "vpn", "datacenter", "abuser", "crawler"];
const CACHE_FILE = path.join(__storageDir__, "cache-v5.json");
const CACHE_TEMP_FILE = CACHE_FILE + ".tmp";
const MAX_LOOKUPS = 500;
const MAX_LATENCIES = 500;
const MAX_LATENCY_FAILURES = 500;
const MAX_BINDINGS = 1000;
const PUBLIC_MISS_LIMIT = 6;
const PUBLIC_MISS_WINDOW_MS = 60 * 1000;
const LATENCY_FAILURE_CACHE_MS = 5 * 60 * 1000;
const CALLER_WINDOW_MAX_ENTRIES = 2048;
const MAX_PROVIDER_BODY_BYTES = 512 * 1024;

let state = createEmptyState();
let inFlight = Object.create(null);
let latencyInFlight = Object.create(null);
let callerWindows = Object.create(null);
let lastCallerWindowPrune = 0;

function createEmptyState() {
  return {
    schema_version: SCHEMA_VERSION,
    lookups: Object.create(null),
    latencies: Object.create(null),
    latency_failures: Object.create(null),
    bindings: Object.create(null),
    usage: { utc_day: utcDay(), count: 0, latency_count: 0 },
  };
}

function utcDay(now) {
  return new Date(now == null ? Date.now() : now).toISOString().slice(0, 10);
}

function loadState() {
  state = createEmptyState();
  if (!fs.existsSync(CACHE_FILE)) return;
  try {
    const parsed = JSON.parse(fs.readFileSync(CACHE_FILE, "utf8"));
    if (!parsed || parsed.schema_version !== SCHEMA_VERSION) return;
    state.lookups = parsed.lookups && typeof parsed.lookups === "object" ? parsed.lookups : Object.create(null);
    state.latencies = parsed.latencies && typeof parsed.latencies === "object" ? parsed.latencies : Object.create(null);
    state.latency_failures = parsed.latency_failures && typeof parsed.latency_failures === "object" ? parsed.latency_failures : Object.create(null);
    state.bindings = parsed.bindings && typeof parsed.bindings === "object" ? parsed.bindings : Object.create(null);
    state.usage = parsed.usage && typeof parsed.usage === "object" ? parsed.usage : { utc_day: utcDay(), count: 0, latency_count: 0 };
    resetUsageDay();
    pruneState();
  } catch (error) {
    console.warn("[ip-info] ignored unreadable cache: " + error.message);
    state = createEmptyState();
  }
}

function saveState() {
  try {
    pruneState();
    fs.writeFileSync(CACHE_TEMP_FILE, JSON.stringify(state), "utf8");
    fs.renameSync(CACHE_TEMP_FILE, CACHE_FILE);
  } catch (error) {
    console.error("[ip-info] failed to save cache: " + error.message);
    try {
      if (fs.existsSync(CACHE_TEMP_FILE)) fs.unlinkSync(CACHE_TEMP_FILE);
    } catch (_) {}
  }
}

function pruneState() {
  pruneObject(state.lookups, MAX_LOOKUPS, function (item) {
    return Date.parse(item && item.fetched_at ? item.fetched_at : 0) || 0;
  });
  pruneObject(state.latencies, MAX_LATENCIES, function (item) {
    return Date.parse(item && item.fetched_at ? item.fetched_at : 0) || 0;
  });
  pruneObject(state.latency_failures, MAX_LATENCY_FAILURES, function (item) {
    return Date.parse(item && item.failed_at ? item.failed_at : 0) || 0;
  });
  pruneObject(state.bindings, MAX_BINDINGS, function (item) {
    return Date.parse(item && item.updated_at ? item.updated_at : 0) || 0;
  });
  Object.keys(state.bindings).forEach(function (key) {
    const binding = state.bindings[key];
    if (!binding || !state.lookups[binding.lookup_key]) delete state.bindings[key];
  });
}

function pruneObject(object, limit, score) {
  const keys = Object.keys(object);
  if (keys.length <= limit) return;
  keys.sort(function (a, b) { return score(object[b]) - score(object[a]); });
  keys.slice(limit).forEach(function (key) { delete object[key]; });
}

function resetUsageDay() {
  const day = utcDay();
  if (!state.usage || state.usage.utc_day !== day) {
    state.usage = { utc_day: day, count: 0, latency_count: 0 };
  }
  if (!Number.isFinite(state.usage.latency_count)) state.usage.latency_count = 0;
}

function numberInRange(value, fallback, min, max) {
  const number = Number(value);
  if (!Number.isFinite(number)) return fallback;
  return Math.min(max, Math.max(min, number));
}

async function getSettings() {
  const config = await server.getConfig();
  return {
    cache_hours: numberInRange(config.cache_hours, 24, 1, 720),
    stale_hours: numberInRange(config.stale_hours, 168, 24, 2160),
    request_timeout_seconds: numberInRange(config.request_timeout_seconds, 5, 2, 8),
    daily_lookup_limit: Math.floor(numberInRange(config.daily_lookup_limit, 45, 1, 100000)),
    latency_cache_minutes: Math.floor(numberInRange(config.latency_cache_minutes, 60, 10, 1440)),
    daily_latency_limit: Math.floor(numberInRange(config.daily_latency_limit, 45, 1, 100000)),
    lazy_lookup: config.lazy_lookup !== false,
  };
}

function cleanInput(req) {
  const query = req && req.query ? req.query : {};
  const uuid = String(query.uuid || "").trim();
  let ip = String(query.ip || "").trim();
  if (ip.charAt(0) === "[" && ip.charAt(ip.length - 1) === "]") ip = ip.slice(1, -1);
  ip = ip.toLowerCase();
  if (!/^[a-zA-Z0-9_-]{1,128}$/.test(uuid)) {
    throw clientError("invalid_uuid", "uuid 参数无效。", 400);
  }
  const family = net.isIP(ip);
  if (!family || !isPublicIP(ip, family)) {
    throw clientError("invalid_ip", "ip 必须是可公开路由的 IPv4 或 IPv6 地址。", 400);
  }
  return { uuid: uuid, ip: ip, family: family };
}

function cleanBody(req) {
  let body;
  try {
    body = JSON.parse(req && req.body ? req.body : "{}");
  } catch (_) {
    throw clientError("invalid_json", "请求体必须是 JSON。", 400);
  }
  const input = cleanInput({ query: { uuid: body.uuid, ip: body.ip } });
  input.force = body.force !== false;
  input.include_latency = body.include_latency === true;
  return input;
}

function isPublicIP(ip, family) {
  if (family === 4) {
    const parts = ip.split(".").map(Number);
    const a = parts[0];
    const b = parts[1];
    if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
    if (a === 100 && b >= 64 && b <= 127) return false;
    if (a === 169 && b === 254) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 0 && parts[2] === 0) return false;
    if (a === 192 && b === 168) return false;
    if (a === 198 && (b === 18 || b === 19)) return false;
    if (a === 198 && b === 51 && parts[2] === 100) return false;
    if (a === 203 && b === 0 && parts[2] === 113) return false;
    return true;
  }
  const lower = ip.toLowerCase();
  if (lower === "::" || lower === "::1") return false;
  if (/^(fc|fd)/.test(lower) || /^fe[89ab]/.test(lower) || /^ff/.test(lower)) return false;
  if (/^2001:0?db8(?::|$)/.test(lower)) return false;
  return true;
}

function clientError(code, message, status) {
  const error = new Error(message);
  error.code = code;
  error.status = status;
  return error;
}

function hasAdminRole(req) {
  const context = req && req.context ? req.context : {};
  const principal = context.principal && typeof context.principal === "object" ? context.principal : {};
  const roles = Array.isArray(principal.roles) ? principal.roles : [];
  return roles.indexOf("admin") !== -1;
}

function bindingKey(input) {
  return input.uuid + "|" + input.family + "|" + input.ip;
}

function lookupKey(input) {
  return input.family + "|" + input.ip;
}

function getLookup(input) {
  return state.lookups[lookupKey(input)] || null;
}

function isFresh(entry, now) {
  return Boolean(entry && Date.parse(entry.expires_at) > now);
}

function isUsableStale(entry, now) {
  return Boolean(entry && Date.parse(entry.stale_until) > now);
}

function bindLookup(input) {
  const key = bindingKey(input);
  const current = state.bindings[key];
  if (current && current.lookup_key === lookupKey(input)) return false;
  state.bindings[key] = {
    uuid: input.uuid,
    family: input.family,
    ip: input.ip,
    lookup_key: lookupKey(input),
    updated_at: new Date().toISOString(),
  };
  return true;
}

function checkPublicMissRate(remoteIP) {
  const key = String(remoteIP || "unknown");
  const now = Date.now();
  if (
    now - lastCallerWindowPrune >= PUBLIC_MISS_WINDOW_MS ||
    Object.keys(callerWindows).length > CALLER_WINDOW_MAX_ENTRIES
  ) {
    Object.keys(callerWindows).forEach(function (callerKey) {
      const callerWindow = callerWindows[callerKey];
      if (!callerWindow || now - callerWindow.started_at >= PUBLIC_MISS_WINDOW_MS) {
        delete callerWindows[callerKey];
      }
    });
    lastCallerWindowPrune = now;
  }
  let window = callerWindows[key];
  if (!window || now - window.started_at >= PUBLIC_MISS_WINDOW_MS) {
    window = { started_at: now, count: 0 };
    callerWindows[key] = window;
  }
  if (window.count >= PUBLIC_MISS_LIMIT) return false;
  window.count += 1;
  return true;
}

function consumeDailyBudget(limit) {
  resetUsageDay();
  if (state.usage.count >= limit) {
    throw clientError("daily_lookup_limit", "插件今日的 IP 检测额度已用完。", 429);
  }
  state.usage.count += 1;
  saveState();
}

function consumeDailyLatencyBudget(limit) {
  resetUsageDay();
  if (state.usage.latency_count >= limit) {
    throw clientError("daily_latency_limit", "插件今日的全球延迟检测额度已用完。", 429);
  }
  state.usage.latency_count += 1;
  saveState();
}

function nullableString(value) {
  if (value == null) return null;
  const text = String(value).trim();
  return text && text.toLowerCase() !== "null" ? text : null;
}

function firstString(values) {
  for (let index = 0; index < values.length; index += 1) {
    const value = nullableString(values[index]);
    if (value) return value;
  }
  return null;
}

function nullableNumber(value) {
  if (value == null || value === "") return null;
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

function booleanValue(value) {
  if (value === true || value === 1 || value === "1") return true;
  if (value === false || value === 0 || value === "0") return false;
  if (typeof value === "string") {
    const normalized = value.trim().toLowerCase();
    if (normalized === "true" || normalized === "yes") return true;
    if (normalized === "false" || normalized === "no") return false;
  }
  return null;
}

function clampScore(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) return null;
  return Math.round(Math.min(100, Math.max(0, number)) * 100) / 100;
}

function scoreLevel(score) {
  if (score == null) return null;
  if (score < 20) return "low";
  if (score < 50) return "medium";
  if (score < 75) return "high";
  return "critical";
}

async function requestJSON(url, settings, options) {
  const controller = new AbortController();
  const timer = setTimeout(function () { controller.abort(); }, settings.request_timeout_seconds * 1000);
  try {
    const response = await fetch(url, {
      method: options && options.method ? options.method : "GET",
      headers: Object.assign({
        "Accept": "application/json",
        "User-Agent": "Komari-IP-Info/" + PLUGIN_VERSION,
      }, options && options.headers ? options.headers : {}),
      body: options && options.body ? options.body : undefined,
      signal: controller.signal,
      redirect: "error",
    });
    const lengthHeader = response.headers && response.headers.get ? Number(response.headers.get("content-length")) : 0;
    if (Number.isFinite(lengthHeader) && lengthHeader > MAX_PROVIDER_BODY_BYTES) {
      throw providerError("provider_response_too_large", "IP data provider response was too large", 502);
    }
    const text = await response.text();
    if (text.length > MAX_PROVIDER_BODY_BYTES) {
      throw providerError("provider_response_too_large", "IP data provider response was too large", 502);
    }
    let data;
    try {
      data = text ? JSON.parse(text) : null;
    } catch (_) {
      throw providerError("provider_invalid_response", "IP data provider returned invalid JSON", 502);
    }
    if (!response.ok || !data || typeof data !== "object" || data.error) {
      const code = response.status === 429 ? "provider_rate_limited" : "provider_error";
      const error = providerError(code, "IP data provider returned HTTP " + response.status, response.status === 429 ? 429 : 502);
      error.retry_after = response.headers && response.headers.get ? response.headers.get("retry-after") : null;
      throw error;
    }
    return data;
  } catch (error) {
    if (error && error.name === "AbortError") {
      throw providerError("provider_timeout", "IP data provider request timed out", 504);
    }
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

function providerError(code, message, status) {
  const error = new Error(message);
  error.code = code;
  error.status = status;
  return error;
}

function emptySignals() {
  return {
    country_code: null,
    proxy: null,
    tor: null,
    vpn: null,
    datacenter: null,
    abuser: null,
    crawler: null,
  };
}

function providerDescriptor(source) {
  if (String(source).indexOf("proxycheck") === 0) {
    return { id: "proxycheck-v3", name: "proxycheck.io v3", homepage: "https://proxycheck.io" };
  }
  if (String(source).indexOf("ipapi.is") === 0) {
    return { id: "ipapi-is", name: "ipapi.is", homepage: "https://ipapi.is" };
  }
  return { id: "net-coffee", name: "Net.Coffee", homepage: "https://ip.net.coffee" };
}

function baseResult(ip, family, source) {
  const provider = providerDescriptor(source);
  return {
    schema_version: SCHEMA_VERSION,
    excluded: false,
    excluded_reason: null,
    address: { value: ip, family: family },
    location: {
      continent: null,
      continent_code: null,
      country: null,
      country_code: null,
      registered_country: null,
      registered_country_code: null,
      region: null,
      region_code: null,
      city: null,
      postal_code: null,
      timezone: null,
      latitude: null,
      longitude: null,
      accuracy_radius: null,
    },
    network: {
      asn: null,
      asn_number: null,
      organization: null,
      operator: null,
      network_type: null,
      company_type: null,
      route: null,
      rir: null,
      domain: null,
      datacenter: null,
    },
    classification: normalizeNativeClassification(null),
    reputation: emptyReputation(),
    capabilities: { media_unlock: false, ai_unlock: false },
    provider: {
      id: provider.id,
      name: provider.name,
      homepage: provider.homepage,
      base_source: source,
      quality_sources: [],
      security_data_available: false,
    },
  };
}

function emptyReputation() {
  return {
    available: false,
    purity_score: null,
    risk_score: null,
    pollution_score: null,
    risk_level: null,
    pollution_level: null,
    positive_signal_count: 0,
    valid_signal_count: 0,
    signals: {
      datacenter: null,
      vpn: null,
      proxy: null,
      tor: null,
      abuser: null,
      crawler: null,
    },
    database_scores: {},
    database_signals: {},
    available_sources: [],
    failed_sources: [],
    method: {
      id: "ip-info-not-exposed-v1",
      status: "unavailable",
    },
  };
}

function parseCompactASN(value) {
  const match = String(value || "").match(/^AS(\d+)\s*(.*)$/i);
  return match ? { number: Number(match[1]), organization: match[2] || null } : { number: null, organization: null };
}

function netCoffeeGeoSource(raw) {
  const sources = Array.isArray(raw && raw.geo_sources) ? raw.geo_sources : [];
  const preferredSource = nullableString(raw && raw.src);
  const preferred = preferredSource
    ? sources.find(function (source) { return nullableString(source && source.src) === preferredSource; })
    : null;
  const hasCoordinates = function (source) {
    return nullableNumber(source && source.lat) != null && nullableNumber(source && source.lon) != null;
  };
  return (preferred && hasCoordinates(preferred) ? preferred : null) ||
    sources.find(hasCoordinates) ||
    preferred ||
    null;
}

function normalizeNetCoffeeResponse(raw, ip, family) {
  if (!raw || typeof raw !== "object" || raw.is_bogon === true) {
    throw providerError("provider_invalid_response", "Net.Coffee returned an invalid or non-public address", 502);
  }
  const result = baseResult(ip, family, "net-coffee");
  const geo = netCoffeeGeoSource(raw);
  const asnNumber = nullableNumber(raw.asn);

  result.location.country = nullableString(raw.country);
  result.location.country_code = normalizedCountryCode(raw.countryCode);
  result.location.registered_country = nullableString(raw.registered_country);
  result.location.registered_country_code = normalizedCountryCode(raw.registered_country_code);
  result.location.region = nullableString(raw.region);
  result.location.city = nullableString(raw.city);
  result.location.latitude = nullableNumber(geo && geo.lat);
  result.location.longitude = nullableNumber(geo && geo.lon);
  result.location.accuracy_radius = nullableNumber(geo && geo.accuracy_km);

  result.network.asn_number = asnNumber;
  result.network.asn = asnNumber == null ? nullableString(raw.asn) : "AS" + Math.trunc(asnNumber);
  result.network.organization = firstString([raw.asOrganization, raw.company_name, raw.isp]);
  result.network.operator = firstString([raw.isp, raw.company_name, raw.asOrganization]);
  result.network.network_type = firstString([raw.asn_kind, raw.company_type]);
  result.network.company_type = nullableString(raw.company_type);
  result.network.route = nullableString(raw.cidr);
  result.network.domain = nullableString(raw.rdns);
  result.network.datacenter = booleanValue(raw.is_datacenter) === true
    ? firstString([raw.datacenter_name, raw.company_name, raw.asOrganization])
    : null;

  result.classification = normalizeNativeClassification(raw);
  result.provider.classification_available = result.classification.type !== "unknown";
  result.provider.rpki_status = nullableString(raw.rpki_status);
  result.provider.response_source = nullableString(raw.src);
  return result;
}

function normalizeIpapiFallback(raw, ip, family) {
  const result = baseResult(ip, family, "ipapi.is-anonymous-fallback");
  const location = raw.location && typeof raw.location === "object" ? raw.location : null;
  const asnObject = raw.asn && typeof raw.asn === "object" ? raw.asn : null;
  const companyObject = raw.company && typeof raw.company === "object" ? raw.company : null;
  const compactASN = typeof raw.asn === "string" ? parseCompactASN(raw.asn) : { number: null, organization: null };
  const asnNumber = asnObject ? nullableNumber(asnObject.asn) : compactASN.number;
  const companyName = companyObject ? nullableString(companyObject.name) : nullableString(raw.company);
  result.location.continent = nullableString(location ? location.continent : raw.continent);
  result.location.country = firstString([location && location.country, raw.country]);
  result.location.country_code = firstString([location && location.country_code, raw.country_code]);
  result.location.region = firstString([location && location.state, raw.region]);
  result.location.city = firstString([location && location.city, raw.city]);
  result.location.timezone = firstString([location && location.timezone, raw.timezone]);
  result.location.latitude = nullableNumber(location ? location.latitude : raw.lat);
  result.location.longitude = nullableNumber(location ? location.longitude : raw.lon);
  result.network.asn_number = asnNumber;
  result.network.asn = asnNumber == null ? null : "AS" + asnNumber;
  result.network.organization = firstString([asnObject && asnObject.org, compactASN.organization, companyName]);
  result.network.operator = result.network.organization || companyName;
  result.network.network_type = firstString([asnObject && asnObject.type, companyObject && companyObject.type]);
  result.network.company_type = nullableString(companyObject && companyObject.type);
  result.network.route = firstString([asnObject && asnObject.route, companyObject && companyObject.network]);
  result.network.rir = firstString([raw.rir, asnObject && asnObject.rir]);
  result.network.domain = firstString([asnObject && asnObject.domain, companyObject && companyObject.domain]);
  result.network.datacenter = raw.datacenter && typeof raw.datacenter === "object" ? nullableString(raw.datacenter.datacenter) : null;
  return result;
}

function proxycheckAddressData(raw, ip) {
  const status = nullableString(raw && raw.status);
  if (status !== "ok" && status !== "warning") {
    throw providerError(status === "denied" ? "provider_rate_limited" : "provider_error", "proxycheck.io returned status " + (status || "unknown"), status === "denied" ? 429 : 502);
  }
  if (raw[ip] && typeof raw[ip] === "object") return raw[ip];
  const addressKeys = Object.keys(raw).filter(function (key) { return net.isIP(key) > 0; });
  if (addressKeys.length === 1 && raw[addressKeys[0]] && typeof raw[addressKeys[0]] === "object") return raw[addressKeys[0]];
  throw providerError("provider_invalid_response", "proxycheck.io response did not contain the requested address", 502);
}

function buildProxycheckReputation(detections, countryCode) {
  const source = detections && typeof detections === "object" ? detections : {};
  const riskScore = clampScore(source.risk);
  const signals = {
    country_code: nullableString(countryCode),
    proxy: booleanValue(source.proxy),
    tor: booleanValue(source.tor),
    vpn: booleanValue(source.vpn),
    datacenter: booleanValue(source.hosting),
    abuser: booleanValue(source.compromised),
    crawler: booleanValue(source.scraper),
  };
  let positiveSignalCount = 0;
  let validSignalCount = 0;
  SIGNAL_KEYS.forEach(function (key) {
    const value = signals[key];
    if (value === true || value === false) {
      validSignalCount += 1;
      if (value) positiveSignalCount += 1;
    }
  });
  const pollutionScore = validSignalCount ? Math.round((positiveSignalCount / validSignalCount) * 10000) / 100 : null;
  const qualityAvailable = riskScore != null || validSignalCount > 0;

  return {
    available: qualityAvailable,
    purity_score: riskScore == null ? null : Math.round((100 - riskScore) * 100) / 100,
    risk_score: riskScore,
    pollution_score: pollutionScore,
    risk_level: scoreLevel(riskScore),
    pollution_level: scoreLevel(pollutionScore),
    positive_signal_count: positiveSignalCount,
    valid_signal_count: validSignalCount,
    signals: signals,
    database_scores: { proxycheck: riskScore },
    database_signals: { proxycheck: qualityAvailable ? signals : null },
    available_sources: qualityAvailable ? ["proxycheck"] : [],
    failed_sources: qualityAvailable ? [] : ["proxycheck"],
    method: {
      id: "proxycheck-v3-risk-v1",
      status: riskScore == null && validSignalCount === 0 ? "signals_unavailable" : "calculated",
      risk: "proxycheck_risk_score",
      pollution: "positive_signals_divided_by_valid_signals",
      confidence: clampScore(source.confidence),
    },
  };
}

function normalizeProxycheckResponse(raw, ip, family, source) {
  const payload = proxycheckAddressData(raw, ip);
  const location = payload.location && typeof payload.location === "object" ? payload.location : {};
  const network = payload.network && typeof payload.network === "object" ? payload.network : {};
  const operator = payload.operator && typeof payload.operator === "object" ? payload.operator : {};
  const result = baseResult(ip, family, source || "proxycheck-v3-fallback");
  const compactASN = parseCompactASN(network.asn);

  result.location.continent = nullableString(location.continent_name);
  result.location.continent_code = nullableString(location.continent_code);
  result.location.country = nullableString(location.country_name);
  result.location.country_code = nullableString(location.country_code);
  result.location.region = nullableString(location.region_name);
  result.location.region_code = nullableString(location.region_code);
  result.location.city = nullableString(location.city_name);
  result.location.postal_code = nullableString(location.postal_code);
  result.location.timezone = nullableString(location.timezone);
  result.location.latitude = nullableNumber(location.latitude);
  result.location.longitude = nullableNumber(location.longitude);

  result.network.asn = nullableString(network.asn);
  result.network.asn_number = compactASN.number;
  result.network.organization = firstString([network.organisation, network.organization, network.provider]);
  result.network.operator = firstString([operator.name, network.provider, result.network.organization]);
  result.network.network_type = nullableString(network.type);
  result.network.company_type = nullableString(network.type);
  result.network.route = nullableString(network.range);
  result.network.domain = nullableString(network.hostname);
  result.network.datacenter = booleanValue(payload.detections && payload.detections.hosting) === true
    ? firstString([operator.name, network.provider])
    : null;

  result.reputation = buildProxycheckReputation(payload.detections, result.location.country_code);
  result.provider.quality_sources = result.reputation.available_sources.slice();
  result.provider.security_data_available = result.reputation.available;
  result.provider.response_status = nullableString(raw.status);
  result.provider.last_updated = nullableString(payload.last_updated);
  return result;
}

async function requestIpapiFallback(ip, family, settings, netCoffeeError, proxycheckError) {
  try {
    const raw = await requestJSON(IPAPI_FALLBACK, settings, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ q: ip }),
    });
    const result = normalizeIpapiFallback(raw, ip, family);
    result.provider.primary_warning = netCoffeeError && netCoffeeError.code ? netCoffeeError.code : "net_coffee_unavailable";
    result.provider.secondary_warning = proxycheckError && proxycheckError.code ? proxycheckError.code : "proxycheck_unavailable";
    result.reputation.database_scores = { proxycheck: null };
    result.reputation.database_signals = { proxycheck: null };
    result.reputation.failed_sources = ["proxycheck"];
    return result;
  } catch (fallbackError) {
    fallbackError.primary_error = netCoffeeError && netCoffeeError.code ? netCoffeeError.code : "net_coffee_unavailable";
    fallbackError.secondary_error = proxycheckError && proxycheckError.code ? proxycheckError.code : "proxycheck_unavailable";
    throw fallbackError;
  }
}

function mainlandChinaResult(base) {
  const result = baseResult(base.address.value, base.address.family, base.provider.base_source);
  result.excluded = true;
  result.excluded_reason = "mainland_china";
  result.location.country = base.location.country;
  result.location.country_code = "CN";
  result.location.registered_country = base.location.registered_country;
  result.location.registered_country_code = base.location.registered_country_code;
  result.classification = base.classification;
  result.provider = Object.assign({}, base.provider);
  result.reputation.method = { id: "excluded-mainland-china-v1", status: "excluded" };
  return result;
}

async function requestProvider(ip, family, settings) {
  consumeDailyBudget(settings.daily_lookup_limit);
  let base;
  try {
    const raw = await requestJSON(NET_COFFEE_LOOKUP_BASE + "/" + encodeURIComponent(ip), settings);
    base = normalizeNetCoffeeResponse(raw, ip, family);
  } catch (netCoffeeError) {
    try {
      const raw = await requestJSON(PROXYCHECK_BASE + "/" + encodeURIComponent(ip) + "?p=0", settings);
      base = normalizeProxycheckResponse(raw, ip, family, "proxycheck-v3-fallback");
      base.provider.primary_warning = netCoffeeError && netCoffeeError.code ? netCoffeeError.code : "net_coffee_unavailable";
    } catch (proxycheckError) {
      base = await requestIpapiFallback(ip, family, settings, netCoffeeError, proxycheckError);
    }
  }
  const countryCode = String(base.location.country_code || "").toUpperCase();
  if (countryCode === "CN") return mainlandChinaResult(base);
  if (!countryCode) {
    base.reputation.method.status = "country_unknown";
    base.provider.country_warning = "country_unknown";
  }
  return base;
}

function normalizedCountryCode(value) {
  const code = String(value || "").trim().toUpperCase();
  if (code === "UK") return "GB";
  return /^[A-Z]{2}$/.test(code) ? code : null;
}

function normalizeNativeClassification(raw) {
  const geolocatedCode = normalizedCountryCode(raw && (raw.countryCode || raw.country_code));
  const registeredCode = normalizedCountryCode(raw && raw.registered_country_code);
  const verdict = nullableString(raw && raw.ai_verdict && raw.ai_verdict.label);
  const confidence = clampScore(raw && raw.ai_verdict && raw.ai_verdict.confidence);
  const publicServiceType = nullableString(raw && raw.public_service && raw.public_service.service_type);
  const publicServiceNote = nullableString(raw && raw.public_service && raw.public_service.note);
  let type = "unknown";
  let label = null;
  let source = "unavailable";

  if (
    (verdict && /任播/.test(verdict)) ||
    (publicServiceType && /anycast/i.test(publicServiceType)) ||
    (publicServiceNote && /任播/.test(publicServiceNote))
  ) {
    type = "anycast";
    label = "任播 IP";
    source = "provider_verdict";
  } else if (verdict && /广播/.test(verdict)) {
    type = "broadcast";
    label = registeredCode ? "广播 IP (" + registeredCode + ")" : "广播 IP";
    source = "provider_verdict";
  } else if (verdict && /原生/.test(verdict)) {
    type = "native";
    label = "原生 IP";
    source = "provider_verdict";
  } else if (geolocatedCode && registeredCode) {
    type = geolocatedCode === registeredCode ? "native" : "broadcast";
    label = type === "native" ? "原生 IP" : "广播 IP (" + registeredCode + ")";
    source = "country_comparison";
  }

  return {
    type: type,
    label: label,
    geolocated_country_code: geolocatedCode,
    registered_country_code: registeredCode,
    confidence: confidence,
    source: source,
  };
}

function normalizeLatencyResponse(raw) {
  const results = raw && raw.results && typeof raw.results === "object" ? raw.results : {};
  const timeouts = Array.isArray(raw && raw.timeouts) ? raw.timeouts.map(String) : [];
  const nodes = LATENCY_NODES.map(function (node) {
    const numeric = nullableNumber(results[node.id]);
    const latency = numeric != null && numeric >= 0 && numeric <= 60000 ? Math.round(numeric) : null;
    return {
      id: node.id,
      name: node.name,
      city: node.city,
      country_code: node.country_code,
      latency_ms: latency,
      status: latency != null ? "ok" : (timeouts.indexOf(node.id) !== -1 ? "timeout" : "unavailable"),
    };
  });
  return {
    nodes: nodes,
    available_count: nodes.filter(function (node) { return node.status === "ok"; }).length,
    timeout_count: nodes.filter(function (node) { return node.status === "timeout"; }).length,
    provider_cached: raw && raw.cached === true,
  };
}

async function requestNetworkProfile(ip, family, settings, sourceData) {
  consumeDailyLatencyBudget(settings.daily_latency_limit);
  const extendedSettings = Object.assign({}, settings, { request_timeout_seconds: 20 });
  const nodeQuery = LATENCY_NODES.map(function (node) { return "node=" + encodeURIComponent(node.id); }).join("&");
  let classification = sourceData && sourceData.classification && typeof sourceData.classification === "object"
    ? sourceData.classification
    : normalizeNativeClassification(null);
  let classificationWarning = null;
  const hasNetCoffeeBase = Boolean(
    sourceData && sourceData.provider && sourceData.provider.base_source === "net-coffee"
  );

  if (!hasNetCoffeeBase) {
    try {
      const lookupRaw = await requestJSON(NET_COFFEE_LOOKUP_BASE + "/" + encodeURIComponent(ip), extendedSettings);
      const checkedCountry = normalizedCountryCode(lookupRaw && (lookupRaw.countryCode || lookupRaw.country_code));
      if (checkedCountry === "CN") {
        throw clientError("mainland_china_excluded", "中国大陆 IP 不执行全球延迟检测。", 404);
      }
      classification = normalizeNativeClassification(lookupRaw);
    } catch (error) {
      if (error && error.code === "mainland_china_excluded") throw error;
      classificationWarning = error && error.code ? error.code : "classification_provider_unavailable";
    }
  }

  const latencyRaw = await requestJSON(
    NET_COFFEE_PING_BASE + "?host=" + encodeURIComponent(ip) + "&" + nodeQuery,
    extendedSettings
  );
  const latency = normalizeLatencyResponse(latencyRaw);
  return {
    schema_version: SCHEMA_VERSION,
    address: { value: ip, family: family },
    classification: classification,
    latency: latency,
    provider: {
      id: "net-coffee",
      name: "Net.Coffee",
      homepage: "https://ip.net.coffee",
      classification_available: classification.type !== "unknown",
      latency_available: latency.available_count > 0,
      classification_warning: classificationWarning,
    },
  };
}

function getLatency(input) {
  return state.latencies[lookupKey(input)] || null;
}

function getLatencyFailure(input) {
  return state.latency_failures[lookupKey(input)] || null;
}

function activeLatencyFailure(input, now) {
  const failure = getLatencyFailure(input);
  return failure && Date.parse(failure.retry_at) > now ? failure : null;
}

function rememberLatencyFailure(input, error) {
  const failedAt = Date.now();
  state.latency_failures[lookupKey(input)] = {
    code: error && error.code ? error.code : "latency_provider_unavailable",
    status: error && error.status ? error.status : 502,
    failed_at: new Date(failedAt).toISOString(),
    retry_at: new Date(failedAt + LATENCY_FAILURE_CACHE_MS).toISOString(),
  };
  saveState();
}

function latencyFailureError(failure) {
  return clientError(
    failure && failure.code ? failure.code : "latency_provider_unavailable",
    "全球延迟检测服务暂时不可用。",
    failure && failure.status ? failure.status : 502
  );
}

async function fetchAndStoreLatency(input, settings, sourceLookup) {
  const key = lookupKey(input);
  if (!latencyInFlight[key]) {
    latencyInFlight[key] = (async function () {
      const normalized = await requestNetworkProfile(input.ip, input.family, settings, sourceLookup && sourceLookup.data);
      const fetchedAt = Date.now();
      const cacheMs = normalized.provider.latency_available
        ? settings.latency_cache_minutes * 60 * 1000
        : LATENCY_FAILURE_CACHE_MS;
      const entry = {
        data: normalized,
        fetched_at: new Date(fetchedAt).toISOString(),
        expires_at: new Date(fetchedAt + cacheMs).toISOString(),
        stale_until: new Date(fetchedAt + Math.max(24 * 60 * 60 * 1000, cacheMs * 4)).toISOString(),
      };
      state.latencies[key] = entry;
      delete state.latency_failures[key];
      saveState();
      return entry;
    })();
  }
  try {
    return await latencyInFlight[key];
  } finally {
    delete latencyInFlight[key];
  }
}

async function resolveLatency(input, settings, sourceLookup, options) {
  const now = Date.now();
  const cached = getLatency(input);
  const force = Boolean(options && options.force);
  if (!force && isFresh(cached, now)) return { entry: cached, cache: "hit", warning: null };
  const recentFailure = force ? null : activeLatencyFailure(input, now);
  if (recentFailure) {
    if (isUsableStale(cached, now)) {
      return { entry: cached, cache: "stale", warning: recentFailure.code };
    }
    throw latencyFailureError(recentFailure);
  }
  try {
    const entry = await fetchAndStoreLatency(input, settings, sourceLookup);
    return { entry: entry, cache: cached ? "refresh" : "miss", warning: null };
  } catch (error) {
    rememberLatencyFailure(input, error);
    if (isUsableStale(cached, now)) {
      return { entry: cached, cache: "stale", warning: error.code || "latency_provider_unavailable" };
    }
    throw error;
  }
}

async function fetchAndStore(input, settings) {
  const key = lookupKey(input);
  if (!inFlight[key]) {
    inFlight[key] = (async function () {
      const normalized = await requestProvider(input.ip, input.family, settings);
      const fetchedAt = Date.now();
      const entry = {
        data: normalized,
        fetched_at: new Date(fetchedAt).toISOString(),
        expires_at: new Date(fetchedAt + settings.cache_hours * 60 * 60 * 1000).toISOString(),
        stale_until: new Date(fetchedAt + settings.stale_hours * 60 * 60 * 1000).toISOString(),
      };
      state.lookups[key] = entry;
      saveState();
      return entry;
    })();
  }
  try {
    return await inFlight[key];
  } finally {
    delete inFlight[key];
  }
}

async function resolveLookup(input, settings, options) {
  const now = Date.now();
  const cached = getLookup(input);
  if (!options.force && isFresh(cached, now)) {
    return { entry: cached, cache: "hit", warning: null };
  }
  if (!options.allow_network) {
    if (cached) return { entry: cached, cache: "stale", warning: "refresh_required" };
    throw clientError("cache_miss", "当前 IP 尚无缓存，请由管理员刷新。", 404);
  }
  try {
    const entry = await fetchAndStore(input, settings);
    return { entry: entry, cache: cached ? "refresh" : "miss", warning: null };
  } catch (error) {
    if (isUsableStale(cached, now)) {
      return { entry: cached, cache: "stale", warning: error.code || "provider_unavailable" };
    }
    throw error;
  }
}

function publicPayload(input, resolved) {
  const data = Object.assign({ uuid: input.uuid }, resolved.entry.data);
  return {
    ok: true,
    data: data,
    meta: {
      cache: resolved.cache,
      stale: resolved.cache === "stale",
      updated_at: resolved.entry.fetched_at,
      expires_at: resolved.entry.expires_at,
      stale_until: resolved.entry.stale_until,
      warning: resolved.warning,
    },
  };
}

function sendJSON(res, status, payload, cacheControl) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Cache-Control", cacheControl || "no-store");
  res.end(JSON.stringify(payload));
}

function sendError(res, error, admin) {
  const status = error && error.status ? error.status : 502;
  const code = error && error.code ? error.code : "provider_unavailable";
  const publicMessages = {
    provider_unavailable: "IP 数据服务暂时不可用。",
    provider_error: "IP 数据服务暂时不可用。",
    provider_invalid_response: "IP 数据服务返回了无效数据。",
    provider_response_too_large: "IP 数据服务返回的数据异常。",
    provider_timeout: "IP 数据服务响应超时。",
    provider_rate_limited: "IP 数据服务请求过于频繁。",
    latency_provider_unavailable: "全球延迟检测服务暂时不可用。",
    daily_latency_limit: "今日的全球延迟检测额度已用完。",
  };
  const message = admin ? String(error && error.message ? error.message : "Unknown error") : (publicMessages[code] || String(error.message || "请求失败。"));
  const payload = { ok: false, error: { code: code, message: message } };
  if (admin && error && error.retry_after) payload.error.retry_after = error.retry_after;
  sendJSON(res, status, payload);
}

async function handlePublicLookup(req, res) {
  if (!hasAdminRole(req)) {
    sendJSON(res, 403, { ok: false, error: { code: "forbidden", message: "登录后才能查看 IP 信息。" } });
    return;
  }
  try {
    const input = cleanInput(req);
    const settings = await getSettings();
    const cached = getLookup(input);
    const needsNetwork = !isFresh(cached, Date.now()) && settings.lazy_lookup;
    if (needsNetwork && !checkPublicMissRate(req.context && req.context.remote_ip)) {
      if (isUsableStale(cached, Date.now())) {
        sendJSON(res, 200, publicPayload(input, { entry: cached, cache: "stale", warning: "caller_rate_limited" }), "private, no-store");
        return;
      }
      throw clientError("caller_rate_limited", "请求过于频繁，请稍后再试。", 429);
    }
    const resolved = await resolveLookup(input, settings, { force: false, allow_network: settings.lazy_lookup });
    if (bindLookup(input)) saveState();
    sendJSON(res, 200, publicPayload(input, resolved), "private, no-store");
  } catch (error) {
    console.warn("[ip-info] public lookup failed: " + (error && error.message ? error.message : error));
    sendError(res, error, false);
  }
}

async function handlePublicLatency(req, res) {
  if (!hasAdminRole(req)) {
    sendJSON(res, 403, { ok: false, error: { code: "forbidden", message: "登录后才能查看 IP 信息。" } });
    return;
  }
  try {
    const input = cleanInput(req);
    const sourceLookup = getLookup(input);
    const sourceBinding = state.bindings[bindingKey(input)];
    if (!sourceLookup || !sourceBinding || sourceBinding.lookup_key !== lookupKey(input)) {
      throw clientError("profile_required", "请先完成此节点的 IP 信息查询。", 404);
    }
    if (sourceLookup.data.excluded || String(sourceLookup.data.location.country_code || "").toUpperCase() === "CN") {
      throw clientError("mainland_china_excluded", "中国大陆 IP 不执行全球延迟检测。", 404);
    }
    const settings = await getSettings();
    const cached = getLatency(input);
    const now = Date.now();
    if (!isFresh(cached, now) && !settings.lazy_lookup) {
      if (cached) {
        sendJSON(res, 200, publicPayload(input, { entry: cached, cache: "stale", warning: "refresh_required" }), "private, no-store");
        return;
      }
      throw clientError("cache_miss", "当前 IP 尚无全球延迟缓存。", 404);
    }
    if (!isFresh(cached, now) && !checkPublicMissRate(req.context && req.context.remote_ip)) {
      if (isUsableStale(cached, now)) {
        sendJSON(res, 200, publicPayload(input, { entry: cached, cache: "stale", warning: "caller_rate_limited" }), "private, no-store");
        return;
      }
      throw clientError("caller_rate_limited", "请求过于频繁，请稍后再试。", 429);
    }
    const resolved = await resolveLatency(input, settings, sourceLookup);
    sendJSON(res, 200, publicPayload(input, resolved), "private, no-store");
  } catch (error) {
    console.warn("[ip-info] public latency lookup failed: " + (error && error.message ? error.message : error));
    sendError(res, error, false);
  }
}

async function handleAdminRefresh(req, res) {
  if (!hasAdminRole(req)) {
    sendJSON(res, 403, { ok: false, error: { code: "forbidden", message: "仅管理员可以刷新 IP 信息。" } });
    return;
  }
  try {
    const input = cleanBody(req);
    const settings = await getSettings();
    const resolved = await resolveLookup(input, settings, { force: input.force, allow_network: true });
    if (bindLookup(input)) saveState();
    let latencyResolved = null;
    let latencyWarning = null;
    if (
      input.include_latency &&
      !resolved.entry.data.excluded &&
      String(resolved.entry.data.location.country_code || "").toUpperCase() !== "CN"
    ) {
      try {
        latencyResolved = await resolveLatency(input, settings, resolved.entry, { force: true });
      } catch (latencyError) {
        latencyWarning = latencyError && latencyError.code
          ? latencyError.code
          : "latency_provider_unavailable";
      }
    }
    const payload = publicPayload(input, resolved);
    payload.meta.latency_warning = latencyWarning;
    if (latencyResolved) payload.related = { latency: publicPayload(input, latencyResolved) };
    sendJSON(res, 200, payload);
  } catch (error) {
    console.warn("[ip-info] admin refresh failed: " + (error && error.message ? error.message : error));
    sendError(res, error, true);
  }
}

async function handleAdminStatus(req, res) {
  if (!hasAdminRole(req)) {
    sendJSON(res, 403, { ok: false, error: { code: "forbidden", message: "仅管理员可以查看插件状态。" } });
    return;
  }
  try {
    const settings = await getSettings();
    resetUsageDay();
    sendJSON(res, 200, {
      ok: true,
      data: {
        version: PLUGIN_VERSION,
        provider: PROVIDER_ID,
        lazy_lookup: settings.lazy_lookup,
        cache_hours: settings.cache_hours,
        stale_hours: settings.stale_hours,
        daily_lookup_limit: settings.daily_lookup_limit,
        latency_cache_minutes: settings.latency_cache_minutes,
        daily_latency_limit: settings.daily_latency_limit,
        usage: state.usage,
        cached_addresses: Object.keys(state.lookups).length,
        cached_latency_addresses: Object.keys(state.latencies).length,
        cached_latency_failures: Object.keys(state.latency_failures).length,
        bindings: Object.keys(state.bindings).length,
      },
    });
  } catch (error) {
    sendError(res, error, true);
  }
}

function handlePublicStatus(req, res) {
  if (!hasAdminRole(req)) {
    sendJSON(res, 403, { ok: false, error: { code: "forbidden", message: "登录后才能查看 IP 信息。" } });
    return;
  }
  sendJSON(res, 200, {
    ok: true,
    data: {
      available: true,
      version: PLUGIN_VERSION,
      schema_version: SCHEMA_VERSION,
      mainland_china_excluded: true,
      capabilities: {
        geo: true,
        network: true,
        reputation: false,
        native_classification: true,
        global_latency: true,
        media_unlock: false,
        ai_unlock: false,
      },
    },
  }, "private, no-store");
}

function load() {
  loadState();
  server.route("GET", "/api/public/ip-info/v1/status", handlePublicStatus);
  server.route("GET", "/api/public/ip-info/v1/lookup", handlePublicLookup);
  server.route("GET", "/api/public/ip-info/v1/latency", handlePublicLatency);
  server.route("POST", "/api/admin/ip-info/v1/refresh", handleAdminRefresh);
  server.route("GET", "/api/admin/ip-info/v1/status", handleAdminStatus);
  console.info("[ip-info] routes registered");
}

function unload() {
  saveState();
  inFlight = Object.create(null);
  latencyInFlight = Object.create(null);
  callerWindows = Object.create(null);
}

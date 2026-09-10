const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const net = require("net");
const vm = require("vm");

const projectRoot = path.resolve(__dirname, "..");
const manifest = JSON.parse(fs.readFileSync(path.join(projectRoot, "komari-plugin.json"), "utf8"));
const source = fs.readFileSync(path.join(projectRoot, "script.js"), "utf8");
const storageDir = fs.mkdtempSync(path.join(os.tmpdir(), "komari-ip-info-test-"));
const routes = Object.create(null);
const requests = [];

function response(status, data) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get() { return null; } },
    async text() { return JSON.stringify(data); },
  };
}

function proxycheck(ip, countryCode, country, overrides) {
  const details = overrides || {};
  return {
    status: "ok",
    [ip]: {
      network: {
        asn: countryCode === "CN" ? "AS4134" : "AS15169",
        range: countryCode === "CN" ? "1.2.0.0/16" : "8.8.8.0/24",
        hostname: countryCode === "CN" ? null : "dns.google",
        provider: countryCode === "CN" ? "China Telecom" : "Google LLC",
        organisation: countryCode === "CN" ? "China Telecom" : "Level 3",
        type: countryCode === "CN" ? "Business" : "Hosting",
      },
      location: {
        continent_name: countryCode === "CN" ? "Asia" : "North America",
        continent_code: countryCode === "CN" ? "AS" : "NA",
        country_name: country,
        country_code: countryCode,
        region_name: countryCode === "CN" ? "Beijing" : "California",
        region_code: countryCode === "CN" ? "BJ" : "CA",
        city_name: countryCode === "CN" ? "Beijing" : "Mountain View",
        postal_code: "94043",
        latitude: 37.4,
        longitude: -122.1,
        timezone: countryCode === "CN" ? "Asia/Shanghai" : "America/Los_Angeles",
      },
      detections: {
        proxy: false,
        vpn: details.vpn === true,
        compromised: false,
        scraper: details.scraper === true,
        tor: false,
        hosting: countryCode !== "CN",
        anonymous: details.vpn === true,
        risk: details.risk == null ? 33 : details.risk,
        confidence: 98,
      },
      operator: null,
      last_updated: "2026-09-10T00:00:00Z",
    },
    query_time: 5,
  };
}

const serverMock = {
  route(method, routePath, handler) { routes[method + " " + routePath] = handler; },
  async getConfig() {
    return {
      cache_hours: 24,
      stale_hours: 168,
      request_timeout_seconds: 5,
      daily_lookup_limit: 45,
      latency_cache_minutes: 60,
      daily_latency_limit: 45,
      lazy_lookup: true,
    };
  },
};

const context = {
  require(name) {
    if (name === "server") return serverMock;
    if (name === "fs") return fs;
    if (name === "path") return path;
    if (name === "net") return net;
    throw new Error("Unexpected module: " + name);
  },
  __storageDir__: storageDir,
  console,
  AbortController,
  URL,
  setTimeout,
  clearTimeout,
  fetch: async function (url, options) {
    requests.push({ url, options });
    if (url === "https://api.ipapi.is") {
      const body = JSON.parse(options.body);
      assert.strictEqual(body.q, "9.9.9.9");
      assert.strictEqual(Object.prototype.hasOwnProperty.call(body, "key"), false);
      return response(200, {
        ip: body.q,
        company: "Quad9",
        asn: "AS19281 Quad9",
        city: "Zurich",
        region: "Zurich",
        country: "Switzerland",
        country_code: "CH",
        timezone: "Europe/Zurich",
      });
    }

    if (url.startsWith("https://ip.net.coffee/api/ip/lookup/")) {
      const ip = decodeURIComponent(url.slice("https://ip.net.coffee/api/ip/lookup/".length));
      if (ip === "9.9.9.9" || ip === "4.4.4.4") return response(503, { error: "temporary" });
      return response(200, {
        ip: ip,
        cidr: ip === "1.2.3.4" ? "1.2.0.0/16" : "8.8.8.0/24",
        is_bogon: false,
        is_datacenter: true,
        company_type: "hosting",
        company_name: ip === "1.2.3.4" ? "China Telecom" : "Google LLC",
        asn: ip === "1.2.3.4" ? 4134 : 15169,
        asOrganization: ip === "1.2.3.4" ? "China Telecom" : "Google LLC",
        country: ip === "1.2.3.4" ? "China" : "Germany",
        countryCode: ip === "1.2.3.4" ? "cn" : "de",
        registered_country: ip === "1.2.3.4" ? "China" : "United Kingdom",
        registered_country_code: ip === "1.2.3.4" ? "cn" : "gb",
        region: ip === "1.2.3.4" ? "Beijing" : "Hesse",
        city: ip === "1.2.3.4" ? "Beijing" : "Frankfurt",
        rdns: ip === "1.2.3.4" ? null : "dns.google",
        asn_kind: "hosting",
        isp: ip === "1.2.3.4" ? "China Telecom" : "Google",
        ai_verdict: {
          label: ip === "1.2.3.4" ? "原生 IP" : "广播 IP (GB)",
          confidence: 96,
        },
        geo_sources: [{ src: "g1", lat: 50.1, lon: 8.6, accuracy_km: 20 }],
        src: "g1",
        rpki_status: "valid",
      });
    }

    if (url.startsWith("https://ip.net.coffee/api/ping/global?")) {
      const parsedPing = new URL(url);
      const host = parsedPing.searchParams.get("host");
      if (host === "7.7.7.7") return response(503, { error: "temporary" });
      assert.strictEqual(host, "8.8.8.8");
      assert.deepStrictEqual(plain(parsedPing.searchParams.getAll("node")), ["n02", "n03", "n04", "n09", "n11", "n13"]);
      return response(200, {
        cached: false,
        results: { n02: 19, n03: 32, n04: 55, n09: 129, n11: 140 },
        timeouts: ["n13"],
      });
    }

    const parsed = new URL(url);
    const ip = decodeURIComponent(parsed.pathname.slice("/v3/".length));
    assert.strictEqual(parsed.origin + "/v3", "https://proxycheck.io/v3");
    assert.strictEqual(parsed.searchParams.get("p"), "0");
    if (ip === "9.9.9.9") return response(503, { status: "denied" });
    return response(200, proxycheck(ip, "US", "United States", { risk: 34, vpn: true }));
  },
};
context.globalThis = context;

function responseRecorder() {
  return {
    statusCode: 200,
    headers: {},
    body: "",
    setHeader(name, value) { this.headers[name] = value; },
    end(value) { this.body += value || ""; },
  };
}

function plain(value) {
  return JSON.parse(JSON.stringify(value));
}

try {
  const expose = "\n;globalThis.__test = { isPublicIP, parseCompactASN, normalizeIpapiFallback, normalizeNetCoffeeResponse, proxycheckAddressData, buildProxycheckReputation, normalizeProxycheckResponse, requestIpapiFallback, normalizeNativeClassification, normalizeLatencyResponse, hasAdminRole };";
  vm.runInNewContext(source + expose, context, { filename: "script.js" });
  vm.runInNewContext("load()", context);
  const helpers = context.__test;

  assert.strictEqual(manifest.short, "ip-info");
  assert.strictEqual(manifest.version, "0.0.1");
  assert.strictEqual(manifest.author, "shanyang");
  assert.strictEqual(manifest.permissions.node, true);
  assert.strictEqual(manifest.permissions.allowRoutes, true);
  assert.strictEqual(manifest.configuration.data.some((item) => item.key === "api_key"), false);
  ["allowSystemRPC", "allowExec", "allowHooks", "allowHTMLInject", "allowListen", "allowAllFileAccess"].forEach(function (permission) {
    assert.notStrictEqual(manifest.permissions[permission], true, permission + " must not be enabled");
  });

  assert.strictEqual(helpers.isPublicIP("8.8.8.8", 4), true);
  assert.strictEqual(helpers.isPublicIP("10.0.0.1", 4), false);
  assert.strictEqual(helpers.isPublicIP("198.51.100.1", 4), false);
  assert.strictEqual(helpers.isPublicIP("2001:4860:4860::8888", 6), true);
  assert.strictEqual(helpers.isPublicIP("fd00::1", 6), false);
  assert.deepStrictEqual(plain(helpers.parseCompactASN("AS15169 Google LLC")), { number: 15169, organization: "Google LLC" });

  const normalizedNetCoffee = helpers.normalizeNetCoffeeResponse({
    ip: "8.8.8.8",
    cidr: "8.8.8.0/24",
    is_bogon: false,
    is_datacenter: true,
    company_type: "hosting",
    company_name: "Google LLC",
    asn: 15169,
    asOrganization: "Google LLC",
    country: "Germany",
    countryCode: "de",
    registered_country: "United Kingdom",
    registered_country_code: "gb",
    region: "Hesse",
    city: "Frankfurt",
    rdns: "dns.google",
    isp: "Google",
    ai_verdict: { label: "广播 IP (GB)", confidence: 96 },
    geo_sources: [
      { src: "g1", lat: null, lon: null },
      { src: "g2", lat: 50.1, lon: 8.6, accuracy_km: 20 },
    ],
    src: "g1",
  }, "8.8.8.8", 4);
  assert.strictEqual(normalizedNetCoffee.provider.base_source, "net-coffee");
  assert.strictEqual(normalizedNetCoffee.location.country_code, "DE");
  assert.strictEqual(normalizedNetCoffee.location.registered_country_code, "GB");
  assert.strictEqual(normalizedNetCoffee.network.asn, "AS15169");
  assert.strictEqual(normalizedNetCoffee.network.route, "8.8.8.0/24");
  assert.strictEqual(normalizedNetCoffee.classification.type, "broadcast");
  assert.strictEqual(normalizedNetCoffee.location.latitude, 50.1);
  assert.strictEqual(normalizedNetCoffee.location.longitude, 8.6);

  const normalizedBase = helpers.normalizeProxycheckResponse(proxycheck("8.8.8.8", "US", "United States", { risk: 34, vpn: true }), "8.8.8.8", 4);
  assert.strictEqual(normalizedBase.address.family, 4);
  assert.strictEqual(normalizedBase.network.asn, "AS15169");
  assert.strictEqual(normalizedBase.location.region, "California");
  assert.strictEqual(normalizedBase.network.route, "8.8.8.0/24");
  assert.strictEqual(normalizedBase.network.network_type, "Hosting");
  assert.strictEqual(normalizedBase.reputation.risk_score, 34);
  assert.strictEqual(normalizedBase.reputation.purity_score, 66);
  assert.strictEqual(normalizedBase.reputation.positive_signal_count, 2);
  assert.strictEqual(normalizedBase.reputation.valid_signal_count, 6);
  assert.strictEqual(normalizedBase.reputation.pollution_score, 33.33);
  assert.deepStrictEqual(plain(normalizedBase.reputation.available_sources), ["proxycheck"]);

  const native = helpers.normalizeNativeClassification({ countryCode: "DE", registered_country_code: "DE" });
  assert.strictEqual(native.type, "native");
  assert.strictEqual(native.label, "原生 IP");
  const broadcast = helpers.normalizeNativeClassification({
    countryCode: "DE",
    registered_country_code: "GB",
    ai_verdict: { label: "广播 IP (GB)", confidence: 96 },
  });
  assert.strictEqual(broadcast.type, "broadcast");
  assert.strictEqual(broadcast.label, "广播 IP (GB)");
  assert.strictEqual(broadcast.confidence, 96);

  assert.strictEqual(helpers.hasAdminRole({ context: { principal: { roles: ["admin"] } } }), true);
  assert.strictEqual(helpers.hasAdminRole({ context: { principal: { roles: ["guest"] }, role: "admin" } }), false);
  assert.ok(routes["GET /api/public/ip-info/v1/lookup"]);
  assert.ok(routes["GET /api/public/ip-info/v1/status"]);
  assert.ok(routes["GET /api/public/ip-info/v1/latency"]);
  assert.ok(routes["POST /api/admin/ip-info/v1/refresh"]);
  assert.ok(routes["GET /api/admin/ip-info/v1/status"]);

  (async function () {
    const settings = await serverMock.getConfig();
    const fallbackRequestCount = requests.length;
    const fallback = await helpers.requestIpapiFallback(
      "9.9.9.9",
      4,
      settings,
      { code: "provider_timeout" },
      { code: "provider_rate_limited" }
    );
    assert.strictEqual(fallback.provider.base_source, "ipapi.is-anonymous-fallback");
    assert.strictEqual(fallback.location.country_code, "CH");
    assert.strictEqual(fallback.provider.primary_warning, "provider_timeout");
    assert.strictEqual(fallback.provider.secondary_warning, "provider_rate_limited");
    assert.deepStrictEqual(plain(fallback.reputation.failed_sources), ["proxycheck"]);
    assert.strictEqual(requests.length - fallbackRequestCount, 1, "fallback helper must make one request");

    const lookup = routes["GET /api/public/ip-info/v1/lookup"];
    const latency = routes["GET /api/public/ip-info/v1/latency"];
    const cnStart = requests.length;
    const cnResponse = responseRecorder();
    await lookup({ query: { uuid: "node-cn", ip: "1.2.3.4" }, context: { remote_ip: "192.0.2.1" } }, cnResponse);
    assert.strictEqual(cnResponse.statusCode, 200);
    const cnPayload = JSON.parse(cnResponse.body);
    assert.strictEqual(cnPayload.data.excluded, true);
    assert.strictEqual(cnPayload.data.excluded_reason, "mainland_china");
    assert.strictEqual(requests.length - cnStart, 1, "CN lookup must stop after the single provider response");
    const cnLatencyResponse = responseRecorder();
    await latency({ query: { uuid: "node-cn", ip: "1.2.3.4" }, context: { remote_ip: "192.0.2.1" } }, cnLatencyResponse);
    assert.strictEqual(cnLatencyResponse.statusCode, 404);
    assert.strictEqual(requests.length - cnStart, 1, "CN lookup must never trigger global latency providers");

    const foreignStart = requests.length;
    const request = { query: { uuid: "node-us", ip: "8.8.8.8" }, context: { remote_ip: "192.0.2.2" } };
    const first = responseRecorder();
    await lookup(request, first);
    assert.strictEqual(first.statusCode, 200);
    const firstPayload = JSON.parse(first.body);
    assert.strictEqual(firstPayload.meta.cache, "miss");
    assert.strictEqual(firstPayload.data.provider.base_source, "net-coffee");
    assert.strictEqual(firstPayload.data.location.country_code, "DE");
    assert.strictEqual(firstPayload.data.classification.type, "broadcast");
    assert.strictEqual(firstPayload.data.classification.label, "广播 IP (GB)");
    assert.strictEqual(requests.length - foreignStart, 1, "non-CN lookup must call one provider endpoint");

    const second = responseRecorder();
    await lookup(request, second);
    assert.strictEqual(second.statusCode, 200);
    assert.strictEqual(JSON.parse(second.body).meta.cache, "hit");
    assert.strictEqual(requests.length - foreignStart, 1, "fresh cache must prevent duplicate provider requests");

    const latencyStart = requests.length;
    const latencyResponse = responseRecorder();
    await latency(request, latencyResponse);
    assert.strictEqual(latencyResponse.statusCode, 200);
    const latencyPayload = JSON.parse(latencyResponse.body);
    assert.strictEqual(latencyPayload.meta.cache, "miss");
    assert.strictEqual(latencyPayload.data.classification.type, "broadcast");
    assert.strictEqual(latencyPayload.data.classification.label, "广播 IP (GB)");
    assert.strictEqual(latencyPayload.data.latency.nodes.length, 6);
    assert.strictEqual(latencyPayload.data.latency.available_count, 5);
    assert.strictEqual(latencyPayload.data.latency.timeout_count, 1);
    assert.strictEqual(latencyPayload.data.latency.nodes[0].id, "n02");
    assert.strictEqual(latencyPayload.data.latency.nodes[0].city, "香港");
    assert.strictEqual(latencyPayload.data.latency.nodes[0].latency_ms, 19);
    assert.strictEqual(requests.length - latencyStart, 1, "network profile must reuse cached classification and only request global latency");

    const cachedLatencyResponse = responseRecorder();
    await latency(request, cachedLatencyResponse);
    assert.strictEqual(cachedLatencyResponse.statusCode, 200);
    assert.strictEqual(JSON.parse(cachedLatencyResponse.body).meta.cache, "hit");
    assert.strictEqual(requests.length - latencyStart, 1, "fresh latency cache must prevent duplicate provider requests");

    const fallbackStart = requests.length;
    const fallbackLookupResponse = responseRecorder();
    await lookup(
      { query: { uuid: "node-fallback", ip: "4.4.4.4" }, context: { remote_ip: "192.0.2.3" } },
      fallbackLookupResponse
    );
    assert.strictEqual(fallbackLookupResponse.statusCode, 200);
    const fallbackPayload = JSON.parse(fallbackLookupResponse.body);
    assert.strictEqual(fallbackPayload.data.provider.base_source, "proxycheck-v3-fallback");
    assert.strictEqual(fallbackPayload.data.provider.primary_warning, "provider_error");
    assert.strictEqual(requests.length - fallbackStart, 2, "proxycheck must only run after Net.Coffee fails");

    const failedProfileRequest = {
      query: { uuid: "node-failure", ip: "7.7.7.7" },
      context: { remote_ip: "192.0.2.4" },
    };
    const failedLookupResponse = responseRecorder();
    await lookup(failedProfileRequest, failedLookupResponse);
    assert.strictEqual(failedLookupResponse.statusCode, 200);
    const failedLatencyStart = requests.length;
    const failedLatencyResponse = responseRecorder();
    await latency(failedProfileRequest, failedLatencyResponse);
    assert.strictEqual(failedLatencyResponse.statusCode, 502);
    assert.strictEqual(requests.length - failedLatencyStart, 1);
    const repeatedFailureResponse = responseRecorder();
    await latency(failedProfileRequest, repeatedFailureResponse);
    assert.strictEqual(repeatedFailureResponse.statusCode, 502);
    assert.strictEqual(requests.length - failedLatencyStart, 1, "recent latency failures must be cached briefly");

    const refresh = routes["POST /api/admin/ip-info/v1/refresh"];
    const beforeForbidden = requests.length;
    const forbidden = responseRecorder();
    await refresh({ context: { principal: { roles: ["guest"] } }, body: JSON.stringify({ uuid: "node-us", ip: "8.8.8.8" }) }, forbidden);
    assert.strictEqual(forbidden.statusCode, 403);
    assert.strictEqual(requests.length, beforeForbidden, "unauthorized refresh must not call providers");

    console.log("All Komari IP Info tests passed.");
  })().catch(function (error) {
    console.error(error);
    process.exitCode = 1;
  }).finally(function () {
    fs.rmSync(storageDir, { recursive: true, force: true });
  });
} catch (error) {
  fs.rmSync(storageDir, { recursive: true, force: true });
  throw error;
}

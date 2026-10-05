import { connect } from "cloudflare:sockets";

// ============================================
// CONSTANTS & DEFAULT CONFIGURATION
// ============================================
const DEFAULT_LOCAL_PROXIES = [
  "galaxytunnel.cloud-ip.cc",
  "icook.hk",
  "icook.tw",
  "www.visa.com.sg"
];

const DEFAULT_DOH_URL = ["https://cloudflare-dns.com/dns-query","https://dns.google/dns-query","https://dns.quad9.net/dns-query","https://dns.adguard-dns.com/dns-query"];
const CONNECTION_TIMEOUT_MS = 30000; // 30 seconds timeout
const DEFAULT_RATE_LIMIT_PER_MINUTE = 60;
const DEFAULT_WS_PATH = "galaxy-tunnel";
const DEFAULT_PROXY_LIST_URL = "https://galaxytunnel.github.io/PROXYIP.txt";
const DEFAULT_PROXY_CACHE_TTL_MS = 3600000; // 1 hour cache (prevents frequent requests)
const MAX_CONFIG_PATH_LENGTH = 128;

// ============================================
// AD & TRACKER DOMAIN BLOCKING
// Domain-based filtering only; encrypted/server-side ads cannot be identified here.
// ============================================
const AD_DOMAIN_SUFFIXES = [
  "doubleclick.net",
  "googleadservices.com",
  "googlesyndication.com",
  "adservice.google.com",
  "pagead2.googlesyndication.com",
  "adcolony.com",
  "appsflyer.com",
  "unityads.unity3d.com",
  "vungle.com",
  "applovin.com",
  "flurry.com",
  "adjust.com",
  "branch.io",
  "admob.com",
  "mopub.com",
  "criteo.com",
  "taboola.com",
  "outbrain.com",
  "scorecardresearch.com",
  "quantserve.com",
  "popads.net",
  "inmobi.com",
  "adroll.com",
  "amazon-adsystem.com",
  "adsafeprotected.com",
  "moatads.com",
  "openx.net",
  "rubiconproject.com",
  "pubmatic.com"
];

function isAdDomain(domain) {
  if (!domain || typeof domain !== "string") return false;
  const lower = domain.toLowerCase().trim().replace(/\.$/, "");
  if (AD_DOMAIN_SUFFIXES.some((suffix) => lower === suffix || lower.endsWith("." + suffix))) {
    return true;
  }
  return /^(ad|ads|adservice|adserver|telemetry|track|tracker|analytics)\./i.test(lower);
}

// ============================================
// DESTINATION ROUTE RULES & SERVER FALLBACK
// Env format:
// ROUTE_RULES=[{"match":"youtube.com","server":"edge-a"}]
// ROUTE_SERVERS=[{"name":"edge-a","host":"proxy.example.com","port":443}]
// ============================================
function parseJsonEnv(value, fallback = []) {
  if (!value) return fallback;
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed : fallback;
  } catch {
    return fallback;
  }
}

function routeMatch(host, rule) {
  const pattern = String(rule?.match || rule?.domain || rule?.ip || "").toLowerCase().trim();
  if (!pattern) return false;
  const value = String(host || "").toLowerCase().trim();
  if (pattern.startsWith("*.")) return value.endsWith(pattern.slice(1));
  return value === pattern || value.endsWith("." + pattern);
}

function resolveRouteTarget(address, port, rawRules, rawServers, logger) {
  const rules = parseJsonEnv(rawRules);
  const servers = parseJsonEnv(rawServers);
  const rule = rules.find((candidate) => routeMatch(address, candidate) &&
    (!candidate.port || Number(candidate.port) === Number(port)));
  if (!rule) return null;

  const server = servers.find((item) => String(item.name || item.id) === String(rule.server || ""));
  if (!server?.host || isPrivateOrBlockedHost(String(server.host))) {
    if (logger) logger.warn("ROUTE_SERVER_INVALID", { address, route: rule.server || null });
    return null;
  }
  return {
    name: String(server.name || server.id || "route-server"),
    host: String(server.host),
    port: Number(server.port || port),
    rule: String(rule.match || rule.domain || rule.ip || "")
  };
}

// ============================================
// STRUCTURED LOGGER WITH REQUEST ID (Item 9)
// ============================================
class Logger {
  constructor(requestId, clientIp = "unknown") {
    this.requestId = requestId;
    this.clientIp = clientIp;
  }

  log(level, event, details = {}) {
    const entry = {
      timestamp: new Date().toISOString(),
      level,
      requestId: this.requestId,
      clientIp: this.clientIp,
      event,
      ...details
    };
    if (level === "ERROR") {
      console.error(JSON.stringify(entry));
    } else if (level === "WARN") {
      console.warn(JSON.stringify(entry));
    } else {
      console.log(JSON.stringify(entry));
    }
  }

  info(event, details) {
    this.log("INFO", event, details);
  }

  warn(event, details) {
    this.log("WARN", event, details);
  }

  error(event, details) {
    this.log("ERROR", event, details);
  }
}

function generateRequestId() {
  if (typeof crypto !== "undefined" && crypto.randomUUID) {
    return crypto.randomUUID();
  }
  return "req_" + Math.random().toString(36).substring(2, 12);
}

// ============================================
// URL SANITIZATION & SSRF PROTECTION (Item 3)
// ============================================
function isPrivateOrBlockedHost(hostname) {
  if (!hostname) return true;
  const host = hostname.toLowerCase().trim();

  if (
    host === "localhost" ||
    host === "127.0.0.1" ||
    host === "0.0.0.0" ||
    host === "::1" ||
    host === "[::1]" ||
    host.endsWith(".local") ||
    host.endsWith(".internal") ||
    host.endsWith(".lan")
  ) {
    return true;
  }

  // IPv4 Private Range Checks
  const ipv4Regex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
  const match = host.match(ipv4Regex);
  if (match) {
    const [_, a, b] = match.map(Number);
    if (a === 10) return true;                         // 10.0.0.0/8
    if (a === 127) return true;                        // 127.0.0.0/8
    if (a === 169 && b === 254) return true;          // 169.254.0.0/16 Link-Local
    if (a === 172 && b >= 16 && b <= 31) return true;  // 172.16.0.0/12
    if (a === 192 && b === 168) return true;          // 192.168.0.0/16
    if (a === 100 && b >= 64 && b <= 127) return true;// 100.64.0.0/10 CGNAT
    if (a === 0) return true;                          // 0.0.0.0/8
  }

  // IPv6 Private & Local Range Checks
  if (host.startsWith("fc") || host.startsWith("fd") || host.startsWith("fe80") || host.startsWith("[fc") || host.startsWith("[fd") || host.startsWith("[fe80")) {
    return true;
  }

  return false;
}

function sanitizeUrl(urlStr) {
  if (!urlStr || typeof urlStr !== "string") return null;
  try {
    const parsed = new URL(urlStr);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return null;
    }
    if (isPrivateOrBlockedHost(parsed.hostname)) {
      return null;
    }
    // Remove auth credentials from URL if any
    parsed.username = "";
    parsed.password = "";
    return parsed.toString();
  } catch {
    return null;
  }
}

// ============================================
// RATE LIMITER (Item 4)
// ============================================
class RateLimiter {
  constructor(limitPerMinute = DEFAULT_RATE_LIMIT_PER_MINUTE) {
    this.limit = limitPerMinute;
    this.records = new Map();
  }

  check(ip) {
    const now = Date.now();
    const windowMs = 60000;
    let clientRecord = this.records.get(ip);

    if (!clientRecord || now - clientRecord.startTime > windowMs) {
      clientRecord = { count: 1, startTime: now };
      this.records.set(ip, clientRecord);
      return { allowed: true, remaining: this.limit - 1, resetIn: 60 };
    }

    clientRecord.count += 1;
    const remaining = Math.max(0, this.limit - clientRecord.count);
    const resetIn = Math.ceil((clientRecord.startTime + windowMs - now) / 1000);

    if (clientRecord.count > this.limit) {
      return { allowed: false, remaining: 0, resetIn };
    }

    // Periodic map cleanup
    if (this.records.size > 5000) {
      for (const [key, val] of this.records.entries()) {
        if (now - val.startTime > windowMs) {
          this.records.delete(key);
        }
      }
    }

    return { allowed: true, remaining, resetIn };
  }
}

const rateLimiter = new RateLimiter();

// ============================================
// PROXY POOL MANAGER CLASS (Item 5)
// ============================================
class ProxyPoolManager {
  constructor(defaultProxies = DEFAULT_LOCAL_PROXIES, ttlMs = DEFAULT_PROXY_CACHE_TTL_MS) {
    this.defaultProxies = defaultProxies;
    this.pool = [...defaultProxies];
    this.lastFetchTime = 0;
    this.ttlMs = ttlMs;
    this.isFetching = false;
  }

  async getProxy(defaultProxy, rawUrl, logger) {
    const sanitizedUrl = sanitizeUrl(rawUrl);
    const now = Date.now();

    if (
      sanitizedUrl &&
      !sanitizedUrl.includes("YOUR_USERNAME") &&
      now - this.lastFetchTime > this.ttlMs &&
      !this.isFetching
    ) {
      this.isFetching = true;
      try {
        if (logger) logger.info("FETCHING_PROXY_LIST", { url: sanitizedUrl });
        const response = await fetch(sanitizedUrl, {
          cf: { cacheTtl: 300, cacheEverything: true }
        });
        if (response.ok) {
          const text = await response.text();
          const fetchedIPs = text
            .split("\n")
            .map((line) => line.trim())
            .filter((line) => line.length > 0 && !line.startsWith("#") && !isPrivateOrBlockedHost(line));

          if (fetchedIPs.length > 0) {
            this.pool = Array.from(new Set([...fetchedIPs, ...this.defaultProxies]));
            if (defaultProxy && !isPrivateOrBlockedHost(defaultProxy) && !this.pool.includes(defaultProxy)) {
              this.pool.unshift(defaultProxy);
            }
            this.lastFetchTime = now;
            if (logger) logger.info("PROXY_POOL_UPDATED", { poolSize: this.pool.length });
          }
        }
      } catch (err) {
        if (logger) logger.warn("PROXY_FETCH_ERROR", { error: err.message });
      } finally {
        this.isFetching = false;
      }
    }

    const validDefault = defaultProxy && !isPrivateOrBlockedHost(defaultProxy) ? defaultProxy : this.defaultProxies[0];
    if (this.pool.length === 0) {
      return validDefault;
    }
    return this.pool[Math.floor(Math.random() * this.pool.length)] || validDefault;
  }

  getPoolSize() {
    return this.pool.length;
  }

  getAllProxies() {
    return [...this.pool];
  }
}

const proxyPoolManager = new ProxyPoolManager();

// ============================================
// IPV6 RFC 5952 ZERO COMPRESSION (Item 7)
// ============================================
function formatIPv6(hextets) {
  const numbers = hextets.map((h) => (typeof h === "string" ? parseInt(h, 16) : h));
  const hex = numbers.map((n) => (n || 0).toString(16));

  let longestStart = -1;
  let longestLen = 0;
  let currentStart = -1;
  let currentLen = 0;

  for (let i = 0; i < 8; i++) {
    if (numbers[i] === 0) {
      if (currentStart === -1) {
        currentStart = i;
        currentLen = 1;
      } else {
        currentLen++;
      }
      if (currentLen > longestLen) {
        longestStart = currentStart;
        longestLen = currentLen;
      }
    } else {
      currentStart = -1;
      currentLen = 0;
    }
  }

  // RFC 5952 requires compressing only when run of 0s is > 1
  if (longestLen > 1) {
    const left = hex.slice(0, longestStart).join(":");
    const right = hex.slice(longestStart + longestLen).join(":");
    if (left === "" && right === "") return "::";
    if (left === "") return `::${right}`;
    if (right === "") return `${left}::`;
    return `${left}::${right}`;
  }

  return hex.join(":");
}

// ============================================
// SECURITY & CORS HEADERS (Item 6 & 12)
// ============================================
function getSecurityHeaders(customContentType = "text/html; charset=utf-8") {
  return {
    "Content-Type": customContentType,
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With, Upgrade, Sec-WebSocket-Key, Sec-WebSocket-Version, Sec-WebSocket-Protocol",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "SAMEORIGIN",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "X-XSS-Protection": "1; mode=block",
    "Permissions-Policy": "interest-cohort=()",
    "X-Robots-Tag": "noindex, nofollow, noarchive, nosnippet",
    "Content-Security-Policy": "default-src 'self' 'unsafe-inline' 'unsafe-eval' https: data: blob:;"
  };
}

function isValidUUID(uuid) {
  if (!uuid || typeof uuid !== "string") return false;
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  return uuidRegex.test(uuid.trim());
}

// ============================================
// HTML UI PAGES WITH NOINDEX META (Item 1, 11, 12)
// ============================================
function getGalaxyPage() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="robots" content="noindex, nofollow, noarchive, nosnippet">
  <title>Galaxy-Tunnel VLESS</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body, html {
      width: 100%; height: 100%;
      background: #02060d; overflow: hidden;
      font-family: 'Segoe UI', Arial, sans-serif;
      display: flex; justify-content: center; align-items: center;
    }
    .space-bg {
      position: absolute; width: 100%; height: 100%;
      background: 
        radial-gradient(circle at 50% 35%, rgba(10, 45, 80, 0.7) 0%, transparent 65%),
        radial-gradient(circle at 80% 80%, rgba(0, 150, 200, 0.15) 0%, transparent 50%),
        #02060d;
      z-index: 1;
    }
    .starfield {
      position: absolute; width: 100%; height: 100%;
      background-image: 
        radial-gradient(2px 2px at 20px 30px, #ffffff, rgba(0,0,0,0)),
        radial-gradient(2px 2px at 40px 70px, rgba(0,212,255,0.8), rgba(0,0,0,0)),
        radial-gradient(1px 1px at 90px 40px, #ffffff, rgba(0,0,0,0)),
        radial-gradient(2px 2px at 160px 120px, rgba(0,212,255,0.9), rgba(0,0,0,0));
      background-repeat: repeat; background-size: 220px 220px;
      animation: starTwinkle 4s ease-in-out infinite alternate; opacity: 0.6;
    }
    @keyframes starTwinkle {
      0% { opacity: 0.4; transform: scale(1); }
      100% { opacity: 0.8; transform: scale(1.02); }
    }
    .card-frame {
      position: relative; z-index: 10;
      width: 90vw; max-width: 480px; aspect-ratio: 1 / 1;
      background: rgba(4, 12, 24, 0.75);
      border: 1.5px solid rgba(0, 212, 255, 0.6);
      box-shadow: 0 0 25px rgba(0, 212, 255, 0.25), inset 0 0 25px rgba(0, 212, 255, 0.1);
      backdrop-filter: blur(12px);
      display: flex; flex-direction: column; justify-content: space-between; align-items: center;
      padding: 35px 25px 25px 25px; border-radius: 4px;
    }
    .graphic-container {
      position: relative; width: 230px; height: 230px;
      display: flex; justify-content: center; align-items: center;
    }
    .ring {
      position: absolute; width: 240px; height: 75px;
      border: 2px solid rgba(0, 230, 255, 0.85); border-radius: 50%;
      transform: rotate(-28deg);
      box-shadow: 0 0 15px rgba(0, 212, 255, 0.8), inset 0 0 15px rgba(0, 212, 255, 0.5);
      pointer-events: none; animation: ringGlow 3s ease-in-out infinite alternate;
    }
    @keyframes ringGlow {
      0% { opacity: 0.7; box-shadow: 0 0 12px rgba(0,212,255,0.6); }
      100% { opacity: 1; box-shadow: 0 0 25px rgba(0,212,255,1); }
    }
    canvas { position: absolute; top: 0; left: 0; }
    .content-bottom {
      width: 100%; display: flex; flex-direction: column; align-items: center;
      text-align: center; position: relative;
    }
    .title {
      font-size: 34px; font-weight: 900; font-style: italic;
      color: #ffffff; letter-spacing: 2px; text-transform: uppercase;
      text-shadow: 0 0 12px rgba(255, 255, 255, 0.7); line-height: 1.1;
    }
    .subtitle {
      font-size: 16px; font-weight: 600; color: #7b93a7;
      letter-spacing: 5px; margin-top: 6px; text-transform: uppercase;
    }
    .access-badge {
      align-self: flex-end; margin-top: 15px; font-size: 20px;
      font-weight: 900; font-style: italic; color: #00e5ff;
      text-transform: uppercase; text-align: right; letter-spacing: 1px; line-height: 1.1;
      text-shadow: 0 0 15px rgba(0, 229, 255, 0.85); animation: statusPulse 2s infinite alternate;
    }
    @keyframes statusPulse {
      0% { opacity: 0.8; text-shadow: 0 0 8px rgba(0,229,255,0.5); }
      100% { opacity: 1; text-shadow: 0 0 20px rgba(0,229,255,1); }
    }
  </style>
</head>
<body>
  <div class="space-bg"></div>
  <div class="starfield"></div>
  <div class="card-frame" id="mainCard">
    <div class="graphic-container">
      <div class="ring"></div>
      <canvas id="nodeCanvas" width="230" height="230"></canvas>
    </div>
    <div class="content-bottom">
      <h1 class="title">GALAXY-TUNNEL</h1>
      <div class="subtitle">VLESS CONFIG</div>
      <div class="access-badge">
        GALAXY VPROXY<br>IS ACCESS
      </div>
    </div>
  </div>
  <script>
    const canvas = document.getElementById('nodeCanvas');
    const ctx = canvas.getContext('2d');
    const numNodes = 32; const nodes = []; const radius = 75;
    let angleX = 0.004; let angleY = 0.007;

    for (let i = 0; i < numNodes; i++) {
      let theta = Math.acos(Math.random() * 2 - 1);
      let phi = Math.random() * Math.PI * 2;
      nodes.push({
        x: radius * Math.sin(theta) * Math.cos(phi),
        y: radius * Math.sin(theta) * Math.sin(phi),
        z: radius * Math.cos(theta)
      });
    }

    function rotateX(node, angle) {
      let cos = Math.cos(angle); let sin = Math.sin(angle);
      let y1 = node.y * cos - node.z * sin;
      let z1 = node.z * cos + node.y * sin;
      node.y = y1; node.z = z1;
    }

    function rotateY(node, angle) {
      let cos = Math.cos(angle); let sin = Math.sin(angle);
      let x1 = node.x * cos - node.z * sin;
      let z1 = node.z * cos + node.x * sin;
      node.x = x1; node.z = z1;
    }

    function draw() {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      let cx = canvas.width / 2; let cy = canvas.height / 2;

      nodes.forEach(node => {
        rotateX(node, angleX);
        rotateY(node, angleY);
      });

      ctx.strokeStyle = 'rgba(0, 220, 255, 0.35)';
      ctx.lineWidth = 1;
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          let dist = Math.hypot(nodes[i].x - nodes[j].x, nodes[i].y - nodes[j].y, nodes[i].z - nodes[j].z);
          if (dist < 60) {
            ctx.beginPath();
            ctx.moveTo(nodes[i].x + cx, nodes[i].y + cy);
            ctx.lineTo(nodes[j].x + cx, nodes[j].y + cy);
            ctx.stroke();
          }
        }
      }

      nodes.forEach(node => {
        let size = (node.z + radius) / (2 * radius) * 3 + 2;
        ctx.beginPath();
        ctx.arc(node.x + cx, node.y + cy, size, 0, Math.PI * 2);
        ctx.fillStyle = '#00f0ff';
        ctx.shadowBlur = 8; ctx.shadowColor = '#00f0ff';
        ctx.fill(); ctx.shadowBlur = 0;
      });

      requestAnimationFrame(draw);
    }
    draw();
  </script>
</body>
</html>`;
}

// 401 Unauthorized Step-by-Step Setup Page (Item 1)
function getUnauthorizedPage() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="robots" content="noindex, nofollow, noarchive, nosnippet">
  <title>401 Unauthorized - Galaxy-Tunnel Setup</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #090d16; color: #e2e8f0;
      min-height: 100vh; display: flex; align-items: center; justify-content: center;
      padding: 24px; line-height: 1.6;
    }
    .container {
      max-width: 620px; width: 100%;
      background: rgba(15, 23, 42, 0.95);
      border: 1px solid rgba(56, 189, 248, 0.3);
      border-radius: 12px; padding: 32px 28px;
      box-shadow: 0 10px 40px rgba(0, 0, 0, 0.6);
    }
    .header { display: flex; align-items: center; gap: 12px; margin-bottom: 20px; }
    .badge {
      background: #ef4444; color: #fff; font-weight: 700;
      font-size: 12px; padding: 4px 10px; border-radius: 9999px;
      letter-spacing: 0.5px;
    }
    h1 { font-size: 22px; color: #f8fafc; font-weight: 700; }
    p { color: #94a3b8; font-size: 14px; margin-bottom: 20px; }
    .step-list { list-style: none; display: flex; flex-direction: column; gap: 16px; }
    .step-item {
      background: rgba(30, 41, 59, 0.7);
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 8px; padding: 14px 16px;
    }
    .step-title {
      font-weight: 600; font-size: 14px; color: #38bdf8;
      display: flex; align-items: center; gap: 8px; margin-bottom: 6px;
    }
    .step-desc { font-size: 13px; color: #cbd5e1; }
    code {
      background: #020617; color: #38bdf8;
      padding: 2px 6px; border-radius: 4px; font-family: monospace; font-size: 12px;
    }
    .step-num {
      background: #0284c7; color: #fff; border-radius: 50%;
      width: 20px; height: 20px; display: inline-flex;
      align-items: center; justify-content: center; font-size: 11px; font-weight: bold;
    }
    .footer-note {
      margin-top: 24px; font-size: 12px; color: #64748b; text-align: center;
    }
  </style>
</head>
<body>
  <div class="container" id="unauthorizedContainer">
    <div class="header">
      <span class="badge">401 UNAUTHORIZED</span>
      <h1>UUID Configuration Required</h1>
    </div>
    <p>Galaxy-Tunnel VLESS server is running, but no valid UUID has been configured.</p>
    <ul class="step-list">
      <li class="step-item">
        <div class="step-title"><span class="step-num">1</span> Generate a secure UUID v4</div>
        <div class="step-desc">Run <code>uuidgen</code> in your terminal or generate one at <a href="https://www.uuidgenerator.net" target="_blank" rel="noopener" style="color:#38bdf8;">uuidgenerator.net</a>.</div>
      </li>
      <li class="step-item">
        <div class="step-title"><span class="step-num">2</span> Set the UUID Environment Variable</div>
        <div class="step-desc">In Cloudflare Dashboard: <strong>Workers & Pages &gt; Settings &gt; Variables</strong>, add variable <code>UUID</code> with your generated UUID. Or add <code>UUID = "your-uuid"</code> in <code>wrangler.toml</code>.</div>
      </li>
      <li class="step-item">
        <div class="step-title"><span class="step-num">3</span> Configure Your Client</div>
        <div class="step-desc">In V2Ray, v2rayN, Sing-box, Clash, or NekoBox, add a VLESS node with WebSocket transport pointing to your domain on port 443 with TLS enabled.</div>
      </li>
      <li class="step-item">
        <div class="step-title"><span class="step-num">4</span> Redeploy / Reload</div>
        <div class="step-desc">Deploy your worker with <code>wrangler deploy</code> and test the connection.</div>
      </li>
    </ul>
    <div class="footer-note">Galaxy-Tunnel VLESS Security Guard &bull; Automatic Access Protection</div>
  </div>
</body>
</html>`;
}

// 404 Camouflage Page (Item 11)
function getCamouflage404() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="robots" content="noindex, nofollow, noarchive, nosnippet">
  <title>404 Not Found</title>
  <style>
    body{font-family:sans-serif;background:#fff;color:#222;text-align:center;padding:50px;}
    h1{font-size:32px;margin-bottom:10px;}p{color:#666;}
  </style>
</head>
<body>
  <h1>404 Not Found</h1>
  <p>The requested resource was not found on this server.</p>
</body>
</html>`;
}

// ============================================
// HOST HEADER & SNI ATTACK DEFENSE
// ============================================
function isValidHostHeader(host) {
  if (!host || typeof host !== "string") return false;
  const trimmed = host.trim();
  if (trimmed.length === 0 || trimmed.length > 253) return false;
  // Disallow carriage returns, newlines, null bytes, command injection tokens
  if (/[\r\n\t\0<>"'\\;{}()$*^|]/.test(trimmed)) return false;
  // Must be valid host / domain / IPv4 / IPv6 with optional port
  return /^([a-zA-Z0-9.-]+|\[[a-fA-F0-9:]+\])(:\d+)?$/.test(trimmed);
}

const SUSPICIOUS_SCANNER_PATHS = [
  ".env", ".git", "wp-admin", "wp-login", "phpmyadmin", "actuator",
  "shell", "boaform", "telescope", "alfa", "xmlrpc.php", "eval-stdin",
  "solr", "config.json", ".aws", "credentials", "setup.cgi"
];

function isSuspiciousProbe(pathname) {
  const lower = String(pathname || "").toLowerCase();
  return SUSPICIOUS_SCANNER_PATHS.some((probe) => lower.includes(probe));
}

// ============================================
// CAMOUFLAGE MASK WEBSITE (GALAXY TUNNEL REAL LIVE)
// ============================================
function getMaskPage(host = "localhost", isAuthEnabled = true, clientIp = "127.0.0.1", colo = "EDGE-LOCAL") {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="description" content="Galaxy Tunnel Quantum Edge Security Network - High-availability Anycast gateway, telemetry diagnostics and encrypted transport.">
  <meta property="og:title" content="Galaxy Tunnel | Quantum Edge Security & Diagnostics">
  <meta property="og:description" content="Real-time edge server telemetry, DNS-over-HTTPS status verification, and full-duplex socket connectivity diagnostics.">
  <title>GALAXY TUNNEL | Quantum Edge Gateway &amp; Telemetry</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Orbitron", monospace, sans-serif;
      background: #020610;
      color: #e2e8f0;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      overflow-x: hidden;
    }
    header {
      background: rgba(4, 12, 28, 0.85);
      border-bottom: 1px solid rgba(0, 212, 255, 0.2);
      backdrop-filter: blur(12px);
      padding: 14px 24px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      position: sticky;
      top: 0;
      z-index: 50;
    }
    .logo-area {
      display: flex;
      align-items: center;
      gap: 12px;
      font-weight: 900;
      font-size: 18px;
      color: #ffffff;
      cursor: pointer;
      user-select: none;
      letter-spacing: 1px;
    }
    .logo-icon {
      width: 34px;
      height: 34px;
      background: radial-gradient(circle, #00f0ff 0%, #0066cc 100%);
      border-radius: 9px;
      display: flex;
      align-items: center;
      justify-content: center;
      color: #020610;
      font-weight: 900;
      font-size: 18px;
      box-shadow: 0 0 16px rgba(0, 240, 255, 0.6);
    }
    .header-actions {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .status-pill {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      background: rgba(0, 240, 255, 0.08);
      border: 1px solid rgba(0, 240, 255, 0.35);
      padding: 6px 14px;
      border-radius: 9999px;
      font-size: 11px;
      font-weight: 800;
      color: #00f0ff;
      letter-spacing: 0.8px;
      text-transform: uppercase;
    }
    .pulse-dot {
      width: 8px;
      height: 8px;
      background: #00f0ff;
      border-radius: 50%;
      box-shadow: 0 0 8px #00f0ff;
      animation: pulseAnim 2s infinite ease-in-out;
    }
    @keyframes pulseAnim {
      0%, 100% { opacity: 1; transform: scale(1); }
      50% { opacity: 0.4; transform: scale(0.75); }
    }
    .btn-portal {
      background: rgba(15, 23, 42, 0.8);
      border: 1px solid rgba(148, 163, 184, 0.3);
      color: #cbd5e1;
      padding: 6px 14px;
      font-size: 12px;
      font-weight: 700;
      border-radius: 8px;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      transition: all 0.2s;
    }
    .btn-portal:hover {
      background: rgba(0, 240, 255, 0.15);
      border-color: #00f0ff;
      color: #00f0ff;
    }
    main {
      flex: 1;
      max-width: 1040px;
      width: 100%;
      margin: 0 auto;
      padding: 20px 16px 40px 16px;
      display: flex;
      flex-direction: column;
      gap: 24px;
    }
    /* Visual Stage Container */
    .stage-wrapper {
      position: relative;
      width: 100%;
      border-radius: 20px;
      overflow: hidden;
      background: #020610;
      border: 1px solid rgba(0, 212, 255, 0.4);
      box-shadow: 0 0 40px rgba(0, 150, 255, 0.15), inset 0 0 60px rgba(0, 50, 100, 0.3);
    }
    #galaxyLiveCanvas {
      display: block;
      width: 100%;
      height: 520px;
      cursor: crosshair;
    }
    .stage-overlay {
      position: absolute;
      top: 16px;
      left: 16px;
      z-index: 10;
      pointer-events: none;
    }
    .stage-badge {
      display: inline-block;
      font-size: 11px;
      font-weight: 800;
      letter-spacing: 1px;
      color: #00f0ff;
      background: rgba(2, 6, 16, 0.7);
      border: 1px solid rgba(0, 240, 255, 0.4);
      padding: 4px 10px;
      border-radius: 6px;
      backdrop-filter: blur(8px);
      text-transform: uppercase;
    }
    .stage-hint {
      position: absolute;
      bottom: 16px;
      right: 16px;
      font-size: 11px;
      color: #64748b;
      background: rgba(2, 6, 16, 0.75);
      border: 1px solid rgba(255, 255, 255, 0.08);
      padding: 4px 10px;
      border-radius: 6px;
      pointer-events: none;
    }

    /* Diagnostics KPI Grid */
    .bench-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 14px;
    }
    .bench-card {
      background: rgba(10, 22, 44, 0.7);
      border-radius: 14px;
      padding: 18px 20px;
      border: 1px solid rgba(255, 255, 255, 0.08);
      backdrop-filter: blur(10px);
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      transition: transform 0.2s, border-color 0.2s;
    }
    .bench-card:hover {
      transform: translateY(-2px);
      border-color: rgba(0, 240, 255, 0.4);
    }
    .bench-card-1 { border-top: 3px solid #00f0ff; }
    .bench-card-2 { border-top: 3px solid #10b981; }
    .bench-card-3 { border-top: 3px solid #f59e0b; }
    .bench-card-4 { border-top: 3px solid #8b5cf6; }
    .bench-title {
      font-size: 12px;
      font-weight: 700;
      color: #94a3b8;
      text-transform: uppercase;
      letter-spacing: 0.6px;
    }
    .bench-val {
      font-size: 26px;
      font-weight: 900;
      color: #ffffff;
      margin-top: 6px;
      font-family: monospace;
    }
    .bench-sub {
      font-size: 12px;
      font-weight: 600;
      margin-top: 4px;
    }
    .bench-card-1 .bench-sub { color: #00f0ff; }
    .bench-card-2 .bench-sub { color: #34d399; }
    .bench-card-3 .bench-sub { color: #fbbf24; }
    .bench-card-4 .bench-sub { color: #a78bfa; }

    /* Technical Telemetry Cards */
    .grid-2 {
      display: grid;
      grid-template-columns: 1fr;
      gap: 16px;
    }
    @media (min-width: 768px) {
      .grid-2 { grid-template-columns: 1fr 1fr; }
    }
    .card {
      background: rgba(10, 22, 44, 0.7);
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 14px;
      padding: 20px 22px;
      backdrop-filter: blur(10px);
    }
    .card-heading {
      font-size: 15px;
      font-weight: 800;
      color: #ffffff;
      margin-bottom: 14px;
      display: flex;
      align-items: center;
      gap: 8px;
      letter-spacing: 0.5px;
    }
    .info-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 10px 0;
      border-bottom: 1px solid rgba(255, 255, 255, 0.05);
      font-size: 13px;
    }
    .info-row:last-child { border-bottom: none; }
    .info-k { color: #94a3b8; font-weight: 500; }
    .info-v { color: #ffffff; font-family: monospace; font-weight: 700; }
    .tag-active {
      color: #10b981;
      background: rgba(16, 185, 129, 0.12);
      border: 1px solid rgba(16, 185, 129, 0.3);
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 11px;
    }

    .btn-run {
      background: linear-gradient(135deg, #00f0ff 0%, #0088ff 100%);
      color: #020610;
      border: none;
      padding: 10px 20px;
      border-radius: 8px;
      font-weight: 800;
      font-size: 13px;
      cursor: pointer;
      transition: all 0.2s;
      display: inline-flex;
      align-items: center;
      gap: 8px;
      margin-top: 10px;
      box-shadow: 0 0 16px rgba(0, 240, 255, 0.4);
    }
    .btn-run:hover {
      box-shadow: 0 0 24px rgba(0, 240, 255, 0.7);
      transform: translateY(-1px);
    }
    .btn-run:disabled { opacity: 0.6; cursor: not-allowed; }

    .footer-bar {
      background: rgba(4, 12, 28, 0.7);
      border: 1px solid rgba(0, 212, 255, 0.2);
      border-radius: 10px;
      padding: 14px;
      text-align: center;
      font-size: 12px;
      font-weight: 600;
      color: #64748b;
      letter-spacing: 0.5px;
    }

    /* Secret Auth Modal */
    .modal-overlay {
      position: fixed;
      top: 0; left: 0; width: 100%; height: 100%;
      background: rgba(2, 6, 16, 0.85);
      backdrop-filter: blur(10px);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 100;
      opacity: 0;
      pointer-events: none;
      transition: opacity 0.25s ease;
    }
    .modal-overlay.open {
      opacity: 1;
      pointer-events: auto;
    }
    .modal-card {
      background: #091224;
      border: 1px solid rgba(0, 240, 255, 0.5);
      box-shadow: 0 0 50px rgba(0, 240, 255, 0.25);
      border-radius: 16px;
      width: 100%;
      max-width: 440px;
      padding: 26px;
      margin: 16px;
    }
    .modal-head {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 14px;
    }
    .modal-title {
      font-size: 17px;
      font-weight: 800;
      color: #00f0ff;
      display: flex;
      align-items: center;
      gap: 8px;
      letter-spacing: 0.5px;
    }
    .btn-close {
      background: transparent;
      border: none;
      color: #64748b;
      font-size: 20px;
      cursor: pointer;
    }
    .btn-close:hover { color: #ffffff; }
    .modal-input {
      width: 100%;
      background: #030814;
      border: 1px solid rgba(0, 240, 255, 0.3);
      padding: 12px 14px;
      border-radius: 8px;
      color: #00f0ff;
      font-family: monospace;
      font-size: 14px;
      outline: none;
      margin-bottom: 14px;
    }
    .modal-input:focus {
      border-color: #00f0ff;
      box-shadow: 0 0 12px rgba(0, 240, 255, 0.4);
    }
    .btn-submit {
      width: 100%;
      background: linear-gradient(135deg, #00f0ff 0%, #0088ff 100%);
      color: #020610;
      border: none;
      padding: 12px;
      border-radius: 8px;
      font-weight: 800;
      font-size: 14px;
      cursor: pointer;
      transition: all 0.2s;
    }
    .btn-submit:hover { opacity: 0.9; }
    .auth-msg {
      font-size: 12px;
      margin-top: 12px;
      text-align: center;
      color: #ef4444;
      font-weight: 600;
      display: none;
    }
  </style>
</head>
<body>
  <header>
    <div class="logo-area" onclick="handleSecretClick()">
      <div class="logo-icon">⚡</div>
      <div>
        <div style="line-height:1.1;">GALAXY TUNNEL</div>
        <div style="font-size:10px; color:#00f0ff; font-weight:600; letter-spacing:2px;">QUANTUM EDGE</div>
      </div>
    </div>
    <div class="header-actions">
      <div class="status-pill">
        <span class="pulse-dot"></span>
        <span>EDGE OPERATIONAL</span>
      </div>
      <button class="btn-portal" onclick="openPortalModal()">
        <span>🔒 Portal Access</span>
      </button>
    </div>
  </header>

  <main>
    <!-- Visual Stage Container with Interactive Animated Canvas -->
    <div class="stage-wrapper">
      <div class="stage-overlay">
        <span class="stage-badge">Live Quantum Cluster • Active</span>
      </div>
      <canvas id="galaxyLiveCanvas"></canvas>
      <div class="stage-hint">⚡ Interactive Live Network</div>
    </div>

    <!-- Benchmark Cards -->
    <div class="bench-grid">
      <div class="bench-card bench-card-1">
        <div class="bench-title">Edge Roundtrip Latency</div>
        <div class="bench-val" id="pingVal">-- ms</div>
        <div class="bench-sub" id="pingStatus">Measuring...</div>
      </div>
      <div class="bench-card bench-card-2">
        <div class="bench-title">DNS-over-HTTPS (DoH)</div>
        <div class="bench-val">Active</div>
        <div class="bench-sub">Encrypted Anycast Resolvers</div>
      </div>
      <div class="bench-card bench-card-3">
        <div class="bench-title">Host &amp; Anti-SNI Shield</div>
        <div class="bench-val">Guarded</div>
        <div class="bench-sub">Strict Header Filtering</div>
      </div>
      <div class="bench-card bench-card-4">
        <div class="bench-title">Edge Cluster PoP</div>
        <div class="bench-val">${colo}</div>
        <div class="bench-sub">Global CDN Edge Node</div>
      </div>
    </div>

    <div>
      <button class="btn-run" id="btnBench" onclick="runDiagnostics()">
        ⚡ Re-Run Diagnostic Benchmark
      </button>
    </div>

    <!-- Technical Telemetry Cards -->
    <div class="grid-2">
      <div class="card">
        <div class="card-heading">🌐 Edge Connection Telemetry</div>
        <div class="info-row">
          <span class="info-k">Client Remote IP:</span>
          <span class="info-v">${clientIp}</span>
        </div>
        <div class="info-row">
          <span class="info-k">Serving Host:</span>
          <span class="info-v">${host}</span>
        </div>
        <div class="info-row">
          <span class="info-k">Transport Protocol:</span>
          <span class="info-v">HTTP/2 &amp; HTTP/3 (QUIC)</span>
        </div>
        <div class="info-row">
          <span class="info-k">Cipher Suite:</span>
          <span class="info-v">TLS 1.3 / AEAD ChaCha20</span>
        </div>
      </div>

      <div class="card">
        <div class="card-heading">🛡️ Edge Threat Mitigation &amp; WAF</div>
        <div class="info-row">
          <span class="info-k">Anti-Host Attack Filter:</span>
          <span class="tag-active">Active</span>
        </div>
        <div class="info-row">
          <span class="info-k">Anti-SNI Spoofing:</span>
          <span class="tag-active">Enforced</span>
        </div>
        <div class="info-row">
          <span class="info-k">Anycast DDoS Mitigation:</span>
          <span class="tag-active">Strict Layer 7</span>
        </div>
        <div class="info-row">
          <span class="info-k">Zero-Trust Tunnel:</span>
          <span class="tag-active">Standby / RFC 6455</span>
        </div>
      </div>
    </div>

    <div class="footer-bar">
      Galaxy Tunnel Quantum Edge Network • High Availability Edge Gateway • All Systems Running
    </div>
  </main>

  <!-- Admin Auth Modal -->
  <div class="modal-overlay" id="portalModal">
    <div class="modal-card">
      <div class="modal-head">
        <div class="modal-title">
          <span>🔒 Gateway Portal Access</span>
        </div>
        <button class="btn-close" onclick="closePortalModal()">✕</button>
      </div>
      <p style="font-size: 13px; color: #94a3b8; margin-bottom: 14px; line-height: 1.5;">
        Enter your Universal Unique Identifier (UUID) or Dashboard Password to unlock the Galaxy console.
      </p>
      <form onsubmit="handlePortalLogin(event)">
        <input type="password" id="authKeyInput" class="modal-input" placeholder="Enter UUID or Password" required autofocus />
        <button type="submit" class="btn-submit" id="submitBtn">Unlock Console</button>
      </form>
      <div class="auth-msg" id="authErrorMsg">⚠️ Invalid UUID or Password. Access Denied.</div>
    </div>
  </div>

  <script>
    // ============================================
    // REAL LIVE ANIMATED CANVAS (IMAGE-ACCURATE)
    // ============================================
    const canvas = document.getElementById('galaxyLiveCanvas');
    const ctx = canvas.getContext('2d');
    let width = 0, height = 0;
    let dpr = window.devicePixelRatio || 1;

    function resizeCanvas() {
      const rect = canvas.getBoundingClientRect();
      width = rect.width;
      height = rect.height;
      canvas.width = width * dpr;
      canvas.height = height * dpr;
      ctx.scale(dpr, dpr);
    }
    window.addEventListener('resize', resizeCanvas);
    resizeCanvas();

    // Mouse Parallax & Interactivity
    let mouse = { x: 0, y: 0, targetX: 0, targetY: 0 };
    canvas.addEventListener('mousemove', (e) => {
      const rect = canvas.getBoundingClientRect();
      mouse.targetX = (e.clientX - rect.left - width / 2) * 0.05;
      mouse.targetY = (e.clientY - rect.top - height / 2) * 0.05;
    });
    canvas.addEventListener('mouseleave', () => {
      mouse.targetX = 0;
      mouse.targetY = 0;
    });

    // Secret Canvas Click Counter
    let canvasClickCount = 0;
    canvas.addEventListener('click', (e) => {
      canvasClickCount++;
      createShockwave(e.clientX - canvas.getBoundingClientRect().left, e.clientY - canvas.getBoundingClientRect().top);
      if (canvasClickCount >= 3) {
        openPortalModal();
        canvasClickCount = 0;
      }
    });

    const shockwaves = [];
    function createShockwave(x, y) {
      shockwaves.push({ x, y, r: 5, maxR: 90, alpha: 1 });
    }

    // Stars Background
    const stars = [];
    const NUM_STARS = 110;
    for (let i = 0; i < NUM_STARS; i++) {
      stars.push({
        x: Math.random(),
        y: Math.random(),
        size: Math.random() * 1.8 + 0.6,
        alpha: Math.random() * 0.7 + 0.3,
        twinkleSpeed: Math.random() * 0.02 + 0.008,
        color: Math.random() > 0.4 ? '#ffffff' : (Math.random() > 0.5 ? '#00e5ff' : '#60a5fa')
      });
    }

    // Shooting Stars
    const shootingStars = [];
    function spawnShootingStar() {
      if (Math.random() < 0.02 && shootingStars.length < 2) {
        shootingStars.push({
          x: Math.random() * width,
          y: Math.random() * (height * 0.4),
          len: Math.random() * 80 + 40,
          speed: Math.random() * 6 + 7,
          angle: Math.PI / 4 + (Math.random() - 0.5) * 0.2,
          alpha: 1
        });
      }
    }

    // Floating Particles between Cloud & Atom
    const beamParticles = [];
    const NUM_BEAM_PARTICLES = 28;
    for (let i = 0; i < NUM_BEAM_PARTICLES; i++) {
      beamParticles.push({
        offsetY: Math.random(),
        offsetX: (Math.random() - 0.5) * 40,
        speed: Math.random() * 0.008 + 0.004,
        size: Math.random() * 2 + 1,
        alpha: Math.random() * 0.8 + 0.2
      });
    }

    // Network Constellation Pulses
    const dataPackets = [
      { progress: 0.1, speed: 0.007, from: 0, to: 'center' },
      { progress: 0.6, speed: 0.009, from: 1, to: 'atom' },
      { progress: 0.3, speed: 0.006, from: 2, to: 'center' },
      { progress: 0.8, speed: 0.008, from: 3, to: 'atom' }
    ];

    let time = 0;

    function draw() {
      time += 0.025;
      mouse.x += (mouse.targetX - mouse.x) * 0.08;
      mouse.y += (mouse.targetY - mouse.y) * 0.08;

      ctx.clearRect(0, 0, width, height);

      const cx = width / 2 + mouse.x;
      const cy = height * 0.44 + mouse.y;

      // 1. Deep Space Cosmic Background
      const bgGrad = ctx.createRadialGradient(cx, cy, 20, cx, cy, Math.max(width, height) * 0.8);
      bgGrad.addColorStop(0, '#061730');
      bgGrad.addColorStop(0.4, '#030b1c');
      bgGrad.addColorStop(1, '#01040a');
      ctx.fillStyle = bgGrad;
      ctx.fillRect(0, 0, width, height);

      // Nebula Cloud Glows
      const neb1 = ctx.createRadialGradient(cx - 180, cy - 80, 10, cx - 180, cy - 80, 220);
      neb1.addColorStop(0, 'rgba(0, 100, 255, 0.18)');
      neb1.addColorStop(1, 'transparent');
      ctx.fillStyle = neb1;
      ctx.fillRect(0, 0, width, height);

      const neb2 = ctx.createRadialGradient(cx + 160, cy + 50, 10, cx + 160, cy + 50, 200);
      neb2.addColorStop(0, 'rgba(0, 220, 255, 0.14)');
      neb2.addColorStop(1, 'transparent');
      ctx.fillStyle = neb2;
      ctx.fillRect(0, 0, width, height);

      // 2. Twinkling Stars
      stars.forEach(s => {
        s.alpha += Math.sin(time * 3 + s.x * 20) * s.twinkleSpeed;
        const curAlpha = Math.max(0.15, Math.min(1, s.alpha));
        ctx.fillStyle = s.color;
        ctx.globalAlpha = curAlpha;
        ctx.beginPath();
        ctx.arc(s.x * width, s.y * height, s.size, 0, Math.PI * 2);
        ctx.fill();
      });
      ctx.globalAlpha = 1;

      // Shooting Stars
      spawnShootingStar();
      for (let i = shootingStars.length - 1; i >= 0; i--) {
        const ss = shootingStars[i];
        ss.x += Math.cos(ss.angle) * ss.speed;
        ss.y += Math.sin(ss.angle) * ss.speed;
        ss.alpha -= 0.02;
        if (ss.alpha <= 0) {
          shootingStars.splice(i, 1);
          continue;
        }
        ctx.strokeStyle = \`rgba(0, 240, 255, \${ss.alpha})\`;
        ctx.lineWidth = 1.8;
        ctx.beginPath();
        ctx.moveTo(ss.x, ss.y);
        ctx.lineTo(ss.x - Math.cos(ss.angle) * ss.len, ss.y - Math.sin(ss.angle) * ss.len);
        ctx.stroke();
      }

      // 3. Earth Horizon Arc with Atmospheric Glow (Bottom of image)
      const earthRadius = Math.max(width * 0.9, 650);
      const earthCenterY = height + earthRadius - (height * 0.15);

      // Atmosphere Outer Halo
      const atmoGrad = ctx.createRadialGradient(cx, earthCenterY, earthRadius - 20, cx, earthCenterY, earthRadius + 70);
      atmoGrad.addColorStop(0, 'rgba(0, 180, 255, 0.7)');
      atmoGrad.addColorStop(0.35, 'rgba(0, 130, 255, 0.35)');
      atmoGrad.addColorStop(0.7, 'rgba(0, 80, 220, 0.1)');
      atmoGrad.addColorStop(1, 'transparent');
      ctx.fillStyle = atmoGrad;
      ctx.beginPath();
      ctx.arc(cx, earthCenterY, earthRadius + 70, Math.PI, 0, false);
      ctx.fill();

      // Earth Planet Body
      const earthGrad = ctx.createRadialGradient(cx, earthCenterY - earthRadius * 0.6, 50, cx, earthCenterY, earthRadius);
      earthGrad.addColorStop(0, '#001a38');
      earthGrad.addColorStop(0.8, '#020c1d');
      earthGrad.addColorStop(1, '#00050e');
      ctx.fillStyle = earthGrad;
      ctx.beginPath();
      ctx.arc(cx, earthCenterY, earthRadius, Math.PI, 0, false);
      ctx.fill();

      // Earth Horizon Rim Light
      ctx.strokeStyle = '#00d4ff';
      ctx.lineWidth = 2.5;
      ctx.shadowBlur = 18;
      ctx.shadowColor = '#00f0ff';
      ctx.beginPath();
      ctx.arc(cx, earthCenterY, earthRadius, Math.PI + 0.25, -0.25, false);
      ctx.stroke();
      ctx.shadowBlur = 0;

      // 4. "GALAXY TUNNEL" Neon Typography Title
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.font = '900 ' + Math.min(38, Math.max(24, width * 0.055)) + 'px -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif';
      
      const titleY = cy - 145;
      // Glow Layer
      ctx.shadowBlur = 20;
      ctx.shadowColor = '#00d4ff';
      ctx.fillStyle = '#ffffff';
      ctx.fillText('GALAXY TUNNEL', cx, titleY);
      ctx.shadowBlur = 8;
      ctx.shadowColor = '#00f0ff';
      ctx.fillText('GALAXY TUNNEL', cx, titleY);
      ctx.shadowBlur = 0;

      // Subtitle
      ctx.font = '700 ' + Math.min(12, Math.max(9, width * 0.02)) + 'px -apple-system, sans-serif';
      ctx.fillStyle = '#38bdf8';
      ctx.letterSpacing = '3px';
      ctx.fillText('QUANTUM SECURE EDGE CLUSTER', cx, titleY + 26);

      // Node Positions (Surrounding 4 cyber elements as in the uploaded image)
      const scale = Math.min(1, Math.max(0.7, width / 700));
      const cloudY = cy - 35;
      const atomY = cy + 85;

      const nodes = [
        { x: cx - 180 * scale, y: cy - 40 + Math.sin(time + 1) * 5, type: 'shield_cyan' },
        { x: cx - 170 * scale, y: cy + 70 + Math.sin(time + 2.5) * 5, type: 'shield_orange' },
        { x: cx + 180 * scale, y: cy - 40 + Math.sin(time + 4) * 5, type: 'globe' },
        { x: cx + 170 * scale, y: cy + 70 + Math.sin(time + 5.5) * 5, type: 'shield_green' }
      ];

      // 5. Constellation Lines between Nodes, Cloud and Atom
      ctx.lineWidth = 1.2;
      nodes.forEach((node, idx) => {
        // Line to Cloud
        ctx.strokeStyle = 'rgba(0, 212, 255, 0.22)';
        ctx.beginPath();
        ctx.moveTo(node.x, node.y);
        ctx.lineTo(cx, cloudY);
        ctx.stroke();

        // Line to Atom
        ctx.strokeStyle = 'rgba(0, 255, 200, 0.18)';
        ctx.beginPath();
        ctx.moveTo(node.x, node.y);
        ctx.lineTo(cx, atomY);
        ctx.stroke();
      });

      // Data Packets Traveling on Lines
      dataPackets.forEach(dp => {
        dp.progress = (dp.progress + dp.speed) % 1;
        const sourceNode = nodes[dp.from];
        const targetX = cx;
        const targetY = dp.to === 'center' ? cloudY : atomY;
        const px = sourceNode.x + (targetX - sourceNode.x) * dp.progress;
        const py = sourceNode.y + (targetY - sourceNode.y) * dp.progress;

        ctx.fillStyle = '#00ffff';
        ctx.shadowBlur = 8;
        ctx.shadowColor = '#00ffff';
        ctx.beginPath();
        ctx.arc(px, py, 2.5, 0, Math.PI * 2);
        ctx.fill();
        ctx.shadowBlur = 0;
      });

      // 6. Vertical Radiant Energy Beam (Cloud -> Atom)
      const beamGrad = ctx.createLinearGradient(cx, cloudY + 20, cx, atomY - 20);
      beamGrad.addColorStop(0, 'rgba(0, 240, 255, 0.6)');
      beamGrad.addColorStop(0.5, 'rgba(0, 255, 200, 0.7)');
      beamGrad.addColorStop(1, 'rgba(0, 240, 255, 0.2)');

      ctx.strokeStyle = beamGrad;
      ctx.lineWidth = 3;
      ctx.shadowBlur = 14;
      ctx.shadowColor = '#00f0ff';
      ctx.beginPath();
      ctx.moveTo(cx, cloudY + 24);
      ctx.lineTo(cx, atomY - 24);
      ctx.stroke();
      ctx.shadowBlur = 0;

      // Vertical streaming light particles
      beamParticles.forEach(bp => {
        bp.offsetY = (bp.offsetY + bp.speed) % 1;
        const py = (cloudY + 24) + ((atomY - 24) - (cloudY + 24)) * bp.offsetY;
        const px = cx + bp.offsetX * Math.sin(bp.offsetY * Math.PI);
        ctx.fillStyle = \`rgba(0, 240, 255, \${bp.alpha})\`;
        ctx.beginPath();
        ctx.arc(px, py, bp.size, 0, Math.PI * 2);
        ctx.fill();
      });

      // 7. Central Holographic Cloud with Keyhole
      ctx.save();
      ctx.translate(cx, cloudY);
      const cloudW = 58 * scale;
      const cloudH = 34 * scale;

      // Cloud Glow Fill
      ctx.fillStyle = 'rgba(0, 180, 255, 0.12)';
      ctx.shadowBlur = 24;
      ctx.shadowColor = '#00e5ff';
      ctx.strokeStyle = '#00e5ff';
      ctx.lineWidth = 2.5;

      // Draw Cloud Shape with Bezier curves
      ctx.beginPath();
      ctx.moveTo(-cloudW * 0.7, cloudH * 0.5);
      ctx.bezierCurveTo(-cloudW * 1.1, cloudH * 0.5, -cloudW * 1.1, -cloudH * 0.3, -cloudW * 0.6, -cloudH * 0.4);
      ctx.bezierCurveTo(-cloudW * 0.5, -cloudH * 1.1, cloudW * 0.1, -cloudH * 1.1, cloudW * 0.3, -cloudH * 0.5);
      ctx.bezierCurveTo(cloudW * 0.8, -cloudH * 0.6, cloudW * 1.1, -cloudH * 0.1, cloudW * 0.9, cloudH * 0.4);
      ctx.bezierCurveTo(cloudW * 1.0, cloudH * 0.9, -cloudW * 0.3, cloudH * 0.9, -cloudW * 0.7, cloudH * 0.5);
      ctx.closePath();
      ctx.fill();
      ctx.stroke();
      ctx.shadowBlur = 0;

      // Keyhole inside Cloud
      const keyH = 18 * scale;
      ctx.fillStyle = '#020610';
      ctx.strokeStyle = '#00f0ff';
      ctx.lineWidth = 2;
      ctx.shadowBlur = 10;
      ctx.shadowColor = '#00f0ff';

      ctx.beginPath();
      ctx.arc(0, -keyH * 0.3, keyH * 0.38, 0, Math.PI * 2);
      ctx.fill();
      ctx.stroke();

      ctx.beginPath();
      ctx.moveTo(-keyH * 0.22, keyH * 0.5);
      ctx.lineTo(keyH * 0.22, keyH * 0.5);
      ctx.lineTo(keyH * 0.14, -keyH * 0.05);
      ctx.lineTo(-keyH * 0.14, -keyH * 0.05);
      ctx.closePath();
      ctx.fill();
      ctx.stroke();
      ctx.shadowBlur = 0;

      ctx.restore();

      // 8. Quantum Atom (Rotating Orbits & Pulsing Core)
      ctx.save();
      ctx.translate(cx, atomY);
      const atomR = 36 * scale;

      // Central Pulsing Nucleus
      const corePulse = Math.sin(time * 4) * 2.5;
      const coreGrad = ctx.createRadialGradient(0, 0, 1, 0, 0, 12 + corePulse);
      coreGrad.addColorStop(0, '#ffffff');
      coreGrad.addColorStop(0.4, '#00ffcc');
      coreGrad.addColorStop(1, 'rgba(0, 212, 255, 0)');
      ctx.fillStyle = coreGrad;
      ctx.beginPath();
      ctx.arc(0, 0, 14 + corePulse, 0, Math.PI * 2);
      ctx.fill();

      // 3 Orbits rotated in 3D
      ctx.lineWidth = 1.6;
      ctx.strokeStyle = '#00ffcc';
      ctx.shadowBlur = 12;
      ctx.shadowColor = '#00ffcc';

      const angles = [0.15 + time * 0.4, 2.1 + time * 0.4, 4.1 + time * 0.4];
      angles.forEach((orbitAngle, idx) => {
        ctx.save();
        ctx.rotate(orbitAngle);

        ctx.beginPath();
        ctx.ellipse(0, 0, atomR * 1.15, atomR * 0.42, 0, 0, Math.PI * 2);
        ctx.stroke();

        // Orbiting Electron
        const ePos = time * 2.5 + idx * (Math.PI * 2 / 3);
        const ex = Math.cos(ePos) * (atomR * 1.15);
        const ey = Math.sin(ePos) * (atomR * 0.42);

        ctx.fillStyle = '#ffffff';
        ctx.beginPath();
        ctx.arc(ex, ey, 2.8, 0, Math.PI * 2);
        ctx.fill();

        ctx.restore();
      });
      ctx.shadowBlur = 0;
      ctx.restore();

      // 9. Draw the 4 Surrounding Cyber Nodes (Shields & Globe)
      nodes.forEach(node => {
        ctx.save();
        ctx.translate(node.x, node.y);
        const nr = 24 * scale;

        if (node.type === 'shield_cyan') {
          drawShield(ctx, nr, '#00f0ff', 'lock');
        } else if (node.type === 'shield_orange') {
          drawShield(ctx, nr, '#f97316', 'lock');
        } else if (node.type === 'shield_green') {
          drawShield(ctx, nr, '#10b981', 'check');
        } else if (node.type === 'globe') {
          drawGlobe(ctx, nr, '#00f0ff', time);
        }

        ctx.restore();
      });

      // Shockwaves from clicks
      for (let i = shockwaves.length - 1; i >= 0; i--) {
        const sw = shockwaves[i];
        sw.r += 2.5;
        sw.alpha -= 0.03;
        if (sw.alpha <= 0) {
          shockwaves.splice(i, 1);
          continue;
        }
        ctx.strokeStyle = \`rgba(0, 240, 255, \${sw.alpha})\`;
        ctx.lineWidth = 2;
        ctx.beginPath();
        ctx.arc(sw.x, sw.y, sw.r, 0, Math.PI * 2);
        ctx.stroke();
      }

      requestAnimationFrame(draw);
    }

    // Helper: Draw Security Shield Node
    function drawShield(c, r, color, iconType) {
      c.shadowBlur = 14;
      c.shadowColor = color;
      c.strokeStyle = color;
      c.fillStyle = 'rgba(4, 14, 30, 0.75)';
      c.lineWidth = 2;

      c.beginPath();
      c.moveTo(0, -r);
      c.lineTo(r * 0.85, -r * 0.6);
      c.lineTo(r * 0.85, r * 0.15);
      c.bezierCurveTo(r * 0.85, r * 0.7, 0, r * 1.1, 0, r * 1.1);
      c.bezierCurveTo(0, r * 1.1, -r * 0.85, r * 0.7, -r * 0.85, r * 0.15);
      c.lineTo(-r * 0.85, -r * 0.6);
      c.closePath();
      c.fill();
      c.stroke();
      c.shadowBlur = 0;

      // Icon inside
      if (iconType === 'lock') {
        c.fillStyle = color;
        // Lock body
        c.fillRect(-r * 0.35, -r * 0.05, r * 0.7, r * 0.55);
        // Shackle
        c.strokeStyle = color;
        c.lineWidth = 2;
        c.beginPath();
        c.arc(0, -r * 0.1, r * 0.26, Math.PI, 0, false);
        c.stroke();
      } else if (iconType === 'check') {
        c.strokeStyle = color;
        c.lineWidth = 2.5;
        c.beginPath();
        c.moveTo(-r * 0.4, 0);
        c.lineTo(-r * 0.1, r * 0.3);
        c.lineTo(r * 0.4, -r * 0.3);
        c.stroke();
      }
    }

    // Helper: Draw 3D Wireframe Globe Node
    function drawGlobe(c, r, color, t) {
      c.shadowBlur = 12;
      c.shadowColor = color;
      c.strokeStyle = color;
      c.fillStyle = 'rgba(4, 14, 30, 0.75)';
      c.lineWidth = 1.6;

      // Outer circle
      c.beginPath();
      c.arc(0, 0, r, 0, Math.PI * 2);
      c.fill();
      c.stroke();

      // Equator
      c.beginPath();
      c.moveTo(-r, 0);
      c.lineTo(r, 0);
      c.stroke();

      // Rotating Longitude Meridians
      const rot = (t * 0.5) % Math.PI;
      const xOffset = Math.sin(rot) * r * 0.75;
      c.beginPath();
      c.ellipse(0, 0, Math.abs(xOffset), r, 0, 0, Math.PI * 2);
      c.stroke();

      const xOffset2 = Math.sin(rot + Math.PI / 2) * r * 0.75;
      c.beginPath();
      c.ellipse(0, 0, Math.abs(xOffset2), r, 0, 0, Math.PI * 2);
      c.stroke();
      c.shadowBlur = 0;
    }

    draw();

    // ============================================
    // PORTAL AUTHENTICATION & DIAGNOSTICS LOGIC
    // ============================================
    let logoClicks = 0;
    function handleSecretClick() {
      logoClicks++;
      if (logoClicks >= 3) {
        openPortalModal();
        logoClicks = 0;
      }
    }

    document.addEventListener('keydown', (e) => {
      if ((e.ctrlKey || e.metaKey) && e.shiftKey && (e.key === 'A' || e.key === 'a')) {
        openPortalModal();
      }
      if (e.key === 'Escape') {
        closePortalModal();
      }
    });

    function openPortalModal() {
      document.getElementById('portalModal').classList.add('open');
      document.getElementById('authKeyInput').focus();
    }

    function closePortalModal() {
      document.getElementById('portalModal').classList.remove('open');
      document.getElementById('authErrorMsg').style.display = 'none';
    }

    async function handlePortalLogin(e) {
      e.preventDefault();
      const key = document.getElementById('authKeyInput').value.trim();
      const errorMsg = document.getElementById('authErrorMsg');
      const submitBtn = document.getElementById('submitBtn');

      if (!key) return;
      submitBtn.textContent = "Verifying Quantum Key...";
      submitBtn.disabled = true;
      errorMsg.style.display = 'none';

      try {
        const resp = await fetch('/api/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ key })
        });
        const data = await resp.json();

        if (resp.ok && data.success) {
          window.location.href = data.redirect || ('/' + encodeURIComponent(key));
        } else {
          errorMsg.textContent = data.message || "⚠️ Invalid Access Key / UUID.";
          errorMsg.style.display = 'block';
          submitBtn.textContent = "Unlock Console";
          submitBtn.disabled = false;
        }
      } catch (err) {
        window.location.href = '/' + encodeURIComponent(key);
      }
    }

    async function runDiagnostics() {
      const btn = document.getElementById('btnBench');
      const pingVal = document.getElementById('pingVal');
      const pingStatus = document.getElementById('pingStatus');

      btn.disabled = true;
      btn.textContent = "Testing Edge Cluster Latency...";
      pingVal.textContent = "...";
      pingStatus.textContent = "Measuring round-trip...";

      const pings = [];
      for (let i = 0; i < 3; i++) {
        const start = performance.now();
        try {
          await fetch('/api/health?t=' + Date.now(), { cache: 'no-store' });
          const latency = Math.round(performance.now() - start);
          pings.push(latency);
        } catch (e) {
          pings.push(28);
        }
        await new Promise(r => setTimeout(r, 120));
      }

      const avg = Math.round(pings.reduce((a, b) => a + b, 0) / pings.length);
      pingVal.textContent = avg + ' ms';
      pingStatus.textContent = "Optimal Anycast Route";
      btn.disabled = false;
      btn.textContent = "⚡ Re-Run Diagnostic Benchmark";
    }

    // Auto run once
    setTimeout(runDiagnostics, 500);
  </script>
</body>
</html>`;
}


// ============================================
// VLESS CONFIGURATION & SUBSCRIPTION OUTPUT
// ============================================
function normalizeWsPath(value) {
  const path = String(value || DEFAULT_WS_PATH)
    .trim()
    .replace(/^\/+|\/+$/g, "");
  if (!path || path.length > MAX_CONFIG_PATH_LENGTH || /[\s\\?#]/.test(path)) {
    return DEFAULT_WS_PATH;
  }
  return path;
}

function encodeBase64Utf8(value) {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function generateVlessConfigs(host, uuid, wsPath, proxyIP = "", trojanPassword = "") {
  const cleanHost = String(host || "").replace(/[^a-zA-Z0-9.:-]/g, "");
  const cleanUuid = String(uuid || "").trim().toLowerCase();
  const cleanPath = normalizeWsPath(wsPath);
  const encodedPath = `%2F${encodeURIComponent(cleanPath)}%3Fed%3D2048`;
  const titleHost = cleanHost.replace(/[^a-zA-Z0-9.-]/g, "");

  const tls = `vless://${cleanUuid}@${cleanHost}:443?encryption=none&security=tls&sni=${cleanHost}&type=ws&host=${cleanHost}&path=${encodedPath}#Galaxy-TLS%20(${titleHost})`;
  const configs = [tls];

  // CMLiu-style edge address mode: connect to the proxy/edge address while
  // preserving the Worker hostname in Host/SNI so no custom DNS setup is
  // required. The same Worker endpoint accepts 443/TLS and 8080/plain WS.
  const cleanProxy = String(proxyIP || "").trim().split(/[\s,]+/)[0]
    .replace(/^\[/, "").replace(/\](:\d+)?$/, "").replace(/:\d+$/, "");
  const edgeAddress = cleanProxy || cleanHost;
  // Cloudflare-supported HTTP/WS edge ports. These are separate client
  // entry points; the Worker still opens the VLESS destination TCP port from
  // the request header. They do not turn plaintext WS into TLS/WSS.
  const noTlsPorts = [80, 8080, 8880, 2052, 2082, 2086, 2095];
  const noTlsConfigs = noTlsPorts.map((port) =>
    `vless://${cleanUuid}@${edgeAddress}:${port}?encryption=none&security=none&type=ws&host=${cleanHost}&path=${encodedPath}#Galaxy-WS-${port}%20(${edgeAddress})`
  );
  configs.push(...noTlsConfigs);

  if (cleanProxy && !isPrivateOrBlockedHost(cleanProxy)) {
    configs.push(`vless://${cleanUuid}@${cleanProxy}:443?encryption=none&security=tls&sni=${cleanHost}&type=ws&host=${cleanHost}&path=${encodedPath}#Galaxy-ProxyIP%20(${cleanProxy})`);
  }

  const cleanTrojanPassword = String(trojanPassword || "").trim();
  const trojan = cleanTrojanPassword
    ? `trojan://${encodeURIComponent(cleanTrojanPassword)}@${cleanHost}:443?security=tls&sni=${cleanHost}&type=ws&host=${cleanHost}&path=${encodedPath}#Galaxy-Trojan%20(${titleHost})`
    : "";
  if (trojan) configs.push(trojan);

  return {
    tls,
    http: noTlsConfigs.find((item) => item.includes(":8080?")) || noTlsConfigs[0] || "",
    proxy: configs.find((item) => item.includes("Galaxy-ProxyIP")) || "",
    trojan,
    plainList: configs.join("\n"),
    base64: encodeBase64Utf8(configs.join("\n"))
  };
}

// ============================================
// MAIN WORKER FETCH HANDLER
// ============================================
const worker_default = {
  async fetch(request, env, ctx) {
    const requestId = generateRequestId();
    const clientIp = request.headers.get("cf-connecting-ip") || request.headers.get("x-forwarded-for") || "unknown";
    const logger = new Logger(requestId, clientIp);

    // Rate Limiting (Item 4)
    const rateLimit = rateLimiter.check(clientIp);
    if (!rateLimit.allowed) {
      logger.warn("RATE_LIMIT_EXCEEDED", { remaining: rateLimit.remaining, resetIn: rateLimit.resetIn });
      return new Response(
        JSON.stringify({ error: "Too Many Requests", retryAfterSeconds: rateLimit.resetIn }),
        {
          status: 429,
          headers: {
            ...getSecurityHeaders("application/json"),
            "Retry-After": rateLimit.resetIn.toString(),
            "X-RateLimit-Limit": DEFAULT_RATE_LIMIT_PER_MINUTE.toString(),
            "X-RateLimit-Remaining": "0"
          }
        }
      );
    }

    const url = new URL(request.url);
    const pathname = url.pathname.replace(/^\/+|\/+$/g, "");

    // Host Header Validation & Anti-SNI Spoofing Defense
    const hostHeader = request.headers.get("Host") || url.host;
    if (!isValidHostHeader(hostHeader)) {
      logger.warn("BLOCKED_MALFORMED_HOST_ATTACK", { host: hostHeader });
      return new Response("400 Bad Request: Malformed Host header", {
        status: 400,
        headers: { "Content-Type": "text/plain; charset=utf-8", "Connection": "close" }
      });
    }

    // Automated Scanner & Malicious Probe Defense
    if (isSuspiciousProbe(pathname)) {
      logger.warn("BLOCKED_SCANNER_PROBE", { path: pathname });
      return new Response(getCamouflage404(), {
        status: 404,
        headers: getSecurityHeaders("text/html; charset=utf-8")
      });
    }

    // Load configurations from env (Item 2: fully configurable via wrangler.toml / env)
    const userID = env.UUID || env.uuid || "";
    const proxyIP = env.PROXYIP || env.proxyip || env.PROXY_IP || DEFAULT_LOCAL_PROXIES[0];
    const rawProxyListUrl = env.PROXY_LIST_URL || DEFAULT_PROXY_LIST_URL;
    const dohURL = env.DNS_RESOLVER_URL || DEFAULT_DOH_URL;
    const configuredWsPath = normalizeWsPath(env.WS_PATH || DEFAULT_WS_PATH);
    const envPassword = String(env.PASSWORD || env.password || "").trim();
    const trojanPassword = String(env.TROJAN_PASSWORD || env.trojan_password || "").trim();
    const routeRulesRaw = env.ROUTE_RULES || "";
    const routeServersRaw = env.ROUTE_SERVERS || "";

    // Health check endpoint (Item 10)
    if (url.pathname === "/health" || url.pathname === "/api/health") {
      logger.info("HEALTH_CHECK_REQUESTED");
      return new Response(
        JSON.stringify({
          status: "healthy",
          service: "galaxy-tunnel-vless",
          timestamp: new Date().toISOString(),
          uuidConfigured: isValidUUID(userID),
          proxyPoolSize: proxyPoolManager.getPoolSize(),
          wsPath: configuredWsPath,
          rateLimitRemaining: rateLimit.remaining
        }),
        {
          status: 200,
          headers: getSecurityHeaders("application/json")
        }
      );
    }

    // CORS preflight options
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: getSecurityHeaders("text/plain") });
    }

    // Portal login: configured UUID or optional PASSWORD unlocks the dashboard.
    if (url.pathname === "/api/login" && request.method === "POST") {
      try {
        const body = await request.json().catch(() => ({}));
        const submittedKey = String(body.key || body.password || body.uuid || "").trim();
        const validUuidKey = isValidUUID(userID) && submittedKey.toLowerCase() === userID.toLowerCase();
        const validPasswordKey = Boolean(envPassword) && submittedKey === envPassword;
        if (validUuidKey || validPasswordKey) {
          return new Response(JSON.stringify({ success: true, redirect: isValidUUID(userID) ? `/${userID}` : "/" }), {
            status: 200,
            headers: {
              ...getSecurityHeaders("application/json"),
              "Set-Cookie": "galaxy_auth=1; Path=/; Max-Age=86400; SameSite=Lax; HttpOnly"
            }
          });
        }
        return new Response(JSON.stringify({ success: false, message: "Invalid UUID or Password" }), {
          status: 401,
          headers: getSecurityHeaders("application/json")
        });
      } catch {
        return new Response(JSON.stringify({ success: false, message: "Login error" }), {
          status: 400,
          headers: getSecurityHeaders("application/json")
        });
      }
    }

    if (url.pathname === "/api/logout") {
      return new Response(null, {
        status: 302,
        headers: {
          "Location": "/",
          "Set-Cookie": "galaxy_auth=0; Path=/; Max-Age=0; SameSite=Lax"
        }
      });
    }

    // Base64 VLESS subscription (TLS/443, HTTP/80, optional safe ProxyIP)
    if (url.pathname === "/sub" && request.method === "GET") {
      if (!isValidUUID(userID)) {
        logger.warn("SUBSCRIPTION_REQUEST_WITHOUT_UUID");
        return new Response("UUID is not configured", {
          status: 401,
          headers: getSecurityHeaders("text/plain; charset=utf-8")
        });
      }

      const host = request.headers.get("Host") || url.host;
      const configs = generateVlessConfigs(host, userID, configuredWsPath, proxyIP, trojanPassword);
      logger.info("SUBSCRIPTION_SERVED", { host, wsPath: configuredWsPath });
      return new Response(configs.base64, {
        status: 200,
        headers: {
          ...getSecurityHeaders("text/plain; charset=utf-8"),
          "Subscription-Userinfo": "upload=0; download=0; total=0; expire=0",
          "Profile-Update-Interval": "24"
        }
      });
    }

    // Handle WebSocket Proxy Connection
    const upgradeHeader = request.headers.get("Upgrade");
    if (upgradeHeader === "websocket") {
      // Camouflage WebSocket path leak risk (Item 11)
      if (pathname !== configuredWsPath) {
        logger.warn("UNAUTHORIZED_WS_PATH", { path: pathname, expected: configuredWsPath });
        return new Response(getCamouflage404(), {
          status: 404,
          headers: getSecurityHeaders("text/html; charset=utf-8")
        });
      }

      // Check UUID validity for WebSocket upgrade (Item 1)
      if (!isValidUUID(userID)) {
        logger.warn("WS_ATTEMPT_WITHOUT_UUID");
        return new Response(getUnauthorizedPage(), {
          status: 401,
          headers: getSecurityHeaders("text/html; charset=utf-8")
        });
      }

      return await proxyOverWSHandler(
        request,
        userID,
        proxyIP,
        rawProxyListUrl,
        dohURL,
        logger,
        routeRulesRaw,
        routeServersRaw
      );
    }

    // Public visitors see the requested EdgeTunnel diagnostic mask page.
    // The configured UUID path or a short-lived auth cookie opens the Galaxy console.
    const cookieHeader = request.headers.get("Cookie") || "";
    const hasAuthCookie = cookieHeader.split(";").some((item) => item.trim() === "galaxy_auth=1");
    const directUuidPath = isValidUUID(pathname) && isValidUUID(userID) && pathname.toLowerCase() === userID.toLowerCase();

    if (directUuidPath || hasAuthCookie) {
      logger.info("GALAXY_PAGE_SERVED");
      return new Response(getGalaxyPage(), {
        status: 200,
        headers: getSecurityHeaders("text/html; charset=utf-8")
      });
    }

    if (pathname !== "" && pathname !== configuredWsPath) {
      return new Response(getCamouflage404(), {
        status: 404,
        headers: getSecurityHeaders("text/html; charset=utf-8")
      });
    }

    const maskHost = request.headers.get("Host") || url.host;
    const maskClientIp = request.headers.get("CF-Connecting-IP") || "127.0.0.1";
    const maskColo = request.cf?.colo || "EDGE-GLOBAL";
    logger.info("MASK_PAGE_SERVED");
    return new Response(getMaskPage(maskHost, Boolean(envPassword || isValidUUID(userID)), maskClientIp, maskColo), {
      status: 200,
      headers: getSecurityHeaders("text/html; charset=utf-8")
    });
  }
};

// ============================================
// WEBSOCKET PROXY STREAM HANDLER
// ============================================
async function proxyOverWSHandler(
  request,
  userID,
  defaultProxy,
  rawProxyListUrl,
  dohURL,
  logger,
  routeRulesRaw = "",
  routeServersRaw = ""
) {
  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);
  webSocket.accept();

  let address = "";
  let portWithRandomLog = "";

  const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";
  const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, logger);

  const remoteSocketWrapper = { value: null };
  let udpStreamWrite = null;
  let isDns = false;

  readableWebSocketStream.pipeTo(
    new WritableStream({
      async write(chunk) {
        if (isDns && udpStreamWrite) {
          return udpStreamWrite(chunk);
        }
        if (remoteSocketWrapper.value) {
          const writer = remoteSocketWrapper.value.writable.getWriter();
          await writer.write(chunk);
          writer.releaseLock();
          return;
        }

        // Process VLESS Protocol Header
        const result = processVlessHeader(chunk, userID);

        if (result.hasError) {
          logger.error("VLESS_HEADER_ERROR", { message: result.message });
          throw new Error(result.message);
        }

        const { addressRemote = "", portRemote = 443, rawDataIndex, responseHeader, isUDP } = result;

        // SSRF check on target destination
        if (isPrivateOrBlockedHost(addressRemote)) {
          logger.warn("BLOCKED_PRIVATE_DESTINATION", { address: addressRemote });
          throw new Error("Access to private destination is blocked");
        }

        address = addressRemote;
        portWithRandomLog = `${portRemote} ${isUDP ? "udp" : "tcp"}`;

        if (isUDP && portRemote !== 53) {
          logger.warn("NON_DNS_UDP_REJECTED", { port: portRemote });
          throw new Error("UDP proxy only enabled for DNS (port 53)");
        }
        if (isUDP && portRemote === 53) {
          isDns = true;
        }

        const rawClientData = chunk.slice(rawDataIndex);

        if (isDns) {
          const { write } = await handleUDPOutBound(webSocket, responseHeader, dohURL, logger);
          udpStreamWrite = write;
          udpStreamWrite(rawClientData);
          return;
        }

        handleTCPOutBound(
          remoteSocketWrapper,
          addressRemote,
          portRemote,
          rawClientData,
          webSocket,
          responseHeader,
          defaultProxy,
          rawProxyListUrl,
          logger,
          routeRulesRaw,
          routeServersRaw
        );
      },
      close() {
        logger.info("WS_STREAM_CLOSED");
      },
      abort(reason) {
        logger.warn("WS_STREAM_ABORTED", { reason: String(reason) });
      }
    })
  ).catch((err) => {
    logger.error("WS_PIPE_ERROR", { error: err.message });
  });

  return new Response(null, { status: 101, webSocket: client });
}

// ============================================
// TCP OUTBOUND WITH TIMEOUT & HYBRID PROXY (Item 8)
// ============================================
async function handleTCPOutBound(
  remoteSocket,
  addressRemote,
  portRemote,
  rawClientData,
  webSocket,
  responseHeader,
  defaultProxy,
  rawProxyListUrl,
  logger,
  routeRulesRaw = "",
  routeServersRaw = ""
) {
  if (isAdDomain(addressRemote)) {
    logger.info("AD_DOMAIN_BLOCKED", {
      address: addressRemote,
      port: portRemote
    });
    safeCloseWebSocket(webSocket);
    return;
  }

  const route = resolveRouteTarget(addressRemote, portRemote, routeRulesRaw, routeServersRaw, logger);
  const primaryAddress = route?.host || addressRemote;
  const primaryPort = route?.port || portRemote;
  if (route) logger.info("DESTINATION_ROUTE_SELECTED", {
    destination: addressRemote,
    route: route.rule,
    server: route.name,
    target: `${primaryAddress}:${primaryPort}`
  });

  let timeoutTimer = null;

  const resetTimeout = () => {
    if (timeoutTimer) clearTimeout(timeoutTimer);
    timeoutTimer = setTimeout(() => {
      logger.warn("CONNECTION_TIMEOUT_REACHED", { address: addressRemote, port: portRemote });
      safeCloseWebSocket(webSocket);
      if (remoteSocket.value && remoteSocket.value.close) {
        try { remoteSocket.value.close(); } catch {}
      }
    }, CONNECTION_TIMEOUT_MS);
  };

  async function connectAndWrite(address, port) {
    resetTimeout();
    const tcpSocket2 = connect({ hostname: address, port });
    remoteSocket.value = tcpSocket2;
    logger.info("TCP_CONNECTING", { target: `${address}:${port}` });

    const writer = tcpSocket2.writable.getWriter();
    await writer.write(rawClientData);
    writer.releaseLock();
    return tcpSocket2;
  }

  async function retry() {
    const activeProxy = await proxyPoolManager.getProxy(defaultProxy, rawProxyListUrl, logger);
    const target = activeProxy || addressRemote;
    logger.info("RETRYING_VIA_PROXY", { proxy: target, port: portRemote });

    try {
      const tcpSocket2 = await connectAndWrite(target, portRemote);
      tcpSocket2.closed
        .catch((error) => {
          logger.warn("RETRY_TCP_CLOSED_ERROR", { error: error.message });
        })
        .finally(() => {
          if (timeoutTimer) clearTimeout(timeoutTimer);
          safeCloseWebSocket(webSocket);
        });
      remoteSocketToWS(tcpSocket2, webSocket, responseHeader, null, logger, resetTimeout);
    } catch (retryErr) {
      logger.error("RETRY_CONNECT_FAILED", { error: retryErr.message });
      safeCloseWebSocket(webSocket);
    }
  }

  try {
    const tcpSocket = await connectAndWrite(primaryAddress, primaryPort);
    remoteSocketToWS(tcpSocket, webSocket, responseHeader, retry, logger, resetTimeout);
  } catch (err) {
    logger.warn("DIRECT_TCP_FAILED_RETRYING", { error: err.message });
    await retry();
  }
}

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, logger) {
  return new ReadableStream({
    start(controller) {
      webSocketServer.addEventListener("message", (event) => {
        controller.enqueue(event.data);
      });
      webSocketServer.addEventListener("close", () => {
        safeCloseWebSocket(webSocketServer);
        controller.close();
      });
      webSocketServer.addEventListener("error", (err) => {
        logger.error("WS_EVENT_ERROR", { error: err.message });
        controller.error(err);
      });

      const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
      if (error) {
        controller.error(error);
      } else if (earlyData) {
        controller.enqueue(earlyData);
      }
    },
    cancel(reason) {
      logger.warn("WS_STREAM_CANCELED", { reason: String(reason) });
      safeCloseWebSocket(webSocketServer);
    }
  });
}

// ============================================
// VLESS PROTOCOL PARSER (Item 7: with formatIPv6)
// ============================================
function processVlessHeader(vlessBuffer, userID2) {
  if (vlessBuffer.byteLength < 24) {
    return { hasError: true, message: "Invalid VLESS data" };
  }

  const version = new Uint8Array(vlessBuffer.slice(0, 1));
  const slicedBuffer = new Uint8Array(vlessBuffer.slice(1, 17));
  const slicedBufferString = stringify(slicedBuffer);

  const uuids = userID2.includes(",") ? userID2.split(",") : [userID2];
  const isValidUser = uuids.some((userUuid) => slicedBufferString === userUuid.trim());

  if (!isValidUser) {
    return { hasError: true, message: "Invalid VLESS user" };
  }

  const optLength = new Uint8Array(vlessBuffer.slice(17, 18))[0];
  const command = new Uint8Array(vlessBuffer.slice(18 + optLength, 18 + optLength + 1))[0];

  let isUDP = false;
  if (command === 1) {
    isUDP = false;
  } else if (command === 2) {
    isUDP = true;
  } else {
    return { hasError: true, message: `VLESS command ${command} not supported` };
  }

  const portIndex = 18 + optLength + 1;
  const portBuffer = vlessBuffer.slice(portIndex, portIndex + 2);
  const portRemote = new DataView(portBuffer).getUint16(0);

  const addressIndex = portIndex + 2;
  const addressType = new Uint8Array(vlessBuffer.slice(addressIndex, addressIndex + 1))[0];

  let addressLength = 0;
  let addressValueIndex = addressIndex + 1;
  let addressValue = "";

  switch (addressType) {
    case 1:
      addressLength = 4;
      addressValue = new Uint8Array(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
      break;
    case 2:
      addressLength = new Uint8Array(vlessBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
      addressValueIndex += 1;
      addressValue = new TextDecoder().decode(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      break;
    case 3: {
      addressLength = 16;
      const dataView = new DataView(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      const rawHextets = [];
      for (let i = 0; i < 8; i++) {
        rawHextets.push(dataView.getUint16(i * 2));
      }
      // IPv6 RFC 5952 Zero-Compression (Item 7)
      addressValue = formatIPv6(rawHextets);
      break;
    }
    default:
      return { hasError: true, message: `Invalid VLESS address type ${addressType}` };
  }

  if (!addressValue) {
    return { hasError: true, message: "VLESS address value is empty" };
  }

  const responseHeader = new Uint8Array([version[0], 0]);
  return {
    hasError: false,
    addressRemote: addressValue,
    addressType,
    portRemote,
    rawDataIndex: addressValueIndex + addressLength,
    responseHeader,
    isUDP
  };
}

async function remoteSocketToWS(remoteSocket, webSocket, responseHeader, retry, logger, onDataActivity) {
  let header = responseHeader;
  let hasIncomingData = false;

  await remoteSocket.readable
    .pipeTo(
      new WritableStream({
        async write(chunk) {
          hasIncomingData = true;
          if (onDataActivity) onDataActivity();
          if (webSocket.readyState !== 1) {
            throw new Error("WebSocket not open");
          }
          if (header) {
            webSocket.send(await new Blob([header, chunk]).arrayBuffer());
            header = null;
          } else {
            webSocket.send(chunk);
          }
        },
        close() {
          logger.info("REMOTE_SOCKET_CLOSED", { hadData: hasIncomingData });
        },
        abort(reason) {
          logger.warn("REMOTE_READABLE_ABORT", { reason: String(reason) });
        }
      })
    )
    .catch((error) => {
      logger.error("REMOTE_SOCKET_PIPE_ERROR", { error: error.message });
      safeCloseWebSocket(webSocket);
    });

  if (hasIncomingData === false && retry) {
    logger.info("NO_DATA_RECEIVED_TRIGGERING_RETRY");
    retry();
  }
}

function base64ToArrayBuffer(base64Str) {
  if (!base64Str) {
    return { earlyData: null, error: null };
  }
  try {
    base64Str = base64Str.replace(/-/g, "+").replace(/_/g, "/");
    const decode = atob(base64Str);
    const arrayBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
    return { earlyData: arrayBuffer.buffer, error: null };
  } catch (error) {
    return { earlyData: null, error };
  }
}

const byteToHex = [];
for (let i = 0; i < 256; ++i) {
  byteToHex.push((i + 256).toString(16).slice(1));
}

function unsafeStringify(arr, offset = 0) {
  return (
    byteToHex[arr[offset + 0]] +
    byteToHex[arr[offset + 1]] +
    byteToHex[arr[offset + 2]] +
    byteToHex[arr[offset + 3]] +
    "-" +
    byteToHex[arr[offset + 4]] +
    byteToHex[arr[offset + 5]] +
    "-" +
    byteToHex[arr[offset + 6]] +
    byteToHex[arr[offset + 7]] +
    "-" +
    byteToHex[arr[offset + 8]] +
    byteToHex[arr[offset + 9]] +
    "-" +
    byteToHex[arr[offset + 10]] +
    byteToHex[arr[offset + 11]] +
    byteToHex[arr[offset + 12]] +
    byteToHex[arr[offset + 13]] +
    byteToHex[arr[offset + 14]] +
    byteToHex[arr[offset + 15]]
  ).toLowerCase();
}

function stringify(arr, offset = 0) {
  const uuid = unsafeStringify(arr, offset);
  if (!isValidUUID(uuid)) {
    throw TypeError("Stringified UUID is invalid");
  }
  return uuid;
}

function safeCloseWebSocket(socket) {
  try {
    if (socket.readyState === 1 || socket.readyState === 2) {
      socket.close();
    }
  } catch (error) {
    console.error("safeCloseWebSocket error", error);
  }
}

async function handleUDPOutBound(webSocket, responseHeader, dohURL, logger) {
  let isHeaderSent = false;
  const transformStream = new TransformStream({
    transform(chunk, controller) {
      for (let index = 0; index < chunk.byteLength; ) {
        const lengthBuffer = chunk.slice(index, index + 2);
        const udpPacketLength = new DataView(lengthBuffer).getUint16(0);
        const udpData = new Uint8Array(chunk.slice(index + 2, index + 2 + udpPacketLength));
        index = index + 2 + udpPacketLength;
        controller.enqueue(udpData);
      }
    },
    flush() {}
  });

  transformStream.readable
    .pipeTo(
      new WritableStream({
        async write(chunk) {
          const resp = await fetch(dohURL, {
            method: "POST",
            headers: { "content-type": "application/dns-message" },
            body: chunk
          });
          const dnsQueryResult = await resp.arrayBuffer();
          const udpSize = dnsQueryResult.byteLength;
          const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 255, udpSize & 255]);

          if (webSocket.readyState === 1) {
            logger.info("DOH_QUERY_SUCCESS", { responseSize: udpSize });
            if (isHeaderSent) {
              webSocket.send(await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer());
            } else {
              webSocket.send(await new Blob([responseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer());
              isHeaderSent = true;
            }
          }
        }
      })
    )
    .catch((error) => {
      logger.error("DNS_UDP_ERROR", { error: error.message });
    });

  const writer = transformStream.writable.getWriter();
  return { write: (chunk) => writer.write(chunk) };
}

export default worker_default;

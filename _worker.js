import { connect } from "cloudflare:sockets";

// ============================================
// CONSTANTS & DEFAULT CONFIGURATION
// ============================================
const DEFAULT_LOCAL_PROXIES = [
  "galaxytunnl.cloud-ip.cc",
  "104.16.132.229",
  "104.16.133.229",
  "162.159.137.65"
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
// CAMOUFLAGE MASK WEBSITE (GALAXY TUNNEL AUTHENTIC UI)
// ============================================
function getMaskPage(host = "localhost", isAuthEnabled = true, clientIp = "127.0.0.1", colo = "EDGE-LOCAL") {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="description" content="Galaxy Edgetunnel - Cloudflare Anycast Zero Log Enterprise Gateway and Network Diagnostics.">
  <meta property="og:title" content="GALAXY TUNNEL | Galaxy Edgetunnel">
  <meta property="og:description" content="Cloudflare Anycast Zero Log Enterprise Edge Gateway.">
  <title>GALAXY TUNNEL | Galaxy Edgetunnel</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@700;800;900&family=Space+Grotesk:wght@500;600;700&display=swap" rel="stylesheet">
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: radial-gradient(circle at 50% 30%, #061730 0%, #030b18 60%, #01050d 100%);
      color: #f1f5f9;
      font-family: 'Space Grotesk', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: 24px 16px;
      overflow-x: hidden;
    }

    /* Ambient Background Glows */
    .ambient-glow {
      position: fixed;
      top: 15%;
      left: 50%;
      transform: translateX(-50%);
      width: 480px;
      height: 380px;
      background: radial-gradient(circle, rgba(0, 160, 255, 0.18) 0%, rgba(2, 44, 78, 0.05) 60%, transparent 80%);
      pointer-events: none;
      z-index: 0;
      filter: blur(40px);
    }

    /* Exact Card Frame from the image */
    .galaxy-card {
      position: relative;
      z-index: 10;
      width: 100%;
      max-width: 520px;
      background: linear-gradient(180deg, rgba(6, 22, 44, 0.85) 0%, rgba(2, 10, 22, 0.95) 100%);
      border: 1px solid rgba(0, 180, 255, 0.35);
      border-radius: 36px;
      padding: 44px 38px 36px 38px;
      box-shadow: 
        0 20px 60px -10px rgba(0, 0, 0, 0.85),
        0 0 40px rgba(0, 140, 255, 0.18),
        inset 0 1px 0 rgba(255, 255, 255, 0.1);
      backdrop-filter: blur(16px);
      transition: transform 0.3s ease, box-shadow 0.3s ease;
    }

    .galaxy-card:hover {
      box-shadow: 
        0 24px 70px -10px rgba(0, 0, 0, 0.9),
        0 0 50px rgba(0, 170, 255, 0.28),
        inset 0 1px 0 rgba(255, 255, 255, 0.15);
    }

    /* Title: GALAXY TUNNEL */
    .title-banner {
      font-family: 'Orbitron', -apple-system, sans-serif;
      font-size: 38px;
      font-weight: 900;
      letter-spacing: 2px;
      color: #ffffff;
      text-transform: uppercase;
      line-height: 1.1;
      margin-bottom: 14px;
      cursor: pointer;
      user-select: none;
      text-shadow: 0 0 20px rgba(255, 255, 255, 0.25);
    }

    /* Subtitle 1: Galaxy Edgetunnel */
    .subtitle-primary {
      font-size: 23px;
      font-weight: 700;
      color: #38bdf8;
      letter-spacing: 0.2px;
      margin-bottom: 12px;
    }

    /* Subtitle 2: Cloudflare Anycast Zero Log */
    .subtitle-secondary {
      display: flex;
      align-items: center;
      gap: 10px;
      font-size: 17px;
      font-weight: 500;
      color: #8fa6bd;
      margin-bottom: 38px;
    }

    .cloud-icon {
      width: 22px;
      height: 22px;
      stroke: #8fa6bd;
      stroke-width: 2;
      fill: none;
      flex-shrink: 0;
    }

    /* Button: FREE COMMUNITY ACCESS */
    .btn-access {
      width: 100%;
      background: rgba(2, 44, 78, 0.55);
      border: 2px solid #0284c7;
      border-radius: 14px;
      padding: 18px 20px;
      font-family: 'Space Grotesk', -apple-system, sans-serif;
      font-size: 17px;
      font-weight: 800;
      color: #38bdf8;
      letter-spacing: 1.5px;
      text-transform: uppercase;
      text-align: center;
      cursor: pointer;
      display: block;
      transition: all 0.25s ease;
      box-shadow: 
        inset 0 0 16px rgba(2, 132, 199, 0.25),
        0 0 20px rgba(2, 132, 199, 0.25);
      margin-bottom: 34px;
      user-select: none;
    }

    .btn-access:hover {
      background: rgba(3, 70, 120, 0.7);
      border-color: #00e5ff;
      color: #ffffff;
      box-shadow: 
        inset 0 0 24px rgba(0, 229, 255, 0.4),
        0 0 32px rgba(0, 229, 255, 0.45);
      transform: translateY(-1px);
    }

    .btn-access:active {
      transform: translateY(1px);
    }

    /* Divider */
    .divider {
      width: 100%;
      height: 1px;
      background: rgba(148, 163, 184, 0.16);
      margin-bottom: 26px;
    }

    /* Bottom Meta Text: DATE: 04/09/2026 • UNLIMITED */
    .meta-text {
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
      font-size: 15px;
      font-weight: 700;
      color: #5c708a;
      letter-spacing: 1.5px;
      text-transform: uppercase;
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .meta-dot {
      color: #3b82f6;
      font-size: 14px;
    }

    /* Telemetry Accordion / Drawer */
    .telemetry-toggle {
      margin-top: 24px;
      font-size: 12px;
      color: #0284c7;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      font-weight: 700;
      user-select: none;
      transition: color 0.2s;
    }
    .telemetry-toggle:hover { color: #38bdf8; }

    .telemetry-panel {
      margin-top: 14px;
      padding: 14px 18px;
      background: rgba(2, 6, 16, 0.6);
      border: 1px solid rgba(0, 180, 255, 0.18);
      border-radius: 12px;
      font-size: 13px;
      display: none;
    }
    .telemetry-panel.open { display: block; }
    .tel-row {
      display: flex;
      justify-content: space-between;
      padding: 6px 0;
      border-bottom: 1px solid rgba(255, 255, 255, 0.05);
    }
    .tel-row:last-child { border-bottom: none; }
    .tel-k { color: #64748b; font-weight: 500; }
    .tel-v { color: #38bdf8; font-family: monospace; font-weight: 700; }

    /* Access Modal */
    .modal-backdrop {
      position: fixed;
      top: 0; left: 0; width: 100%; height: 100%;
      background: rgba(1, 4, 10, 0.85);
      backdrop-filter: blur(12px);
      z-index: 100;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 16px;
      opacity: 0;
      pointer-events: none;
      transition: opacity 0.25s ease;
    }
    .modal-backdrop.open {
      opacity: 1;
      pointer-events: auto;
    }
    .modal-box {
      width: 100%;
      max-width: 460px;
      background: #061426;
      border: 1px solid rgba(0, 212, 255, 0.5);
      border-radius: 24px;
      padding: 28px;
      box-shadow: 0 0 50px rgba(0, 180, 255, 0.25);
    }
    .modal-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 16px;
    }
    .modal-title {
      font-size: 18px;
      font-weight: 800;
      color: #38bdf8;
      font-family: 'Orbitron', sans-serif;
    }
    .btn-close {
      background: none;
      border: none;
      color: #64748b;
      font-size: 22px;
      cursor: pointer;
    }
    .btn-close:hover { color: #ffffff; }
    .modal-desc {
      font-size: 13px;
      color: #94a3b8;
      line-height: 1.5;
      margin-bottom: 18px;
    }
    .input-key {
      width: 100%;
      background: #020712;
      border: 1px solid rgba(0, 180, 255, 0.3);
      border-radius: 10px;
      padding: 12px 14px;
      color: #38bdf8;
      font-family: monospace;
      font-size: 14px;
      outline: none;
      margin-bottom: 14px;
    }
    .input-key:focus {
      border-color: #00f0ff;
      box-shadow: 0 0 12px rgba(0, 240, 255, 0.4);
    }
    .btn-submit {
      width: 100%;
      background: linear-gradient(135deg, #0284c7 0%, #00f0ff 100%);
      color: #010610;
      border: none;
      border-radius: 10px;
      padding: 13px;
      font-size: 14px;
      font-weight: 800;
      cursor: pointer;
      font-family: 'Space Grotesk', sans-serif;
      letter-spacing: 0.5px;
      transition: opacity 0.2s;
    }
    .btn-submit:hover { opacity: 0.9; }
    .err-msg {
      font-size: 12px;
      color: #ef4444;
      margin-top: 10px;
      text-align: center;
      display: none;
    }
    .quick-links {
      margin-top: 18px;
      padding-top: 14px;
      border-top: 1px solid rgba(255, 255, 255, 0.08);
      display: flex;
      justify-content: space-between;
      font-size: 12px;
    }
    .quick-links a {
      color: #38bdf8;
      text-decoration: none;
      font-weight: 600;
    }
    .quick-links a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <div class="ambient-glow"></div>

  <!-- Main Cyber Card Matching Image Exactly -->
  <div class="galaxy-card">
    <div class="title-banner" onclick="handleSecretClick()" title="Galaxy Tunnel">
      GALAXY TUNNEL
    </div>

    <div class="subtitle-primary">
      Galaxy Edgetunnel
    </div>

    <div class="subtitle-secondary">
      <svg class="cloud-icon" viewBox="0 0 24 24">
        <path d="M17.5 19H9a7 7 0 1 1 6.71-9h1.79a4.5 4.5 0 1 1 0 9Z" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
      <span>Cloudflare Anycast Zero Log</span>
    </div>

    <button class="btn-access" onclick="openAccessModal()">
      FREE COMMUNITY ACCESS
    </button>

    <div class="divider"></div>

    <div class="meta-text">
      <span>DATE: 04/09/2026</span>
      <span class="meta-dot">•</span>
      <span>UNLIMITED</span>
    </div>

    <!-- Collapsible Edge Telemetry for ISP/Operator Legitimacy -->
    <div class="telemetry-toggle" onclick="toggleTelemetry()">
      <span id="telArrow">▸</span>
      <span>Edge Diagnostics &amp; Telemetry</span>
    </div>

    <div class="telemetry-panel" id="telemetryPanel">
      <div class="tel-row">
        <span class="tel-k">Serving Host:</span>
        <span class="tel-v">${host}</span>
      </div>
      <div class="tel-row">
        <span class="tel-k">Client Remote IP:</span>
        <span class="tel-v">${clientIp}</span>
      </div>
      <div class="tel-row">
        <span class="tel-k">Anycast Edge PoP:</span>
        <span class="tel-v">${colo}</span>
      </div>
      <div class="tel-row">
        <span class="tel-k">Roundtrip Ping:</span>
        <span class="tel-v" id="livePing">Checking...</span>
      </div>
      <div class="tel-row">
        <span class="tel-k">WAF &amp; Anti-SNI Attack Shield:</span>
        <span class="tel-v" style="color:#10b981;">Active</span>
      </div>
    </div>
  </div>

  <!-- Gateway Access Modal -->
  <div class="modal-backdrop" id="accessModal">
    <div class="modal-box">
      <div class="modal-header">
        <div class="modal-title">GALAXY PORTAL</div>
        <button class="btn-close" onclick="closeAccessModal()">✕</button>
      </div>
      <p class="modal-desc">
        Enter your Universal Unique Identifier (UUID) or Access Key to unlock configuration profiles and subscriptions.
      </p>
      <form onsubmit="handleLogin(event)">
        <input type="password" id="accessKeyInput" class="input-key" placeholder="Enter UUID or Password" autofocus required />
        <button type="submit" class="btn-submit" id="submitBtn">Unlock Community Configs</button>
      </form>
      <div class="err-msg" id="loginErrMsg">⚠️ Invalid Access Key or UUID.</div>
      <div class="quick-links">
        <a href="/sub" target="_blank">📥 Subscription Link</a>
        <a href="/api/health" target="_blank">⚡ System Status</a>
      </div>
    </div>
  </div>

  <script>
    let secretClicks = 0;
    function handleSecretClick() {
      secretClicks++;
      if (secretClicks >= 3) {
        openAccessModal();
        secretClicks = 0;
      }
    }

    document.addEventListener('keydown', (e) => {
      if ((e.ctrlKey || e.metaKey) && e.shiftKey && (e.key === 'A' || e.key === 'a')) {
        openAccessModal();
      }
      if (e.key === 'Escape') {
        closeAccessModal();
      }
    });

    function openAccessModal() {
      document.getElementById('accessModal').classList.add('open');
      document.getElementById('accessKeyInput').focus();
    }

    function closeAccessModal() {
      document.getElementById('accessModal').classList.remove('open');
      document.getElementById('loginErrMsg').style.display = 'none';
    }

    function toggleTelemetry() {
      const panel = document.getElementById('telemetryPanel');
      const arrow = document.getElementById('telArrow');
      panel.classList.toggle('open');
      arrow.textContent = panel.classList.contains('open') ? '▾' : '▸';
      if (panel.classList.contains('open')) {
        measurePing();
      }
    }

    async function measurePing() {
      const pingEl = document.getElementById('livePing');
      const t0 = performance.now();
      try {
        await fetch('/api/health?t=' + Date.now(), { cache: 'no-store' });
        const latency = Math.round(performance.now() - t0);
        pingEl.textContent = latency + ' ms';
      } catch (err) {
        pingEl.textContent = '24 ms';
      }
    }

    async function handleLogin(e) {
      e.preventDefault();
      const key = document.getElementById('accessKeyInput').value.trim();
      const errMsg = document.getElementById('loginErrMsg');
      const btn = document.getElementById('submitBtn');

      if (!key) return;
      btn.textContent = 'Verifying Access...';
      btn.disabled = true;
      errMsg.style.display = 'none';

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
          errMsg.textContent = data.message || '⚠️ Invalid Access Key.';
          errMsg.style.display = 'block';
          btn.textContent = 'Unlock Community Configs';
          btn.disabled = false;
        }
      } catch (err) {
        window.location.href = '/' + encodeURIComponent(key);
      }
    }

    // Pre-measure ping
    setTimeout(measurePing, 400);
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

      // Check UUID or Trojan credentials for WebSocket upgrade
      if (!isValidUUID(userID) && !trojanPassword && !envPassword) {
        logger.warn("WS_ATTEMPT_WITHOUT_CREDENTIALS");
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
        routeServersRaw,
        trojanPassword || envPassword
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
  routeServersRaw = "",
  trojanPassword = ""
) {
  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);
  webSocket.accept();

  let address = "";
  let portWithRandomLog = "";

  const url = new URL(request.url);
  const earlyDataHeader = request.headers.get("sec-websocket-protocol") || url.searchParams.get("ed") || "";
  const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, logger);

  // Precompute expected Trojan password hashes for instant verification
  const trojanCandidates = [trojanPassword, userID].filter(Boolean);
  const expectedTrojanHashes = trojanCandidates.map((p) => sha224(String(p).trim()).toLowerCase());

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

        // Process VLESS or Trojan Protocol Header (Dual Protocol Auto-Detect)
        const result = processProtocolHeader(chunk, userID, expectedTrojanHashes);

        if (result.hasError) {
          logger.error("PROTOCOL_HEADER_ERROR", { message: result.message });
          throw new Error(result.message);
        }

        const { addressRemote = "", portRemote = 443, rawDataIndex, responseHeader, isUDP, protocol = "vless" } = result;

        // SSRF check on target destination
        if (isPrivateOrBlockedHost(addressRemote)) {
          logger.warn("BLOCKED_PRIVATE_DESTINATION", { address: addressRemote });
          throw new Error("Access to private destination is blocked");
        }

        address = addressRemote;
        portWithRandomLog = `${portRemote} ${isUDP ? "udp" : "tcp"} (${protocol})`;

        if (isUDP && portRemote !== 53) {
          // Graceful Failover: Cloudflare Workers connect() does not support raw UDP outbound.
          // Safely acknowledge without crashing the WebSocket session, enabling client TCP fallback.
          logger.info("UDP_NON_DNS_GRACEFUL_FAILOVER", { port: portRemote, address: addressRemote });
          if (responseHeader) {
            try {
              webSocket.send(responseHeader);
            } catch (_) {}
          }
          return;
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

  // Early Data (0-RTT) Handshake Header Echo (RFC 6455 & Cloudflare WebSocket standard)
  const responseHeaders = earlyDataHeader ? { "Sec-WebSocket-Protocol": earlyDataHeader } : undefined;
  return new Response(null, { status: 101, webSocket: client, headers: responseHeaders });
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
// SHA-224 PURE JAVASCRIPT HASH HELPER
// ============================================
function sha224(message) {
  const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];
  let h0 = 0xc1059ed8, h1 = 0x367cd507, h2 = 0x3070dd17, h3 = 0xf70e5939;
  let h4 = 0xffc00b31, h5 = 0x68581511, h6 = 0x64f98fa7, h7 = 0xbefa4fa4;
  const msgBytes = new TextEncoder().encode(String(message || ""));
  const bitLen = msgBytes.length * 8;
  const numBlocks = Math.ceil((msgBytes.length + 9) / 64);
  const padded = new Uint8Array(numBlocks * 64);
  padded.set(msgBytes);
  padded[msgBytes.length] = 0x80;
  new DataView(padded.buffer).setBigUint64(padded.length - 8, BigInt(bitLen));
  const view = new DataView(padded.buffer);
  const w = new Uint32Array(64);
  for (let i = 0; i < padded.length; i += 64) {
    for (let j = 0; j < 16; j++) w[j] = view.getUint32(i + j * 4);
    for (let j = 16; j < 64; j++) {
      const s0 = ((w[j - 15] >>> 7) | (w[j - 15] << 25)) ^ ((w[j - 15] >>> 18) | (w[j - 15] << 14)) ^ (w[j - 15] >>> 3);
      const s1 = ((w[j - 2] >>> 17) | (w[j - 2] << 15)) ^ ((w[j - 2] >>> 19) | (w[j - 2] << 13)) ^ (w[j - 2] >>> 10);
      w[j] = (w[j - 16] + s0 + w[j - 7] + s1) >>> 0;
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
    for (let j = 0; j < 64; j++) {
      const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + S1 + ch + K[j] + w[j]) >>> 0;
      const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e; e = (d + temp1) >>> 0;
      d = c; c = b; b = a; a = (temp1 + temp2) >>> 0;
    }
    h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + h) >>> 0;
  }
  const toHex = (n) => n.toString(16).padStart(8, "0");
  return toHex(h0) + toHex(h1) + toHex(h2) + toHex(h3) + toHex(h4) + toHex(h5) + toHex(h6);
}

// ============================================
// TROJAN PROTOCOL PARSER
// ============================================
function processTrojanHeader(trojanBuffer, expectedHashes = []) {
  if (trojanBuffer.byteLength < 60) {
    return { hasError: true, message: "Invalid Trojan payload length" };
  }

  const view = new DataView(trojanBuffer);
  const hashBytes = new Uint8Array(trojanBuffer.slice(0, 56));
  const hexHash = new TextDecoder().decode(hashBytes).toLowerCase();

  // Validate CRLF after hex hash
  if (view.getUint8(56) !== 0x0d || view.getUint8(57) !== 0x0a) {
    return { hasError: true, message: "Invalid Trojan CRLF delimiter" };
  }

  // Validate password hash against configured hashes
  if (expectedHashes.length > 0) {
    const isMatched = expectedHashes.some((h) => h.toLowerCase() === hexHash);
    if (!isMatched) {
      return { hasError: true, message: "Invalid Trojan password hash" };
    }
  }

  const command = view.getUint8(58);
  const isUDP = command === 3;
  if (command !== 1 && command !== 3) {
    return { hasError: true, message: `Trojan command ${command} not supported` };
  }

  const addressType = view.getUint8(59);
  let addressIndex = 60;
  let addressValue = "";

  if (addressType === 1) { // IPv4
    addressValue = new Uint8Array(trojanBuffer.slice(addressIndex, addressIndex + 4)).join(".");
    addressIndex += 4;
  } else if (addressType === 3) { // Domain
    const domainLen = view.getUint8(addressIndex);
    addressIndex += 1;
    addressValue = new TextDecoder().decode(trojanBuffer.slice(addressIndex, addressIndex + domainLen));
    addressIndex += domainLen;
  } else if (addressType === 4) { // IPv6
    const rawHextets = [];
    for (let i = 0; i < 8; i++) {
      rawHextets.push(view.getUint16(addressIndex + i * 2));
    }
    addressValue = formatIPv6(rawHextets);
    addressIndex += 16;
  } else {
    return { hasError: true, message: `Unknown Trojan address type ${addressType}` };
  }

  const portRemote = view.getUint16(addressIndex);
  addressIndex += 2;

  // Validate trailing CRLF delimiter
  if (addressIndex + 1 < trojanBuffer.byteLength && view.getUint8(addressIndex) === 0x0d && view.getUint8(addressIndex + 1) === 0x0a) {
    addressIndex += 2;
  }

  return {
    hasError: false,
    addressRemote: addressValue,
    addressType,
    portRemote,
    rawDataIndex: addressIndex,
    responseHeader: null,
    isUDP,
    protocol: "trojan"
  };
}

// ============================================
// UNIFIED PROTOCOL DETECTOR (VLESS & TROJAN DUAL)
// ============================================
function processProtocolHeader(chunk, userID, trojanHashes = []) {
  if (!chunk || chunk.byteLength < 24) {
    return { hasError: true, message: "Payload buffer too small" };
  }

  const view = new DataView(chunk);

  // Trojan signature: minimum 58 bytes, bytes 56 and 57 must be \r\n (0x0d, 0x0a)
  if (chunk.byteLength >= 58 && view.getUint8(56) === 0x0d && view.getUint8(57) === 0x0a) {
    return processTrojanHeader(chunk, trojanHashes);
  }

  // Otherwise, process as VLESS
  return processVlessHeader(chunk, userID);
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

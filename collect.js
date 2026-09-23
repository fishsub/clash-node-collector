#!/usr/bin/env node
/**
 * clash-node-collector
 * 本地收集公开代理订阅源，支持 Base64 / URI 列表 / Clash YAML
 * 按 IP + 端口 去重，输出标准 Clash / Mihomo 订阅 YAML
 *
 * 用法: node collect.js
 * 需要: Node.js 18+
 */

import { writeFileSync, mkdirSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

// ==================== 订阅源（可自行增删）====================
const SOURCES = [
  { name: 'awesome-vpn-all', url: 'https://raw.githubusercontent.com/awesome-vpn/awesome-vpn/master/all' },
  { name: 'awesome-vpn-clash', url: 'https://raw.githubusercontent.com/awesome-vpn/awesome-vpn/master/clash.yaml' },
  { name: 'Alirewa-sub1', url: 'https://raw.githubusercontent.com/Alirewa/V2ray-Configs/main/sub1.txt' },
  { name: 'morpheus-best', url: 'https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/best.txt' },
  { name: 'morpheus-lite', url: 'https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/lite.txt' },
  { name: 'MatinGhanbari', url: 'https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/all_sub.txt' },
  { name: 'ebrasha', url: 'https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/main/all_extracted_configs.txt' },
  { name: 'Au1rxx-b64', url: 'https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/v2ray-base64.txt' },
  { name: 'Au1rxx-clash', url: 'https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/clash.yaml' },
  { name: 'kooker-b64', url: 'https://raw.githubusercontent.com/kooker/FreeSubsCheck/main/base64.txt' },
  { name: 'kooker-mihomo', url: 'https://raw.githubusercontent.com/kooker/FreeSubsCheck/main/mihomo.yaml' },
];

/** 输出节点上限，防止客户端卡死 */
const MAX_PROXIES = 2500;
const TIMEOUT_MS = 25000;

// ==================== 工具 ====================
function b64decode(str) {
  try {
    const s = String(str).replace(/\s+/g, '');
    const pad = '='.repeat((4 - (s.length % 4)) % 4);
    return Buffer.from(s + pad, 'base64').toString('utf8');
  } catch {
    return '';
  }
}

function safeName(s, i) {
  s = decodeURIComponent(String(s || '').replace(/\+/g, ' '));
  s = s.replace(/[\x00-\x1f"]/g, '').slice(0, 60);
  return s || `node-${i}`;
}

function parseQuery(qs) {
  const out = {};
  if (!qs) return out;
  for (const part of qs.split('&')) {
    const eq = part.indexOf('=');
    if (eq === -1) {
      if (part) out[decodeURIComponent(part)] = '';
      continue;
    }
    const k = part.slice(0, eq);
    const v = part.slice(eq + 1);
    if (k) out[decodeURIComponent(k)] = decodeURIComponent(v || '');
  }
  return out;
}

/** 去重键：仅 IP + 端口 */
function dedupeKey(server, port) {
  return `${String(server).toLowerCase()}|${parseInt(port, 10) || 0}`;
}

const URI_RE = /(?:vmess|vless|trojan|ss|ssr|hysteria2|hy2|hysteria|tuic):\/\/[^\s<>"']+/gi;

// ==================== URI → Clash Proxy ====================
function vmessToProxy(uri, i) {
  let raw = uri.slice(8);
  let frag = '';
  if (raw.includes('#')) {
    const idx = raw.indexOf('#');
    frag = raw.slice(idx + 1);
    raw = raw.slice(0, idx);
  }
  let data;
  try {
    data = JSON.parse(b64decode(raw) || raw);
  } catch {
    return null;
  }
  const server = String(data.add || data.host || '');
  const port = parseInt(data.port, 10);
  const uuid = String(data.id || '');
  if (!server || !port || !uuid) return null;

  const net = data.net || 'tcp';
  const tls = ['tls', 'true', '1', 'reality'].includes(String(data.tls || '').toLowerCase());
  const proxy = {
    name: safeName(frag || data.ps, i),
    type: 'vmess',
    server,
    port,
    uuid,
    alterId: parseInt(data.aid || 0, 10),
    cipher: data.scy || 'auto',
    udp: true,
    network: net,
  };
  if (tls) {
    proxy.tls = true;
    if (data.sni || data.host) proxy.servername = data.sni || data.host;
  }
  if (net === 'ws') {
    proxy['ws-opts'] = {
      path: data.path || '/',
      headers: { Host: data.host || server },
    };
  }
  if (net === 'grpc') {
    proxy['grpc-opts'] = { 'grpc-service-name': data.path || '' };
  }
  return { proxy, key: dedupeKey(server, port) };
}

function genericUriToProxy(uri, i) {
  const m = uri.match(/^([a-z0-9]+):\/\/(.+)$/i);
  if (!m) return null;
  let scheme = m[1].toLowerCase();
  if (scheme === 'hy2') scheme = 'hysteria2';
  let rest = m[2];
  let frag = '';
  if (rest.includes('#')) {
    const idx = rest.lastIndexOf('#');
    frag = rest.slice(idx + 1);
    rest = rest.slice(0, idx);
  }
  let query = {};
  if (rest.includes('?')) {
    const idx = rest.indexOf('?');
    query = parseQuery(rest.slice(idx + 1));
    rest = rest.slice(0, idx);
  }

  // ss://base64(method:pass@host:port)
  if (scheme === 'ss' && !rest.includes('@')) {
    const dec = b64decode(rest);
    if (dec.includes('@')) return genericUriToProxy(`ss://${dec}${frag ? '#' + frag : ''}`, i);
  }

  let user = '', pass = '', hostport = rest;
  if (rest.includes('@')) {
    const idx = rest.lastIndexOf('@');
    const userinfo = rest.slice(0, idx);
    hostport = rest.slice(idx + 1);
    if (scheme === 'ss' && userinfo.includes(':')) {
      const ci = userinfo.indexOf(':');
      user = userinfo.slice(0, ci);
      pass = userinfo.slice(ci + 1);
    } else {
      pass = userinfo;
      user = userinfo;
    }
  }

  let host = hostport;
  let port = 0;
  if (hostport.startsWith('[')) {
    const mm = hostport.match(/^\[(.+)\]:(\d+)$/);
    if (mm) {
      host = mm[1];
      port = parseInt(mm[2], 10);
    }
  } else {
    const ci = hostport.lastIndexOf(':');
    if (ci > 0) {
      host = hostport.slice(0, ci);
      port = parseInt(hostport.slice(ci + 1), 10);
    }
  }
  if (!host || !port) return null;
  host = decodeURIComponent(host);
  pass = decodeURIComponent(pass || '');
  user = decodeURIComponent(user || '');

  const name = safeName(frag, i);
  const proxy = { name, type: scheme, server: host, port, udp: true };
  let ident = pass || user;

  if (scheme === 'vless') {
    proxy.type = 'vless';
    proxy.uuid = pass;
    proxy.encryption = query.encryption || 'none';
    const net = query.type || query.network || 'tcp';
    proxy.network = net;
    const sec = (query.security || '').toLowerCase();
    if (sec === 'tls' || sec === 'reality') proxy.tls = true;
    if (query.sni || query.servername) proxy.servername = query.sni || query.servername;
    if (query.flow) proxy.flow = query.flow;
    if (query.fp || query.fingerprint) proxy['client-fingerprint'] = query.fp || query.fingerprint;
    if (sec === 'reality') {
      proxy.tls = true;
      const ro = {};
      if (query.pbk || query.publicKey) ro['public-key'] = query.pbk || query.publicKey;
      if (query.sid || query.shortId) ro['short-id'] = query.sid || query.shortId;
      if (Object.keys(ro).length) proxy['reality-opts'] = ro;
    }
    if (net === 'ws') {
      proxy['ws-opts'] = {
        path: decodeURIComponent(query.path || '/'),
        headers: { Host: query.host || query.sni || host },
      };
    }
    if (net === 'grpc') {
      proxy['grpc-opts'] = { 'grpc-service-name': query.serviceName || query.path || '' };
    }
    ident = pass;
  } else if (scheme === 'trojan') {
    proxy.type = 'trojan';
    proxy.password = pass;
    if ((query.security || 'tls') !== 'none') proxy.tls = true;
    if (query.sni) proxy.sni = query.sni;
    if (query.allowInsecure === '1' || query.insecure === '1') proxy['skip-cert-verify'] = true;
    const net = query.type || 'tcp';
    if (net === 'ws') {
      proxy.network = 'ws';
      proxy['ws-opts'] = {
        path: decodeURIComponent(query.path || '/'),
        headers: { Host: query.host || query.sni || host },
      };
    }
    ident = pass;
  } else if (scheme === 'ss') {
    proxy.type = 'ss';
    proxy.cipher = user || query.method || 'aes-128-gcm';
    proxy.password = pass;
    ident = `${proxy.cipher}:${pass}`;
  } else if (scheme === 'hysteria2') {
    proxy.type = 'hysteria2';
    proxy.password = pass;
    if (query.sni) proxy.sni = query.sni;
    if (query.insecure === '1' || query.allow_insecure === '1') proxy['skip-cert-verify'] = true;
    if (query.obfs) proxy.obfs = query.obfs;
    if (query['obfs-password']) proxy['obfs-password'] = query['obfs-password'];
    ident = pass;
  } else if (scheme === 'hysteria') {
    proxy.type = 'hysteria';
    proxy['auth-str'] = pass || query.auth || '';
    if (query.sni) proxy.sni = query.sni;
    proxy.up = query.upmbps || '50';
    proxy.down = query.downmbps || '100';
    ident = pass;
  } else if (scheme === 'tuic') {
    proxy.type = 'tuic';
    proxy.uuid = user || pass;
    proxy.password = user ? pass : query.password || '';
    if (query.sni) proxy.sni = query.sni;
    proxy.alpn = [query.alpn || 'h3'];
    ident = proxy.uuid;
  } else {
    return null;
  }

  if (!ident) return null;
  return { proxy, key: dedupeKey(host, port) };
}

function uriToProxy(uri, i) {
  try {
    if (uri.toLowerCase().startsWith('vmess://')) return vmessToProxy(uri, i);
    return genericUriToProxy(uri, i);
  } catch {
    return null;
  }
}

// ==================== 提取 URI ====================
function extractUris(text) {
  const uris = new Set();
  let body = text;
  const stripped = text.trim();

  if (stripped && !/^(vmess|vless|trojan|ss|hy|#|proxies:|port:|mixed-port:)/i.test(stripped)) {
    const dec = b64decode(stripped);
    if (dec && (dec.includes('://') || /vmess|vless|trojan/.test(dec.slice(0, 30)))) {
      body = dec;
    }
  }

  for (const line of body.split(/\r?\n/)) {
    const l = line.trim();
    if (!l || l.startsWith('#')) continue;
    if (l.includes('://')) {
      const m = l.match(URI_RE);
      if (m) m.forEach((u) => uris.add(u.replace(/[`,;"')\]]+$/, '')));
      continue;
    }
    if (l.length > 30 && /^[A-Za-z0-9+/_=-]+$/.test(l)) {
      const dec = b64decode(l);
      if (dec.includes('://')) {
        const m = dec.match(URI_RE);
        if (m) m.forEach((u) => uris.add(u.replace(/[`,;"')\]]+$/, '')));
      }
    }
  }

  const all = body.match(URI_RE);
  if (all) all.forEach((u) => uris.add(u.replace(/[`,;"')\]]+$/, '')));
  return [...uris];
}

// ==================== Clash YAML ====================
async function tryParseYaml(text) {
  try {
    const yaml = await import('js-yaml');
    const data = yaml.load(text);
    if (data && Array.isArray(data.proxies)) return data.proxies;
    return [];
  } catch {
    return [];
  }
}

function normalizeClashProxy(p, i) {
  if (!p || !p.type || !p.server || !p.port) return null;
  const name = safeName(p.name, i);
  const proxy = { ...p, name, udp: p.udp !== false };
  return { proxy, key: dedupeKey(proxy.server, proxy.port) };
}

// ==================== 拉取 ====================
async function fetchText(url) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      signal: ctrl.signal,
      headers: { 'User-Agent': 'clash-node-collector/1.0' },
      redirect: 'follow',
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.text();
  } finally {
    clearTimeout(t);
  }
}

// ==================== 主流程 ====================
async function main() {
  const seen = new Map();
  const nameSet = new Set();
  let idx = 0;

  console.log(`clash-node-collector — 拉取 ${SOURCES.length} 个源（按 IP+端口 去重）\n`);

  for (const src of SOURCES) {
    process.stdout.write(`[${src.name}] `);
    try {
      const text = await fetchText(src.url);
      let added = 0;

      const yamlProxies = await tryParseYaml(text);
      if (yamlProxies.length) {
        for (const p of yamlProxies) {
          idx++;
          const res = normalizeClashProxy(p, idx);
          if (!res || seen.has(res.key)) continue;
          let n = res.proxy.name;
          let c = 1;
          while (nameSet.has(n)) n = `${res.proxy.name}-${++c}`;
          res.proxy.name = n;
          nameSet.add(n);
          seen.set(res.key, res.proxy);
          added++;
        }
        console.log(`YAML ${yamlProxies.length} → 新增 ${added}`);
        continue;
      }

      const uris = extractUris(text);
      for (const uri of uris) {
        idx++;
        const res = uriToProxy(uri, idx);
        if (!res || seen.has(res.key)) continue;
        let n = res.proxy.name;
        let c = 1;
        while (nameSet.has(n)) n = `${res.proxy.name}-${++c}`;
        res.proxy.name = n;
        nameSet.add(n);
        seen.set(res.key, res.proxy);
        added++;
      }
      console.log(`URI ${uris.length} → 新增 ${added}`);
    } catch (e) {
      console.log(`失败: ${e.message}`);
    }
  }

  let proxies = [...seen.values()];
  console.log(`\n去重后共 ${proxies.length} 个节点（IP+端口唯一）`);
  if (proxies.length > MAX_PROXIES) {
    proxies = proxies.slice(0, MAX_PROXIES);
    console.log(`已截断为 ${MAX_PROXIES} 个（修改 MAX_PROXIES 可调整）`);
  }

  const names = proxies.map((p) => p.name);
  const doc = {
    'mixed-port': 7890,
    'allow-lan': false,
    mode: 'rule',
    'log-level': 'info',
    ipv6: false,
    'external-controller': '127.0.0.1:9090',
    'unified-delay': true,
    proxies,
    'proxy-groups': [
      {
        name: 'PROXY',
        type: 'select',
        proxies: ['AUTO', ...names],
      },
      {
        name: 'AUTO',
        type: 'url-test',
        proxies: names,
        url: 'http://www.gstatic.com/generate_204',
        interval: 300,
        tolerance: 50,
      },
    ],
    rules: ['GEOIP,LAN,DIRECT', 'MATCH,PROXY'],
  };

  let yamlText;
  try {
    const yaml = await import('js-yaml');
    yamlText = yaml.dump(doc, { lineWidth: 120, noRefs: true });
  } catch {
    console.warn('未安装 js-yaml，输出 JSON。建议: npm i js-yaml');
    yamlText = JSON.stringify(doc, null, 2);
  }

  const outDir = join(__dirname, 'output');
  mkdirSync(outDir, { recursive: true });
  const outFile = join(outDir, 'clash.yaml');
  writeFileSync(outFile, yamlText, 'utf8');
  console.log(`\n已保存: ${outFile}`);
  console.log('可导入 Clash Verge / Clash Meta / Mihomo');
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

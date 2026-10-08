const { token, isLocked, isAuthed, keyMatches } = require('./_auth');

module.exports = (req, res) => {
  if (!isLocked()) return res.status(200).json({ locked: false, authed: true });

  if (req.method === 'POST') {
    const key = req.body && req.body.key;
    if (!keyMatches(key)) return res.status(401).json({ locked: true, authed: false });
    res.setHeader(
      'Set-Cookie',
      'lf=' + token() + '; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000'
    );
    return res.status(200).json({ locked: true, authed: true });
  }

  return res.status(200).json({ locked: true, authed: isAuthed(req) });
};

const dns = require('node:dns').promises;
const net = require('node:net');
const { isAuthed } = require('./_auth');

const P = '/api/proxy?url=';

// Response headers that stop a page from loading inside another page, or that
// would be wrong after we re-serve the content.
const DROP = new Set([
  'x-frame-options',
  'content-security-policy',
  'content-security-policy-report-only',
  'set-cookie',
  'content-encoding',
  'content-length',
  'transfer-encoding',
  'connection',
  'strict-transport-security',
  'report-to',
  'nel',
  'cross-origin-opener-policy',
  'cross-origin-embedder-policy',
  'cross-origin-resource-policy',
  'location',
]);

/* ---------- safety: never let the proxy reach private networks ---------- */

function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return (
      a === 0 || a === 10 || a === 127 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127) ||
      a >= 224
    );
  }
  const l = ip.toLowerCase();
  if (l === '::1' || l === '::' || l.startsWith('fc') || l.startsWith('fd') || l.startsWith('fe80')) return true;
  if (l.startsWith('::ffff:')) {
    const v4 = l.slice(7);
    return net.isIPv4(v4) ? isPrivateIp(v4) : true;
  }
  return false;
}

async function assertPublic(u) {
  if (u.protocol !== 'http:' && u.protocol !== 'https:') {
    throw new Error('Only http and https links can be opened.');
  }
  const host = u.hostname.replace(/^\[|\]$/g, '');
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.internal')) {
    throw new Error('That address is not allowed.');
  }
  const addrs = net.isIP(host) ? [{ address: host }] : await dns.lookup(host, { all: true });
  if (addrs.some((a) => isPrivateIp(a.address))) throw new Error('That address is not allowed.');
}

/* ---------- rewriting ---------- */

function prox(value, base) {
  const t = String(value).trim().replace(/&amp;/g, '&');
  if (!t || /^(#|data:|blob:|javascript:|mailto:|tel:|about:)/i.test(t)) return value;
  try {
    return P + encodeURIComponent(new URL(t, base).href);
  } catch (e) {
    return value;
  }
}

function rewriteCss(css, base) {
  return css
    .replace(/url\(\s*(['"]?)([^)'"]+)\1\s*\)/gi, (m, q, u) => 'url(' + q + prox(u, base) + q + ')')
    .replace(/@import\s+(['"])([^'"]+)\1/gi, (m, q, u) => '@import ' + q + prox(u, base) + q);
}

// Runs inside every proxied page, before the page's own scripts. It catches the
// requests and navigations that the server-side rewrite cannot see.
function shim() {
  var P = '/api/proxy?url=';
  var B;
  try { B = new URLSearchParams(location.search).get('url') || location.href; } catch (e) { B = location.href; }
  var skip = /^(#|data:|blob:|javascript:|mailto:|tel:|about:)/i;

  function px(u) {
    if (u == null) return u;
    u = String(u).trim();
    if (!u || skip.test(u)) return u;
    if (u.indexOf(P) === 0 || u.indexOf(location.origin + P) === 0) return u;
    try {
      var a = new URL(u, B);
      if (a.origin === location.origin) a = new URL(a.pathname + a.search + a.hash, B);
      if (a.protocol !== 'http:' && a.protocol !== 'https:') return u;
      return P + encodeURIComponent(a.href);
    } catch (e) { return u; }
  }

  var of = window.fetch;
  if (of) {
    window.fetch = function (i, n) {
      try {
        if (typeof i === 'string' || i instanceof URL) i = px(i);
        else if (i && i.url) i = new Request(px(i.url), i);
      } catch (e) {}
      return of.call(this, i, n);
    };
  }

  var xo = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function (m, u) {
    arguments[1] = px(u);
    return xo.apply(this, arguments);
  };

  var wo = window.open;
  window.open = function (u, a, b) { return wo.call(this, px(u), a, b); };

  if (navigator.sendBeacon) {
    var sb = navigator.sendBeacon.bind(navigator);
    navigator.sendBeacon = function (u, d) { return sb(px(u), d); };
  }

  var sa = Element.prototype.setAttribute;
  Element.prototype.setAttribute = function (n, v) {
    if (/^(src|href|action|poster)$/i.test(n) && typeof v === 'string') v = px(v);
    return sa.call(this, n, v);
  };

  [
    ['HTMLImageElement', 'src'], ['HTMLScriptElement', 'src'], ['HTMLIFrameElement', 'src'],
    ['HTMLLinkElement', 'href'], ['HTMLAnchorElement', 'href'], ['HTMLSourceElement', 'src'],
    ['HTMLMediaElement', 'src'], ['HTMLFormElement', 'action'], ['HTMLEmbedElement', 'src'],
    ['HTMLVideoElement', 'poster']
  ].forEach(function (pair) {
    var C = window[pair[0]];
    if (!C) return;
    var d = Object.getOwnPropertyDescriptor(C.prototype, pair[1]);
    if (!d || !d.set) return;
    Object.defineProperty(C.prototype, pair[1], {
      configurable: true,
      enumerable: d.enumerable,
      get: d.get,
      set: function (v) { d.set.call(this, px(v)); }
    });
  });

  // GET forms replace the whole query string, which would wipe out ?url=, so
  // build the target address ourselves.
  document.addEventListener('submit', function (e) {
    var f = e.target;
    if (!f || f.tagName !== 'FORM' || e.defaultPrevented) return;
    var raw = f.getAttribute('action');
    var real;
    try {
      if (!raw) real = B;
      else if (raw.indexOf(P) === 0) real = decodeURIComponent(raw.slice(P.length));
      else real = new URL(raw, B).href;
    } catch (err) { return; }
    var method = (f.getAttribute('method') || 'get').toLowerCase();
    if (method === 'get') {
      try {
        var u = new URL(real);
        var fd = e.submitter ? new FormData(f, e.submitter) : new FormData(f);
        var params = new URLSearchParams();
        fd.forEach(function (v, k) { if (typeof v === 'string') params.append(k, v); });
        u.search = params.toString();
        e.preventDefault();
        location.href = P + encodeURIComponent(u.href);
      } catch (err) {}
    } else {
      f.action = P + encodeURIComponent(real);
    }
  }, true);
}

function rewriteHtml(html, pageUrl) {
  let base = pageUrl;
  const bm = html.match(/<base\b[^>]*\bhref\s*=\s*(?:"([^"]*)"|'([^']*)')/i);
  if (bm) {
    try { base = new URL(bm[1] || bm[2], pageUrl).href; } catch (e) {}
  }

  html = html
    .replace(/<meta[^>]+http-equiv\s*=\s*["']?content-security-policy["']?[^>]*>/gi, '')
    .replace(/<base\b[^>]*>/gi, '')
    .replace(/\s(?:integrity|nonce)\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/gi, '')
    .replace(/\scrossorigin(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+))?/gi, '')
    .replace(
      /(\s(?:href|src|action|poster|data-src)\s*=\s*)(?:"([^"]*)"|'([^']*)')/gi,
      (m, pre, d, s) => pre + '"' + prox(d !== undefined ? d : s, base).replace(/"/g, '&quot;') + '"'
    )
    .replace(/(\s(?:srcset|data-srcset)\s*=\s*)(?:"([^"]*)"|'([^']*)')/gi, (m, pre, d, s) => {
      const list = (d !== undefined ? d : s)
        .split(',')
        .map((c) => {
          const parts = c.trim().split(/\s+/);
          if (parts[0]) parts[0] = prox(parts[0], base);
          return parts.join(' ');
        })
        .join(', ');
      return pre + '"' + list.replace(/"/g, '&quot;') + '"';
    });

  const tag = '<script>(' + shim.toString() + ')()</script>';
  if (/<head[^>]*>/i.test(html)) return html.replace(/<head[^>]*>/i, (m) => m + tag);
  return tag + html;
}

function errorPage(res, status, message) {
  res.status(status);
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(
    '<!doctype html><meta charset="utf-8"><title>Could not open</title>' +
    '<body style="font:16px system-ui;padding:40px;max-width:520px;margin:auto;color:#17202f">' +
    '<h2>Could not open this page</h2><p>' + String(message).replace(/</g, '&lt;') + '</p></body>'
  );
}

/* ---------- handler ---------- */

module.exports = async (req, res) => {
  try {
    if (!isAuthed(req)) return errorPage(res, 401, 'This proxy is locked. Go back to the home page and enter the access key.');
    if (!['GET', 'HEAD', 'POST'].includes(req.method)) return errorPage(res, 405, 'Method not allowed.');

    let target = req.query.url;

    // A page script navigated to a path on our own origin (for example
    // location.href = '/play'). Work out the real address from the Referer.
    if (!target && req.query.stray !== undefined) {
      let base = '';
      try { base = new URL(req.headers.referer || '').searchParams.get('url') || ''; } catch (e) {}
      if (!base) return errorPage(res, 404, 'Page not found.');
      const q = new URLSearchParams();
      for (const [k, v] of Object.entries(req.query)) {
        if (k !== 'stray') (Array.isArray(v) ? v : [v]).forEach((x) => q.append(k, x));
      }
      const qs = q.toString();
      const dest = new URL('/' + req.query.stray + (qs ? '?' + qs : ''), base).href;
      res.writeHead(307, { Location: P + encodeURIComponent(dest) });
      return res.end();
    }

    if (!target) return errorPage(res, 400, 'No link was given.');
    if (Array.isArray(target)) target = target[0];

    let u;
    try { u = new URL(target); } catch (e) { return errorPage(res, 400, 'That is not a valid web address.'); }
    await assertPublic(u);

    const headers = {
      'user-agent': req.headers['user-agent'] || 'Mozilla/5.0',
      accept: req.headers.accept || '*/*',
      'accept-language': req.headers['accept-language'] || 'en-US,en;q=0.9',
      referer: u.origin + '/',
    };
    if (req.headers.range) headers.range = req.headers.range;

    let body;
    if (req.method === 'POST') {
      const ctype = req.headers['content-type'] || '';
      const b = req.body;
      if (Buffer.isBuffer(b) || typeof b === 'string') body = b;
      else if (b && ctype.includes('application/x-www-form-urlencoded')) body = new URLSearchParams(b).toString();
      else if (b) body = JSON.stringify(b);
      if (ctype) headers['content-type'] = ctype;
      headers.origin = u.origin;
    }

    const r = await fetch(u.href, {
      method: req.method,
      headers,
      body,
      redirect: 'manual',
      signal: AbortSignal.timeout(25000),
    });

    if (r.status >= 300 && r.status < 400 && r.headers.get('location')) {
      const next = new URL(r.headers.get('location'), u.href).href;
      res.writeHead(r.status === 301 || r.status === 308 ? 302 : r.status, { Location: P + encodeURIComponent(next) });
      return res.end();
    }

    r.headers.forEach((v, k) => { if (!DROP.has(k.toLowerCase())) res.setHeader(k, v); });
    res.status(r.status);

    const type = (r.headers.get('content-type') || '').toLowerCase();

    if (req.method === 'HEAD') return res.end();

    if (/text\/html|application\/xhtml/.test(type)) {
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      return res.send(rewriteHtml(await r.text(), u.href));
    }
    if (/text\/css/.test(type)) {
      res.setHeader('Content-Type', 'text/css; charset=utf-8');
      return res.send(rewriteCss(await r.text(), u.href));
    }
    return res.send(Buffer.from(await r.arrayBuffer()));
  } catch (err) {
    const msg = err && err.name === 'TimeoutError' ? 'The site took too long to respond.' : (err && err.message) || 'Something went wrong.';
    return errorPage(res, 502, msg);
  }
};

const crypto = require('node:crypto');

// If ACCESS_KEY is set in Vercel, the proxy only works for people who entered it.
function token() {
  return crypto.createHash('sha256').update('linkframe:' + process.env.ACCESS_KEY).digest('hex');
}

function parseCookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach((part) => {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  });
  return out;
}

function isLocked() {
  return Boolean(process.env.ACCESS_KEY);
}

function isAuthed(req) {
  if (!isLocked()) return true;
  return parseCookies(req).lf === token();
}

function keyMatches(input) {
  const a = crypto.createHash('sha256').update(String(input || '')).digest();
  const b = crypto.createHash('sha256').update(String(process.env.ACCESS_KEY || '')).digest();
  return crypto.timingSafeEqual(a, b);
}

module.exports = { token, isLocked, isAuthed, keyMatches };

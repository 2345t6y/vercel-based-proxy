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

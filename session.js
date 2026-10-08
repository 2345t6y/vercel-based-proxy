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

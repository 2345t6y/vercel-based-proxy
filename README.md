# Linkframe

Paste a link and it opens inside the page. A small serverless proxy on Vercel fetches the site, removes the headers that block embedding, and rewrites links so everything keeps loading through the proxy.

## Deploy

1. Put this folder in a GitHub repo (the files must be at the repo root: `index.html`, `api/`, `vercel.json`).
2. On vercel.com choose **Add New → Project**, import the repo, and press **Deploy**. No build settings needed.
3. Open your Vercel address and paste a link.

You can also run `npx vercel` inside this folder.

## Lock it (recommended)

An open proxy gets found and abused fast, and that can get your Vercel project suspended. In the Vercel project go to **Settings → Environment Variables**, add `ACCESS_KEY` with a password, then redeploy. Visitors will be asked for the key once.

## What works and what doesn't

Works well: most static sites, simple browser games, search pages, documentation, forums.

Limited or broken:
- **Anything that needs WebSockets** (live chat, Discord, WhatsApp Web, most multiplayer games). Vercel functions can't relay them.
- **Logins.** Cookies are not forwarded, so you can't stay signed in.
- **Large or streaming media.** Vercel caps a response at about 4.5 MB, so big files and video fail.
- **Sites with bot protection** (Cloudflare challenges and similar) may refuse Vercel's servers.
- **Heavy single-page apps** that build addresses from `location` in unusual ways.

For those, a full-featured rewriting proxy (Ultraviolet or Scramjet) on a host that allows long-running servers is the next step.

## Notes

- Pages you open run on your Vercel domain, so they share its browser storage. Only open sites you'd be comfortable running on that domain.
- Check Vercel's terms of use before running a public proxy. Keeping `ACCESS_KEY` set keeps it private.

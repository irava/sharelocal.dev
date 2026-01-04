# sharelocal

Expose a local web app running on localhost:<port> via a stable public HTTPS URL.

## Quickstart

```bash
npm i -g sharelocal.dev
```

Run (make sure your local web app is running first, e.g. on port 3000):

```bash
sharelocal 3000
```

This prints a public link under:

```bash
https://on.sharelocal.dev/p/<tunnelId>/?k=<sessionKey>
```

## Verification checklist

- Fresh install: run `sharelocal 3000` with no environment variables set.
- Output URL uses `https://on.sharelocal.dev/p/<tunnelId>/?k=<sessionKey>`.

## Troubleshooting

- Port in use / nothing running: make sure `http://localhost:<port>` works locally first.
- Firewalls: allow outbound HTTPS and WebSockets.
- “Can’t reach the sharelocal service”: the hosted backend may be down or blocked on your network.



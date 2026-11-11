# SOC web dashboard

React + Vite + TypeScript dashboard for the SOC API (see ../../docs/soc.md for the API).

## Run in development

1. Start the API (from the repository root), with a development database and secret:

   ```sh
   export IDPS_SOC_JWT_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
   export IDPS_SOC_DATABASE_URL=sqlite:///./dev-soc.db
   python scripts/dev_seed.py --i-understand-this-adds-demo-logins   # optional demo data
   uvicorn soc.api.main:app --port 8000
   ```

2. Start the dashboard (from this folder):

   ```sh
   npm install
   npm run dev                          # http://localhost:5173
   ```

   The dev server proxies `/api` (including the `/api/ws/alerts` live feed) to
   `http://127.0.0.1:8000`; set `IDPS_SOC_API` to point it elsewhere.

`scripts/dev_seed.py` lists the demo logins. They are for a local development database only.

## Pages

Alerts (live feed with filters) · Alert detail (flow, SHAP/LIME explanation chart, triage,
block request, add to case) · Actions (confirm or reject pending requests) · Blocks ·
Cases and case detail (notes, attached alerts) · Metrics · Admin (users, sensors, audit log).
The maps and the assistant chat arrive in weeks 12–14.

## Checks

```sh
npm test            # vitest
npm run typecheck   # tsc
npm run build       # production bundle in dist/
```

## Security notes

- The access token is kept in memory and sessionStorage (cleared when the tab closes), sent
  only in the Authorization header, and never put in a URL. The live feed sends it as the
  WebSocket's first message.
- API data is always rendered as text; the dashboard never uses `dangerouslySetInnerHTML`.
- In production, serve `dist/` from the same origin as the API behind HTTPS, with a
  Content-Security-Policy such as `default-src 'self'; connect-src 'self' wss:`.

# Run the app with Docker and ngrok

This runs the app on your PC and gives it a public ngrok URL. Your PC, Docker
Desktop, and ngrok must stay running while people use that URL. Postgres data is
kept in a Docker volume. The API and database are not published to the internet.

## 1. Start Docker Desktop

Open Docker Desktop and wait until it says the engine is running. In PowerShell,
from this repository folder, confirm it with:

```powershell
docker info
```

## 2. Create local secrets

Run this once from the repository folder. It creates a local ignored file; do
not commit or share it.

```powershell
node -e "const c=require('node:crypto'); console.log(['POSTGRES_PASSWORD='+c.randomBytes(24).toString('hex'),'JWT_SECRET='+c.randomBytes(48).toString('hex'),'MASTER_ENCRYPTION_KEY='+c.randomBytes(32).toString('base64'),'WEB_ORIGIN=http://localhost:3000'].join('\n'))" | Set-Content -Encoding ascii -NoNewline .env.docker
```

## 3. Build and start the containers

```powershell
docker compose --env-file .env.docker -f infra/docker-compose.yml up -d --build
```

Wait for the API migration and startup to finish, then open `http://localhost:3000`.
Check status with:

```powershell
docker compose --env-file .env.docker -f infra/docker-compose.yml ps
docker compose --env-file .env.docker -f infra/docker-compose.yml logs -f api
```

## 4. Start the public tunnel

In another PowerShell window:

```powershell
ngrok http 3000
```

Use the `https://...ngrok-free.app` forwarding URL printed by ngrok. If ngrok
asks you to connect an account, sign in at ngrok.com and copy the authtoken from
its dashboard. Enter it directly in PowerShell with `ngrok config add-authtoken
YOUR_TOKEN`; do not paste it into chat or commit it.

The free tunnel may show an ngrok browser interstitial the first time a visitor
opens the link. Keep the ngrok window running. Scans make real HTTP requests to
the targets you submit, so only scan systems you are authorized to test.

## Configure password-reset email

Password reset uses Resend. Verify a sender domain in Resend, create an API key,
and set these values in the ignored `.env.docker` file:

```text
RESEND_API_KEY=re_...
PASSWORD_RESET_EMAIL_FROM=security@your-verified-domain.example
PUBLIC_APP_URL=https://your-ngrok-domain.ngrok-free.dev
```

Recreate the API container after changing these settings:

```powershell
docker compose --env-file .env.docker -f infra/docker-compose.yml up -d --force-recreate api
```

Reset tokens are single-use, expire after 30 minutes, and are stored only as
SHA-256 hashes. Until email is configured, the reset form will explain that
recovery is unavailable on this deployment.

## Stop and resume

Press Ctrl+C in the ngrok window to close public access. Stop containers with:

```powershell
docker compose --env-file .env.docker -f infra/docker-compose.yml down
```

Start them again with the build command above. The database volume remains. To
delete the local database too, use `docker compose ... down -v` (this erases its
stored data).

The existing `render.yaml` deployment remains available for a future paid
Render deployment.

# Hacker Platform

This project is a web application security testing platform for authorized assessment work. It is built to help organize project scope, scan targets, and review findings.

## Main parts

- scanner-core: the scanning engine
- apps/api: backend API
- apps/web: web dashboard
- infra: local infrastructure setup

## Requirements

- Node.js 20+
- Docker

## Local setup

1. Install dependencies:

   npm install

2. Start the local database containers:

   docker compose -f infra/docker-compose.yml up -d

3. Configure the API environment:

   cp apps/api/.env.example apps/api/.env

4. Generate the Prisma client and apply the schema:

   cd apps/api
   npm run prisma:generate
   npm run prisma:migrate -- --name init
   cd ../..

5. Run the app:

   npm run build --workspace packages/scanner-core
   npm run dev --workspace apps/api
   npm run dev --workspace apps/web

## Notes

This is a security testing tool and should only be used on systems you are authorized to test.

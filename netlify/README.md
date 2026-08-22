# NOVA GPS - Netlify Deployment

This directory contains the Netlify Functions and Drizzle ORM schema for deploying NOVA GPS to Netlify's serverless platform.

## Architecture

The original serverful architecture (FastAPI, PostgreSQL, Kafka, Mosquitto) has been adapted for Netlify's serverless environment:

- **API Layer**: Netlify Functions (TypeScript) replacing FastAPI
- **Database**: Netlify Database (managed PostgreSQL) with Drizzle ORM
- **Real-time**: Polling-based updates (serverless-friendly alternative to WebSockets)
- **Frontend**: React SPA with hybrid consumer/developer view modes

## Setup

### 1. Install Dependencies

```bash
cd netlify
npm install
```

### 2. Configure Environment Variables

Set the following environment variables in Netlify:

- `DATABASE_URL` - PostgreSQL connection string (provided by Netlify Database)
- `SECRET_KEY` - JWT signing secret
- `JWT_ALGORITHM` - JWT algorithm (default: HS256)

### 3. Database Migration

Using Drizzle ORM with Netlify Database:

```bash
# Generate migrations
npx drizzle-kit generate

# Apply migrations
npx drizzle-kit migrate
```

## Functions

| Function | Endpoint | Description |
|----------|----------|-------------|
| `auth.ts` | `/api/auth` | JWT authentication and validation |
| `devices.ts` | `/api/devices` | Device registration and listing |
| `ingest.ts` | `/api/ingest` | Location ingestion (GPS device webhooks) |
| `consent.ts` | `/api/consent` | User consent management |

## Frontend Features

### Hybrid View Mode

- **Consumer View**: Clean map-focused interface for end users
- **Developer View**: Full terminal interface with all controls

### Responsive Design

- Mobile-friendly sidebar drawer
- Adaptive layout for different screen sizes
- Touch-friendly controls

### Form Validation

- Real-time email validation
- Required field checking
- Loading states and error feedback

## Deployment

1. Push to main branch
2. Netlify automatically builds and deploys
3. Functions are deployed to `/.netlify/functions/`
4. Frontend is served from `frontend/dist`

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `DATABASE_URL` | PostgreSQL connection string | Yes |
| `SECRET_KEY` | JWT signing secret | Yes |
| `JWT_ALGORITHM` | JWT algorithm | No (default: HS256) |
| `CORS_ORIGINS` | Allowed CORS origins | No |

## Production URL

https://novagps.com
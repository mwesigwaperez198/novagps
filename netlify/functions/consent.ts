import { Handler } from "@netlify/functions";
import { Pool } from "pg";

const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  throw new Error("DATABASE_URL environment variable must be set");
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false,
});

interface ConsentCreate {
  device_id: string;
  user_email: string;
  source: string;
  scope: string;
}

export const handler: Handler = async (event, _context) => {
  const headers = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Authorization, Content-Type",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  };

  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 200, headers };
  }

  if (event.httpMethod === "GET") {
    try {
      const result = await pool.query(
        "SELECT id, device_id, user_email, source, scope, status, consented_at, revoked_at FROM consents ORDER BY consented_at DESC"
      );

      return {
        statusCode: 200,
        headers,
        body: JSON.stringify(result.rows),
      };
    } catch (error) {
      console.error("Database error:", error);
      return {
        statusCode: 500,
        headers,
        body: JSON.stringify({ error: "Failed to fetch consents" }),
      };
    }
  }

  if (event.httpMethod === "POST") {
    try {
      const body: ConsentCreate = event.body ? JSON.parse(event.body) : {};

      if (!body.device_id || !body.user_email) {
        return {
          statusCode: 400,
          headers,
          body: JSON.stringify({ error: "Device ID and user email are required" }),
        };
      }

      const result = await pool.query(
        `INSERT INTO consents (device_id, user_email, source, scope)
         VALUES ($1, $2, $3, $4)
         RETURNING id, device_id, user_email, source, scope, status, consented_at, revoked_at`,
        [
          body.device_id,
          body.user_email,
          body.source || "web",
          body.scope || "live-location,history,alerts",
        ]
      );

      return {
        statusCode: 201,
        headers,
        body: JSON.stringify(result.rows[0]),
      };
    } catch (error) {
      console.error("Database error:", error);
      return {
        statusCode: 500,
        headers,
        body: JSON.stringify({ error: "Failed to create consent" }),
      };
    }
  }

  return {
    statusCode: 405,
    headers,
    body: JSON.stringify({ error: "Method not allowed" }),
  };
};
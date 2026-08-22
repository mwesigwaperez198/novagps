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

interface Device {
  id: string;
  name: string;
  email: string;
  phone: string;
  identifier: string;
  serial?: string;
  device_type: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

interface DeviceCreate {
  name: string;
  email: string;
  phone: string;
  identifier?: string;
  serial?: string;
  device_type?: string;
}

function getUserId(event: any): string | null {
  const authHeader = event.headers.authorization || event.headers.Authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return null;
  }
  return "demo-user-id"; // In production, decode JWT
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
        "SELECT id, name, email, phone, identifier, serial, device_type, is_active, created_at, updated_at FROM devices ORDER BY created_at DESC"
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
        body: JSON.stringify({ error: "Failed to fetch devices" }),
      };
    }
  }

  if (event.httpMethod === "POST") {
    const userId = getUserId(event);
    if (!userId) {
      return {
        statusCode: 401,
        headers,
        body: JSON.stringify({ error: "Authorization required" }),
      };
    }

    try {
      const body: DeviceCreate = event.body ? JSON.parse(event.body) : {};

      if (!body.name || !body.email || !body.phone) {
        return {
          statusCode: 400,
          headers,
          body: JSON.stringify({ error: "Name, email, and phone are required" }),
        };
      }

      const result = await pool.query(
        `INSERT INTO devices (name, email, phone, identifier, serial, device_type)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING id, name, email, phone, identifier, serial, device_type, is_active, created_at, updated_at`,
        [
          body.name,
          body.email,
          body.phone,
          body.identifier || `dev-${Date.now()}`,
          body.serial || null,
          body.device_type || "other",
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
        body: JSON.stringify({ error: "Failed to create device" }),
      };
    }
  }

  return {
    statusCode: 405,
    headers,
    body: JSON.stringify({ error: "Method not allowed" }),
  };
};
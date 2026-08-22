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

interface LocationUpdate {
  identifier: string;
  latitude: number;
  longitude: number;
  altitude?: number;
  speed?: number;
  heading?: number;
  accuracy?: number;
  source?: string;
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

  if (event.httpMethod === "POST") {
    try {
      const body: LocationUpdate = event.body ? JSON.parse(event.body) : {};

      if (!body.identifier || body.latitude === undefined || body.longitude === undefined) {
        return {
          statusCode: 400,
          headers,
          body: JSON.stringify({ error: "Identifier, latitude, and longitude are required" }),
        };
      }

      // Find device by identifier
      const deviceResult = await pool.query(
        "SELECT id FROM devices WHERE identifier = $1",
        [body.identifier]
      );

      if (deviceResult.rows.length === 0) {
        return {
          statusCode: 404,
          headers,
          body: JSON.stringify({ error: "Device not found" }),
        };
      }

      const deviceId = deviceResult.rows[0].id;

      // Insert location
      const result = await pool.query(
        `INSERT INTO locations (device_id, latitude, longitude, altitude, speed, heading, accuracy, source)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         RETURNING id, device_id, latitude, longitude, altitude, speed, heading, accuracy, source, recorded_at`,
        [
          deviceId,
          body.latitude,
          body.longitude,
          body.altitude || null,
          body.speed || null,
          body.heading || null,
          body.accuracy || null,
          body.source || "http",
        ]
      );

      return {
        statusCode: 201,
        headers,
        body: JSON.stringify({
          message: "Location updated",
          location: result.rows[0],
        }),
      };
    } catch (error) {
      console.error("Database error:", error);
      return {
        statusCode: 500,
        headers,
        body: JSON.stringify({ error: "Failed to update location" }),
      };
    }
  }

  return {
    statusCode: 405,
    headers,
    body: JSON.stringify({ error: "Method not allowed" }),
  };
};
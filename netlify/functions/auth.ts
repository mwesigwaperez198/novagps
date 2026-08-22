import { Handler } from "@netlify/functions";
import jwt from "jsonwebtoken";

const JWT_SECRET = process.env.SECRET_KEY || process.env.JWT_SECRET;
const JWT_ALGORITHM = process.env.JWT_ALGORITHM || "HS256";

if (!JWT_SECRET) {
  throw new Error("SECRET_KEY or JWT_SECRET environment variable must be set");
}

interface LoginRequest {
  email: string;
  password: string;
}

interface AuthResponse {
  token: string;
  user?: {
    email: string;
    role: string;
  };
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
      const body: LoginRequest = event.body ? JSON.parse(event.body) : {};

      if (!body.email || !body.password) {
        return {
          statusCode: 400,
          headers,
          body: JSON.stringify({ error: "Email and password required" }),
        };
      }

      // In production, verify against database
      // For now, create a demo token
      const token = jwt.sign(
        { email: body.email, role: "admin", sub: "demo-user-id" },
        JWT_SECRET,
        { expiresIn: "24h", algorithm: JWT_ALGORITHM as jwt.Algorithm }
      );

      const response: AuthResponse = {
        token,
        user: { email: body.email, role: "admin" },
      };

      return {
        statusCode: 200,
        headers,
        body: JSON.stringify(response),
      };
    } catch (error) {
      return {
        statusCode: 401,
        headers,
        body: JSON.stringify({ error: "Invalid credentials" }),
      };
    }
  }

  if (event.httpMethod === "GET") {
    const authHeader = event.headers.authorization || event.headers.Authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return {
        statusCode: 401,
        headers,
        body: JSON.stringify({ error: "Authorization header required" }),
      };
    }

    const token = authHeader.substring(7);

    try {
      const decoded = jwt.verify(token, JWT_SECRET, {
        algorithms: [JWT_ALGORITHM as jwt.Algorithm],
      });

      return {
        statusCode: 200,
        headers,
        body: JSON.stringify({ valid: true, user: decoded }),
      };
    } catch (error) {
      return {
        statusCode: 401,
        headers,
        body: JSON.stringify({ error: "Invalid or expired token" }),
      };
    }
  }

  return {
    statusCode: 405,
    headers,
    body: JSON.stringify({ error: "Method not allowed" }),
  };
};
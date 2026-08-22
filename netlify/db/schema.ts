import { integer } from "drizzle-orm/pg-core";
import { pgTable, text, timestamp, real, boolean, json, index } from "drizzle-orm/pg-core";
import { createInsertSchema, createSelectSchema } from "drizzle-zod";
import { z } from "zod";

// Device table
export const devices = pgTable(
  "devices",
  {
    id: text("id").primaryKey().$defaultFn(() => crypto.randomUUID()),
    name: text("name").notNull(),
    email: text("email").notNull(),
    phone: text("phone").notNull(),
    identifier: text("identifier").notNull().unique(),
    serial: text("serial"),
    deviceType: text("device_type", { enum: ["vehicle", "motorcycle", "phone", "laptop", "other"] }).notNull().default("other"),
    isActive: boolean("is_active").notNull().default(true),
    createdAt: timestamp("created_at").notNull().defaultNow(),
    updatedAt: timestamp("updated_at").notNull().defaultNow(),
  },
  (table) => ({
    emailIdx: index("ix_devices_email").on(table.email),
    identifierIdx: index("ix_devices_identifier").on(table.identifier),
  })
);

// Location table
export const locations = pgTable(
  "locations",
  {
    id: text("id").primaryKey().$defaultFn(() => crypto.randomUUID()),
    deviceId: text("device_id").notNull().references(() => devices.id, { onDelete: "cascade" }),
    latitude: real("latitude").notNull(),
    longitude: real("longitude").notNull(),
    altitude: real("altitude"),
    speed: real("speed"),
    heading: real("heading"),
    accuracy: real("accuracy"),
    source: text("source").notNull().default("http"),
    geom: text("geom"),
    recordedAt: timestamp("recorded_at").notNull().defaultNow(),
    receivedAt: timestamp("received_at").notNull().defaultNow(),
    rawPayload: json("raw_payload").$type<Record<string, unknown> | null>(),
  },
  (table) => ({
    deviceRecordedIdx: index("ix_locations_device_recorded_at").on(table.deviceId, table.recordedAt),
    receivedIdx: index("ix_locations_received_at").on(table.receivedAt),
  })
);

// Consent table
export const consents = pgTable(
  "consents",
  {
    id: text("id").primaryKey().$defaultFn(() => crypto.randomUUID()),
    deviceId: text("device_id").notNull().references(() => devices.id, { onDelete: "cascade" }),
    userEmail: text("user_email").notNull(),
    source: text("source").notNull(),
    scope: text("scope").notNull(),
    status: text("status", { enum: ["active", "revoked", "deleted"] }).notNull().default("active"),
    consentedAt: timestamp("consented_at").notNull().defaultNow(),
    revokedAt: timestamp("revoked_at"),
    proofHash: text("proof_hash"),
  },
  (table) => ({
    deviceStatusIdx: index("ix_consents_device_status").on(table.deviceId, table.status),
  })
);

// Audit log table
export const auditLogs = pgTable(
  "audit_logs",
  {
    id: text("id").primaryKey().$defaultFn(() => crypto.randomUUID()),
    actor: text("actor").notNull(),
    role: text("role").notNull(),
    action: text("action").notNull(),
    commandId: text("command_id"),
    argsHash: text("args_hash"),
    outputHash: text("output_hash"),
    exitCode: integer("exit_code"),
    startedAt: timestamp("started_at"),
    endedAt: timestamp("ended_at"),
    metadataJson: json("metadata_json").$type<Record<string, unknown> | null>(),
    createdAt: timestamp("created_at").notNull().defaultNow(),
  },
  (table) => ({
    actionIdx: index("ix_audit_logs_action").on(table.action),
  })
);

// Zod schemas for validation
export const deviceInsertSchema = createInsertSchema(devices);
export const deviceSelectSchema = createSelectSchema(devices);
export const locationInsertSchema = createInsertSchema(locations);
export const locationSelectSchema = createSelectSchema(locations);
export const consentInsertSchema = createInsertSchema(consents);
export const consentSelectSchema = createSelectSchema(consents);

// Types
export type Device = typeof devices.$inferSelect;
export type NewDevice = typeof devices.$inferInsert;
export type Location = typeof locations.$inferSelect;
export type NewLocation = typeof locations.$inferInsert;
export type Consent = typeof consents.$inferSelect;
export type NewConsent = typeof consents.$inferInsert;
import { pgTable, serial, text, timestamp, varchar, integer, jsonb } from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';

// 1. SOC Users & RBAC
export const users = pgTable('users', {
  id: serial('id').primaryKey(),
  uid: text('uid').notNull().unique(), // Firebase Auth UID
  email: text('email').notNull(),
  name: text('name'),
  role: text('role').notNull().default('analyst'), // 'admin' | 'analyst' | 'auditor'
  createdAt: timestamp('created_at').defaultNow(),
  lastLoginAt: timestamp('last_login_at'),
});

// 2. Real SIEM Security Logs
export const securityLogs = pgTable('security_logs', {
  id: varchar('id', { length: 64 }).primaryKey(),
  timestamp: timestamp('timestamp').notNull().defaultNow(),
  sourceType: varchar('source_type', { length: 64 }).notNull(), // WinEventLog:Security, Linux:Syslog, AWS:CloudTrail, etc.
  host: varchar('host', { length: 128 }).notNull(),
  user: varchar('user', { length: 128 }),
  eventId: integer('event_id'),
  severity: varchar('severity', { length: 24 }).notNull().default('low'), // critical, high, medium, low, info
  action: varchar('action', { length: 64 }),
  srcIp: varchar('src_ip', { length: 64 }),
  destIp: varchar('dest_ip', { length: 64 }),
  processName: varchar('process_name', { length: 256 }),
  commandLine: text('command_line'),
  message: text('message').notNull(),
  raw: text('raw').notNull(),
  tags: jsonb('tags').$type<string[]>(),
  clusterId: varchar('cluster_id', { length: 64 }),
  anomalyScore: integer('anomaly_score'),
  createdAt: timestamp('created_at').defaultNow(),
});

// 3. Security Incidents & Alerts
export const securityAlerts = pgTable('security_alerts', {
  id: varchar('id', { length: 64 }).primaryKey(),
  title: text('title').notNull(),
  severity: varchar('severity', { length: 24 }).notNull().default('medium'),
  status: varchar('status', { length: 32 }).notNull().default('new'), // new, investigating, contained, remediated, false_positive
  source: varchar('source', { length: 64 }).notNull(),
  host: varchar('host', { length: 128 }),
  user: varchar('user', { length: 128 }),
  mitreTactic: varchar('mitre_tactic', { length: 64 }).notNull(),
  mitreTechniqueId: varchar('mitre_technique_id', { length: 32 }).notNull(),
  mitreTechniqueName: text('mitre_technique_name').notNull(),
  d3fendCountermeasure: text('d3fend_countermeasure'),
  confidenceScore: integer('confidence_score').default(85),
  relatedLogIds: jsonb('related_log_ids').$type<string[]>(),
  aiAnalysis: jsonb('ai_analysis'),
  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow(),
});

// 4. Incident Response Actions & Containment (Sophos / Shuffle / Script)
export const incidentActions = pgTable('incident_actions', {
  id: serial('id').primaryKey(),
  alertId: varchar('alert_id', { length: 64 }),
  actionType: varchar('action_type', { length: 64 }).notNull(), // isolate_host, unisolate_host, kill_process, block_ip, trigger_shuffle_playbook
  target: varchar('target', { length: 256 }).notNull(),
  requestedBy: varchar('requested_by', { length: 128 }).notNull(),
  approvedBy: varchar('approved_by', { length: 128 }),
  status: varchar('status', { length: 32 }).notNull().default('completed'), // pending_approval, in_progress, completed, failed, rejected
  platform: varchar('platform', { length: 32 }).notNull().default('simulated'), // sophos, shuffle, simulated
  executionResult: jsonb('execution_result'),
  notes: text('notes'),
  createdAt: timestamp('created_at').defaultNow(),
  completedAt: timestamp('completed_at'),
});

// 5. SOC Audit Logs
export const auditLogs = pgTable('audit_logs', {
  id: serial('id').primaryKey(),
  userId: varchar('user_id', { length: 128 }),
  userEmail: varchar('user_email', { length: 128 }),
  action: varchar('action', { length: 128 }).notNull(),
  resourceType: varchar('resource_type', { length: 64 }).notNull(),
  resourceId: varchar('resource_id', { length: 128 }),
  details: jsonb('details'),
  ipAddress: varchar('ip_address', { length: 64 }),
  createdAt: timestamp('created_at').defaultNow(),
});

// 6. Real SIEM Connectors (Splunk HEC, Elastic, Sophos Central, Shuffle SOAR)
export const siemConnectors = pgTable('siem_connectors', {
  id: varchar('id', { length: 64 }).primaryKey(),
  name: varchar('name', { length: 128 }).notNull(),
  type: varchar('type', { length: 64 }).notNull(), // splunk_hec, elastic_search, sophos_central, shuffle_soar
  endpointUrl: text('endpoint_url'),
  status: varchar('status', { length: 32 }).notNull().default('connected'), // connected, disconnected, error
  lastSyncAt: timestamp('last_sync_at'),
  eventCount: integer('event_count').default(0),
  config: jsonb('config'),
  createdAt: timestamp('created_at').defaultNow(),
});

// 7. SOAR Playbook Execution Records
export const playbookExecutions = pgTable('playbook_executions', {
  id: serial('id').primaryKey(),
  playbookId: varchar('playbook_id', { length: 64 }).notNull(),
  playbookName: text('playbook_name').notNull(),
  triggeredBy: varchar('triggered_by', { length: 128 }).notNull(),
  alertId: varchar('alert_id', { length: 64 }),
  status: varchar('status', { length: 32 }).notNull().default('running'), // running, completed, failed
  steps: jsonb('steps'),
  outputPayload: jsonb('output_payload'),
  startedAt: timestamp('started_at').defaultNow(),
  finishedAt: timestamp('finished_at'),
});

// Relations
export const usersRelations = relations(users, ({ many }) => ({
  auditLogs: many(auditLogs),
}));

import { pgTable, serial, text, timestamp, varchar, integer, jsonb, boolean, doublePrecision } from 'drizzle-orm/pg-core';
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
  destPort: integer('dest_port'),
  processName: varchar('process_name', { length: 256 }),
  parentProcess: varchar('parent_process', { length: 256 }),
  commandLine: text('command_line'),
  fileHash: varchar('file_hash', { length: 128 }),
  message: text('message').notNull(),
  raw: text('raw').notNull(),
  tags: jsonb('tags').$type<string[]>(),
  entropy: doublePrecision('entropy'),
  clusterId: varchar('cluster_id', { length: 64 }),
  anomalyScore: integer('anomaly_score'),
  createdAt: timestamp('created_at').defaultNow(),
});

// 3. Security Incidents & Alerts
export const securityAlerts = pgTable('security_alerts', {
  id: varchar('id', { length: 64 }).primaryKey(),
  title: text('title').notNull(),
  description: text('description'),
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
  iocs: jsonb('iocs').$type<{ type: 'ip' | 'domain' | 'sha256' | 'url' | 'user'; value: string; threatScore: number }[]>(),
  playbookId: varchar('playbook_id', { length: 64 }),
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

// 8. Enterprise XDR Endpoints
export const endpoints = pgTable('endpoints', {
  id: varchar('id', { length: 64 }).primaryKey(),
  hostname: varchar('hostname', { length: 128 }).notNull().unique(),
  ip: varchar('ip', { length: 64 }).notNull(),
  os: varchar('os', { length: 128 }).notNull(),
  agentVersion: varchar('agent_version', { length: 128 }).notNull(),
  status: varchar('status', { length: 32 }).notNull().default('online'), // online, isolated, compromised, offline
  lastHeartbeat: varchar('last_heartbeat', { length: 64 }).notNull(),
  riskScore: integer('risk_score').notNull().default(0),
  activeAlertsCount: integer('active_alerts_count').notNull().default(0),
  user: varchar('user', { length: 128 }).notNull(),
  installedEfs: boolean('installed_efs').notNull().default(false),
  tamperProtection: boolean('tamper_protection').notNull().default(true),
  updatedAt: timestamp('updated_at').defaultNow(),
});

// 9. Local Threat Intelligence Catalog
export const threatIntel = pgTable('threat_intel', {
  id: varchar('id', { length: 64 }).primaryKey(),
  indicator: text('indicator').notNull().unique(),
  type: varchar('type', { length: 24 }).notNull(), // ip, domain, sha256, cve
  threatName: text('threat_name').notNull(),
  feedSource: varchar('feed_source', { length: 64 }).notNull(),
  reputationScore: integer('reputation_score').notNull(),
  confidence: integer('confidence').notNull(),
  associatedThreatActor: text('associated_threat_actor').notNull(),
  geolocation: text('geolocation'),
  tags: jsonb('tags').$type<string[]>().notNull(),
  firstSeen: varchar('first_seen', { length: 64 }).notNull(),
  lastSeen: varchar('last_seen', { length: 64 }).notNull(),
  activeCampaign: text('active_campaign'),
});

// 10. MITRE ATT&CK & D3FEND Techniques Matrix
export const mitreTechniques = pgTable('mitre_techniques', {
  id: varchar('id', { length: 32 }).primaryKey(),
  name: text('name').notNull(),
  tacticId: varchar('tactic_id', { length: 32 }).notNull(),
  tacticName: varchar('tactic_name', { length: 64 }).notNull(),
  description: text('description').notNull(),
  detectedCount: integer('detected_count').notNull().default(0),
  coveredByRules: boolean('covered_by_rules').notNull().default(true),
  d3fendTechniqueId: varchar('d3fend_technique_id', { length: 32 }).notNull(),
  d3fendTechniqueName: text('d3fend_technique_name').notNull(),
  d3fendCategory: varchar('d3fend_category', { length: 32 }).notNull(),
  gapStatus: varchar('gap_status', { length: 32 }).notNull(), // covered, active_threat_covered, uncovered_gap
});

// 11. SOAR Playbooks Catalog
export const soarPlaybooks = pgTable('soar_playbooks', {
  id: varchar('id', { length: 64 }).primaryKey(),
  name: text('name').notNull(),
  description: text('description').notNull(),
  triggerEvent: text('trigger_event').notNull(),
  targetThreat: text('target_threat').notNull(),
  executionCount: integer('execution_count').notNull().default(0),
  avgDurationSec: doublePrecision('avg_duration_sec').notNull().default(3.0),
  steps: jsonb('steps').$type<any[]>().notNull(),
  status: varchar('status', { length: 32 }).notNull().default('idle'),
  createdAt: timestamp('created_at').defaultNow(),
});

// 12. UEBA Behavioral Risk Profiles
export const uebaProfiles = pgTable('ueba_profiles', {
  username: varchar('username', { length: 128 }).primaryKey(),
  department: varchar('department', { length: 128 }).notNull(),
  riskScore: integer('risk_score').notNull().default(0),
  anomalyIndicators: jsonb('anomaly_indicators').$type<string[]>().notNull(),
  failedLoginsToday: integer('failed_logins_today').notNull().default(0),
  unusualHoursActivity: boolean('unusual_hours_activity').notNull().default(false),
  highVolumeDataTransfer: boolean('high_volume_data_transfer').notNull().default(false),
  lastActivity: varchar('last_activity', { length: 64 }).notNull(),
});

// 13. Enterprise Attack Simulation Scenarios
export const attackScenarios = pgTable('attack_scenarios', {
  id: varchar('id', { length: 64 }).primaryKey(),
  name: text('name').notNull(),
  adversary: text('adversary').notNull(),
  severity: varchar('severity', { length: 24 }).notNull(),
  description: text('description').notNull(),
  attackChainSteps: jsonb('attack_chain_steps').$type<any[]>().notNull(),
  mitreCoverage: jsonb('mitre_coverage').$type<string[]>().notNull(),
  recommendedPlaybookId: varchar('recommended_playbook_id', { length: 64 }).notNull(),
});

// Relations
export const usersRelations = relations(users, ({ many }) => ({
  auditLogs: many(auditLogs),
}));

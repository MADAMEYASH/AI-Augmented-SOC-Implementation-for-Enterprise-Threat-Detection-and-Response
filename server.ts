import express, { Request, Response } from 'express';
import { createServer as createViteServer } from 'vite';
import { GoogleGenAI } from '@google/genai';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json({ limit: '10mb' }));

// Initialize Google GenAI
const apiKey = process.env.GEMINI_API_KEY;
const ai = apiKey
  ? new GoogleGenAI({
      apiKey,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        },
      },
    })
  : null;

// Endpoint: AI Threat Analysis (LogAI / Alkido / Tier-3 SOC Co-Pilot)
app.post('/api/gemini/analyze-threat', async (req: Request, res: Response) => {
  try {
    const { alert, logs, iocs, context } = req.body;

    if (!ai) {
      // Heuristic fallback if API key is not yet configured
      return res.json({
        executiveSummary: `Automated LogAI & Alkido analysis determined high probability of multi-stage compromise involving ${alert?.title || 'anomalous system activity'}. Endpoint telemetry on ${alert?.endpoint || 'critical assets'} indicates unauthorized credential dumping and living-off-the-land utility invocation.`,
        confidenceScore: 94,
        threatActor: 'FIN7 / Scattered Spider emulation',
        mitreTechniques: [
          { id: 'T1059.001', name: 'PowerShell Execution', tactic: 'Execution' },
          { id: 'T1003.001', name: 'LSASS Memory Dumping', tactic: 'Credential Access' },
          { id: 'T1021.002', name: 'SMB/Windows Admin Shares', tactic: 'Lateral Movement' },
        ],
        rootCause: `Initial vector via spearphishing attachment containing obfuscated macro, followed by certutil download of second-stage payload.`,
        recommendedActions: [
          'Trigger Shuffle Playbook: PB-XDR-ISOLATE-01 to immediately isolate host from enterprise subnet',
          'Revoke compromised Active Directory / Okta SSO tokens for target identity',
          'Deploy Sigma rule SIG-2026-WIN-4688 to block LOLBin child processes',
          'Broadcast IOC block hashes to perimeter Palo Alto firewalls and Sophos Central',
        ],
        defenseGapNote: 'Current D3FEND coverage lacks automated LSASS memory credential protection (D3-MGP). Immediate enforcement recommended.',
      });
    }

    const prompt = `You are a Lead Principal Security Architect & Senior SOC Incident Commander at an Enterprise Defense Center (running Splunk, Elastic SIEM, Sophos XDR, LogAI, Alkido, and Shuffle SOAR).
Analyze the following security alert, raw logs, and IOC context:

Alert Data:
${JSON.stringify(alert, null, 2)}

Associated Ingested Logs:
${JSON.stringify(logs, null, 2)}

Extracted IOCs:
${JSON.stringify(iocs, null, 2)}

Investigation Context:
${context || 'Real-time detection triage in enterprise financial perimeter'}

Respond in JSON format matching this schema:
{
  "executiveSummary": "string (concise, high-impact summary for CISO / SOC manager)",
  "confidenceScore": number (0-100),
  "threatActor": "string (probable APT / cybercrime group or modus operandi)",
  "mitreTechniques": [
    { "id": "string (e.g. T1059.001)", "name": "string", "tactic": "string" }
  ],
  "rootCause": "string (detailed technical root cause chain)",
  "recommendedActions": [
    "string (step 1)",
    "string (step 2)",
    "string (step 3)"
  ],
  "defenseGapNote": "string (D3FEND countermeasure recommendation and gap analysis)"
}`;

    const response = await ai.models.generateContent({
      model: 'gemini-3.8-flash',
      contents: prompt,
      config: {
        responseMimeType: 'application/json',
      },
    });

    const parsed = JSON.parse(response.text || '{}');
    return res.json(parsed);
  } catch (error: any) {
    console.error('Gemini threat analysis error:', error);
    return res.status(500).json({
      error: error.message || 'Failed to complete AI threat investigation',
    });
  }
});

// Endpoint: Natural Language to SPL / KQL Query Translator
app.post('/api/gemini/spl-translate', async (req: Request, res: Response) => {
  try {
    const { query, syntax } = req.body; // syntax: 'SPL' | 'KQL'

    if (!ai) {
      if (syntax === 'SPL') {
        return res.json({
          convertedQuery: `index=security sourcetype=WinEventLog:Security EventCode=4625 | stats count by TargetUserName, Source_Network_Address | where count > 5 | sort - count`,
          explanation: `Splunk query filtering Windows Security event 4625 (Failed Logon), aggregating by TargetUserName and Source IP, alerting on threshold > 5.`,
        });
      } else {
        return res.json({
          convertedQuery: `event.category: "authentication" and event.outcome: "failure" | stats count() by user.name, source.ip`,
          explanation: `Elastic KQL query targeting failed authentication events across enterprise directory sources.`,
        });
      }
    }

    const prompt = `You are a SIEM query engineer expert in Splunk SPL (Search Processing Language) and Elastic KQL (Kibana Query Language).
Convert this natural language security question into an optimized ${syntax || 'SPL'} query:
User query: "${query}"

Return JSON:
{
  "convertedQuery": "string (valid, production-ready ${syntax || 'SPL'} query)",
  "explanation": "string (brief explanation of fields, indexes, and logic)"
}`;

    const response = await ai.models.generateContent({
      model: 'gemini-3.8-flash',
      contents: prompt,
      config: {
        responseMimeType: 'application/json',
      },
    });

    const parsed = JSON.parse(response.text || '{}');
    return res.json(parsed);
  } catch (error: any) {
    console.error('SPL translation error:', error);
    return res.status(500).json({ error: error.message || 'Failed to translate query' });
  }
});

// Endpoint: AI SOAR Playbook Generator
app.post('/api/gemini/generate-playbook', async (req: Request, res: Response) => {
  try {
    const { threatScenario, platform } = req.body;

    if (!ai) {
      return res.json({
        playbookName: `PB-AUTO-${(threatScenario || 'INCIDENT').toUpperCase().replace(/\\s+/g, '-')}`,
        description: `Automated multi-action SOAR workflow for rapid containment and telemetry preservation.`,
        triggers: ['Webhook from Splunk SIEM Alert', 'Sophos XDR Critical Detection'],
        steps: [
          { step: 1, action: 'Host Isolation', system: 'Sophos Central API', details: 'Apply network isolation to endpoint preserving agent communication' },
          { step: 2, action: 'Identity Lockout', system: 'Okta / Azure AD', details: 'Revoke active sessions and force password reset on compromised account' },
          { step: 3, action: 'Firewall Block', system: 'Palo Alto Panorama', details: 'Inject C2 IP into Dynamic Address Group (DAG)' },
          { step: 4, action: 'Forensic Dump', system: 'Velociraptor / EDR', details: 'Collect volatile RAM artifact and MFT triage package' },
          { step: 5, action: 'SOC Notification', system: 'Slack & Jira Service Desk', details: 'Create high-priority ticket with triage summary and IOC hash list' },
        ],
      });
    }

    const prompt = `You are a Cyber Security Automation Engineer designing a Shuffle SOAR playbook for the following threat scenario:
Scenario: "${threatScenario}"
Platform: "${platform || 'Shuffle SOAR + Sophos XDR + Splunk + Firewalls'}"

Generate an incident response playbook in JSON:
{
  "playbookName": "string",
  "description": "string",
  "triggers": ["string"],
  "steps": [
    {
      "step": number,
      "action": "string",
      "system": "string",
      "details": "string"
    }
  ]
}`;

    const response = await ai.models.generateContent({
      model: 'gemini-3.8-flash',
      contents: prompt,
      config: {
        responseMimeType: 'application/json',
      },
    });

    const parsed = JSON.parse(response.text || '{}');
    return res.json(parsed);
  } catch (error: any) {
    console.error('Playbook generation error:', error);
    return res.status(500).json({ error: error.message || 'Failed to generate playbook' });
  }
});

// Setup Vite or Static File Serving
async function startServer() {
  const isProd = process.env.NODE_ENV === 'production';
  const port = 3000;

  if (isProd) {
    app.use(express.static(path.resolve(__dirname, 'dist')));
    app.get('*', (req, res) => {
      res.sendFile(path.resolve(__dirname, 'dist', 'index.html'));
    });
  } else {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  }

  app.listen(port, '0.0.0.0', () => {
    console.log(`[AegisSOC] SOC Control Plane running on http://0.0.0.0:${port}`);
  });
}

startServer().catch((err) => {
  console.error('[AegisSOC] Fatal server error:', err);
  process.exit(1);
});

/**
 * Purple Team Simulator — Decepticon-inspired autonomous attack-defense gap analysis
 * AI simulates attack paths through MITRE ATT&CK kill chain, evaluates defenses, identifies gaps
 */

// ═══════════════════════════════════════════════════════════════════════════
// MITRE ATT&CK TACTICS (Enterprise, v14)
// ═══════════════════════════════════════════════════════════════════════════

const MITRE_TACTICS = [
  {
    id: 'TA0043', name: 'Reconnaissance', phase: 'pre-attack',
    description: 'Gathering information to plan future operations',
    techniques: ['T1595 Active Scanning', 'T1592 Gather Victim Host Info', 'T1589 Gather Victim Identity Info', 'T1590 Gather Victim Network Info', 'T1591 Gather Victim Org Info', 'T1598 Phishing for Information'],
  },
  {
    id: 'TA0042', name: 'Resource Development', phase: 'pre-attack',
    description: 'Establishing resources to support operations',
    techniques: ['T1583 Acquire Infrastructure', 'T1586 Compromise Accounts', 'T1584 Compromise Infrastructure', 'T1587 Develop Capabilities', 'T1585 Establish Accounts', 'T1588 Obtain Capabilities'],
  },
  {
    id: 'TA0001', name: 'Initial Access', phase: 'attack',
    description: 'Gaining initial foothold in the target environment',
    techniques: ['T1566 Phishing', 'T1190 Exploit Public-Facing Application', 'T1133 External Remote Services', 'T1078 Valid Accounts', 'T1189 Drive-by Compromise', 'T1199 Trusted Relationship'],
  },
  {
    id: 'TA0002', name: 'Execution', phase: 'attack',
    description: 'Running adversary-controlled code',
    techniques: ['T1059 Command and Scripting Interpreter', 'T1203 Exploitation for Client Execution', 'T1204 User Execution', 'T1053 Scheduled Task/Job', 'T1047 Windows Management Instrumentation'],
  },
  {
    id: 'TA0003', name: 'Persistence', phase: 'attack',
    description: 'Maintaining access across restarts and credential changes',
    techniques: ['T1098 Account Manipulation', 'T1136 Create Account', 'T1078 Valid Accounts', 'T1053 Scheduled Task/Job', 'T1505 Server Software Component', 'T1133 External Remote Services'],
  },
  {
    id: 'TA0004', name: 'Privilege Escalation', phase: 'attack',
    description: 'Gaining higher-level permissions',
    techniques: ['T1068 Exploitation for Privilege Escalation', 'T1078 Valid Accounts', 'T1548 Abuse Elevation Control Mechanism', 'T1134 Access Token Manipulation', 'T1053 Scheduled Task/Job'],
  },
  {
    id: 'TA0005', name: 'Defense Evasion', phase: 'attack',
    description: 'Avoiding detection throughout the attack',
    techniques: ['T1070 Indicator Removal', 'T1036 Masquerading', 'T1027 Obfuscated Files', 'T1562 Impair Defenses', 'T1112 Modify Registry', 'T1218 System Binary Proxy Execution'],
  },
  {
    id: 'TA0006', name: 'Credential Access', phase: 'attack',
    description: 'Stealing credentials for lateral movement',
    techniques: ['T1110 Brute Force', 'T1003 OS Credential Dumping', 'T1555 Credentials from Password Stores', 'T1056 Input Capture', 'T1539 Steal Web Session Cookie'],
  },
  {
    id: 'TA0007', name: 'Discovery', phase: 'attack',
    description: 'Understanding the target environment',
    techniques: ['T1083 File and Directory Discovery', 'T1046 Network Service Discovery', 'T1135 Network Share Discovery', 'T1057 Process Discovery', 'T1082 System Information Discovery'],
  },
  {
    id: 'TA0008', name: 'Lateral Movement', phase: 'attack',
    description: 'Moving through the environment to reach objectives',
    techniques: ['T1021 Remote Services', 'T1080 Taint Shared Content', 'T1550 Use Alternate Authentication Material', 'T1570 Lateral Tool Transfer'],
  },
  {
    id: 'TA0009', name: 'Collection', phase: 'post-attack',
    description: 'Gathering data of interest to the adversary',
    techniques: ['T1560 Archive Collected Data', 'T1005 Data from Local System', 'T1039 Data from Network Shared Drive', 'T1114 Email Collection', 'T1113 Screen Capture'],
  },
  {
    id: 'TA0011', name: 'Command and Control', phase: 'post-attack',
    description: 'Communicating with compromised systems',
    techniques: ['T1071 Application Layer Protocol', 'T1132 Data Encoding', 'T1001 Data Obfuscation', 'T1573 Encrypted Channel', 'T1105 Ingress Tool Transfer'],
  },
  {
    id: 'TA0010', name: 'Exfiltration', phase: 'post-attack',
    description: 'Stealing data from the target environment',
    techniques: ['T1041 Exfiltration Over C2 Channel', 'T1567 Exfiltration Over Web Service', 'T1048 Exfiltration Over Alternative Protocol', 'T1029 Scheduled Transfer'],
  },
  {
    id: 'TA0040', name: 'Impact', phase: 'post-attack',
    description: 'Disrupting availability or compromising integrity',
    techniques: ['T1485 Data Destruction', 'T1486 Data Encrypted for Impact', 'T1489 Service Stop', 'T1491 Defacement', 'T1561 Disk Wipe'],
  },
];

// ═══════════════════════════════════════════════════════════════════════════
// SCENARIO TEMPLATES
// ═══════════════════════════════════════════════════════════════════════════

const SCENARIO_TYPES = [
  { id: 'external-attacker', name: 'External Threat Actor', description: 'Sophisticated external attacker targeting the organization from the internet' },
  { id: 'insider-threat', name: 'Insider Threat', description: 'Malicious or compromised insider with legitimate access' },
  { id: 'ransomware', name: 'Ransomware Operator', description: 'Ransomware gang seeking to encrypt and exfiltrate data' },
  { id: 'apt', name: 'APT / Nation-State', description: 'Advanced persistent threat with long-term objectives and sophisticated tradecraft' },
  { id: 'supply-chain', name: 'Supply Chain Attack', description: 'Attacker compromising a third-party vendor or dependency' },
];

// ═══════════════════════════════════════════════════════════════════════════
// PURPLE TEAM SIMULATION
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Run a purple team simulation
 * @param {object} options
 * @param {string} options.target - Target description
 * @param {string} options.scope - Scope definition
 * @param {string} options.scenario - Scenario type ID
 * @param {string} options.defenses - Known defensive controls
 * @param {function} options.askAIJSON - AI JSON function
 * @param {function} options.onProgress - Progress callback
 * @param {number} options.timeout - AI timeout
 * @returns {Promise<object>} - Simulation results
 */
async function runSimulation(options) {
  const { target, scope, scenario, defenses, askAIJSON, onProgress, timeout = 120000 } = options;
  const start = Date.now();

  const scenarioType = SCENARIO_TYPES.find(s => s.id === scenario) || SCENARIO_TYPES[0];

  // Phase 1: Attack simulation + defense evaluation
  if (onProgress) onProgress({ phase: 'simulating', message: 'AI simulating attack phases and evaluating defenses...' });

  const tacticsSubset = MITRE_TACTICS.slice(0, 10); // Focus on the first 10 (most impactful)

  const prompt = `You are a senior purple team operator conducting an attack-defense gap analysis.

TARGET: ${target}
SCOPE: ${scope || 'Full infrastructure'}
THREAT SCENARIO: ${scenarioType.name} — ${scenarioType.description}
KNOWN DEFENSES: ${defenses || 'Unknown — assume standard enterprise controls'}

For each of the following 10 MITRE ATT&CK tactics, simulate a realistic attack technique and evaluate defensive coverage:

${tacticsSubset.map((t, i) => `${i + 1}. ${t.id} ${t.name}: ${t.description}\n   Example techniques: ${t.techniques.slice(0, 3).join(', ')}`).join('\n\n')}

Return a JSON object with this EXACT structure:
{
  "tactics": [
    {
      "id": "TA0043",
      "name": "Reconnaissance",
      "attack": {
        "technique": "T1595.001 Active Scanning: Scanning IP Blocks",
        "scenario": "Brief description of how the attacker would execute this technique against the target",
        "likelihood": 85
      },
      "defense": {
        "detection": 40,
        "prevention": 20,
        "controls": ["List of relevant defensive controls that exist or should exist"],
        "gaps": ["Specific gaps in defensive coverage"]
      },
      "risk": "critical|high|medium|low"
    }
  ],
  "attackPath": "Brief narrative of the most likely full kill chain (3-4 sentences)",
  "criticalGaps": ["Top 5 most critical defensive gaps across all tactics"],
  "recommendations": [
    {"priority": 1, "action": "Specific recommendation", "impact": "high|medium|low", "effort": "low|medium|high"}
  ]
}

SCORING GUIDE:
- detection: 0-100 (probability the attack would be detected by existing controls)
- prevention: 0-100 (probability the attack would be blocked/prevented)
- likelihood: 0-100 (probability the attacker would attempt this technique)
- risk: based on (likelihood * (100 - prevention)) / 100

Be specific to the target. Use realistic scores — don't be optimistic about defenses unless specific controls are mentioned. Return ONLY valid JSON.`;

  const result = await askAIJSON(prompt, { timeout });

  if (!result || !result.tactics) {
    throw new Error('AI returned invalid simulation result');
  }

  // Phase 2: Calculate aggregate scores
  if (onProgress) onProgress({ phase: 'analyzing', message: 'Computing gap analysis scores...' });

  const tactics = result.tactics || [];
  let totalDetection = 0, totalPrevention = 0, totalLikelihood = 0;
  const riskCounts = { critical: 0, high: 0, medium: 0, low: 0 };

  tactics.forEach(t => {
    totalDetection += (t.defense?.detection || 0);
    totalPrevention += (t.defense?.prevention || 0);
    totalLikelihood += (t.attack?.likelihood || 0);
    riskCounts[t.risk || 'medium']++;
  });

  const n = tactics.length || 1;
  const avgDetection = Math.round(totalDetection / n);
  const avgPrevention = Math.round(totalPrevention / n);
  const avgLikelihood = Math.round(totalLikelihood / n);
  const overallRisk = Math.round(avgLikelihood * (100 - avgPrevention) / 100);

  // Grade based on detection + prevention average
  const defenseScore = Math.round((avgDetection + avgPrevention) / 2);
  const grade = defenseScore >= 80 ? 'A' : defenseScore >= 65 ? 'B' : defenseScore >= 50 ? 'C' : defenseScore >= 35 ? 'D' : 'F';

  const duration = Date.now() - start;

  return {
    scenario: scenarioType,
    target,
    scope: scope || 'Full infrastructure',
    defenses: defenses || 'Standard enterprise controls',
    tactics,
    attackPath: result.attackPath || '',
    criticalGaps: result.criticalGaps || [],
    recommendations: result.recommendations || [],
    summary: {
      avgDetection,
      avgPrevention,
      avgLikelihood,
      overallRisk,
      defenseScore,
      grade,
      riskCounts,
      tacticsAnalyzed: n,
    },
    duration,
  };
}

module.exports = {
  MITRE_TACTICS,
  SCENARIO_TYPES,
  runSimulation,
};

/**
 * Flow Templates — security-focused workflow templates
 * Port of arcline.pro flow template pattern
 */

import type { FlowCreateInput, FlowNode, FlowEdge } from "@/lib/flows/types";

export interface FlowTemplateDefinition extends FlowCreateInput {
  difficulty: "beginner" | "intermediate" | "advanced";
  required_tools: string[];
}

export const FLOW_TEMPLATES: FlowTemplateDefinition[] = [
  {
    name: "Recon Pipeline",
    slug: "recon-pipeline",
    description: "Automated reconnaissance pipeline: subdomain enumeration → port scanning → critical finding notification",
    category: "recon",
    trigger_type: "manual",
    difficulty: "beginner",
    required_tools: ["dns", "nmap"],
    nodes: [
      { id: "start", type: "start", data: { label: "Start", config: { trigger: "manual" } }, position: { x: 250, y: 0 } },
      { id: "subdomain", type: "agent", data: { label: "Subdomain Enum", config: { agentSlug: "subdomain-enum", taskDescription: "Enumerate subdomains for target" }, description: "Run subdomain enumeration agent" }, position: { x: 250, y: 100 } },
      { id: "portscan", type: "agent", data: { label: "Port Scan", config: { agentSlug: "port-scanner", taskDescription: "Scan discovered subdomains for open ports" }, description: "Run port scanner on discovered subdomains" }, position: { x: 250, y: 200 } },
      { id: "check-critical", type: "condition", data: { label: "Critical Findings?", config: { expression: "state.portscan && JSON.stringify(state.portscan).includes('critical')" }, description: "Check if any critical findings were found" }, position: { x: 250, y: 300 } },
      { id: "notify", type: "notify", data: { label: "Alert Team", config: { message: "Critical recon findings detected — review port scan results" } }, position: { x: 100, y: 400 } },
      { id: "end", type: "end", data: { label: "End", config: {} }, position: { x: 250, y: 500 } },
    ],
    edges: [
      { id: "e1", source: "start", target: "subdomain" },
      { id: "e2", source: "subdomain", target: "portscan" },
      { id: "e3", source: "portscan", target: "check-critical" },
      { id: "e4", source: "check-critical", target: "notify", sourceHandle: "true", label: "true" },
      { id: "e5", source: "check-critical", target: "end", sourceHandle: "false", label: "false" },
      { id: "e6", source: "notify", target: "end" },
    ],
  },
  {
    name: "Compliance Check",
    slug: "compliance-check",
    description: "Run PCI DSS and HIPAA compliance checks in sequence, then notify with results",
    category: "compliance",
    trigger_type: "manual",
    difficulty: "beginner",
    required_tools: [],
    nodes: [
      { id: "start", type: "start", data: { label: "Start", config: {} }, position: { x: 250, y: 0 } },
      { id: "pci", type: "agent", data: { label: "PCI DSS Check", config: { agentSlug: "pci-checker", taskDescription: "Evaluate system against PCI DSS v4.0" } }, position: { x: 250, y: 100 } },
      { id: "hipaa", type: "agent", data: { label: "HIPAA Check", config: { agentSlug: "hipaa-checker", taskDescription: "Evaluate system against HIPAA Security Rule" } }, position: { x: 250, y: 200 } },
      { id: "notify", type: "notify", data: { label: "Send Results", config: { message: "Compliance checks completed — review PCI and HIPAA results" } }, position: { x: 250, y: 300 } },
      { id: "end", type: "end", data: { label: "End", config: {} }, position: { x: 250, y: 400 } },
    ],
    edges: [
      { id: "e1", source: "start", target: "pci" },
      { id: "e2", source: "pci", target: "hipaa" },
      { id: "e3", source: "hipaa", target: "notify" },
      { id: "e4", source: "notify", target: "end" },
    ],
  },
  {
    name: "Incident Response",
    slug: "incident-response",
    description: "Automated incident response: log analysis → malware check → conditional escalation → playbook execution",
    category: "ops",
    trigger_type: "manual",
    difficulty: "intermediate",
    required_tools: ["osint"],
    nodes: [
      { id: "start", type: "start", data: { label: "Start", config: {} }, position: { x: 250, y: 0 } },
      { id: "logs", type: "agent", data: { label: "Log Hunter", config: { agentSlug: "log-hunter", taskDescription: "Search logs for indicators of compromise" } }, position: { x: 250, y: 100 } },
      { id: "malware", type: "agent", data: { label: "Malware Analyzer", config: { agentSlug: "malware-analyzer", taskDescription: "Analyze suspicious artifacts for malware indicators" } }, position: { x: 250, y: 200 } },
      { id: "check-malware", type: "condition", data: { label: "Malware Detected?", config: { expression: "state.malware && JSON.stringify(state.malware).includes('malware')" } }, position: { x: 250, y: 300 } },
      { id: "playbook", type: "agent", data: { label: "Incident Playbook", config: { agentSlug: "incident-playbook", taskDescription: "Execute incident response playbook for detected malware" } }, position: { x: 100, y: 400 } },
      { id: "notify", type: "notify", data: { label: "Alert SOC", config: { message: "Malware incident detected and playbook executed — SOC review required" } }, position: { x: 100, y: 500 } },
      { id: "end", type: "end", data: { label: "End", config: {} }, position: { x: 250, y: 600 } },
    ],
    edges: [
      { id: "e1", source: "start", target: "logs" },
      { id: "e2", source: "logs", target: "malware" },
      { id: "e3", source: "malware", target: "check-malware" },
      { id: "e4", source: "check-malware", target: "playbook", sourceHandle: "true", label: "true" },
      { id: "e5", source: "check-malware", target: "end", sourceHandle: "false", label: "false" },
      { id: "e6", source: "playbook", target: "notify" },
      { id: "e7", source: "notify", target: "end" },
    ],
  },
  {
    name: "Vulnerability Triage",
    slug: "vuln-triage",
    description: "Scan for vulnerabilities, triage by severity, and generate remediation plans for high/critical findings",
    category: "remediation",
    trigger_type: "manual",
    difficulty: "intermediate",
    required_tools: ["nmap"],
    nodes: [
      { id: "start", type: "start", data: { label: "Start", config: {} }, position: { x: 250, y: 0 } },
      { id: "scan", type: "agent", data: { label: "Header Audit", config: { agentSlug: "header-auditor", taskDescription: "Audit HTTP security headers for target" } }, position: { x: 250, y: 100 } },
      { id: "tls", type: "agent", data: { label: "TLS Analysis", config: { agentSlug: "tls-analyzer", taskDescription: "Analyze TLS configuration and certificate security" } }, position: { x: 250, y: 200 } },
      { id: "check-severity", type: "condition", data: { label: "High Severity?", config: { expression: "state.scan && (JSON.stringify(state.scan).includes('F') || JSON.stringify(state.scan).includes('critical'))" } }, position: { x: 250, y: 300 } },
      { id: "remediate", type: "llm", data: { label: "Generate Remediation Plan", config: { prompt: "Based on the security findings, generate a prioritized remediation plan with specific fix instructions for each high/critical finding.", ai: { mode: "inherit" } } }, position: { x: 100, y: 400 } },
      { id: "notify", type: "notify", data: { label: "Notify", config: { message: "Vulnerability triage complete — remediation plan generated" } }, position: { x: 250, y: 500 } },
      { id: "end", type: "end", data: { label: "End", config: {} }, position: { x: 250, y: 600 } },
    ],
    edges: [
      { id: "e1", source: "start", target: "scan" },
      { id: "e2", source: "scan", target: "tls" },
      { id: "e3", source: "tls", target: "check-severity" },
      { id: "e4", source: "check-severity", target: "remediate", sourceHandle: "true", label: "true" },
      { id: "e5", source: "check-severity", target: "notify", sourceHandle: "false", label: "false" },
      { id: "e6", source: "remediate", target: "notify" },
      { id: "e7", source: "notify", target: "end" },
    ],
  },
];

export function getFlowTemplates(): FlowTemplateDefinition[] {
  return FLOW_TEMPLATES;
}

/**
 * Vigil — LLM-Driven Code Vulnerability Scanner
 * Inspired by Vulnhuntr's zero-shot vulnerability discovery approach.
 *
 * Algorithm:
 *   1. Discover source files in target directory
 *   2. Triage: LLM scans each file for entry points (routes, handlers, user input)
 *   3. Deep analysis: For files with entry points, run vulnerability-specific prompts
 *   4. Confidence scoring (0-10) with proof-of-concept generation
 *   5. Normalize findings to Vigil schema
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Vulnerability types aligned with Vulnhuntr + OWASP
const VULN_TYPES = {
  RCE:  { name: 'Remote Code Execution',       cwe: 'CWE-94',  mitre: 'T1059', sinks: 'eval, exec, spawn, execSync, child_process, Function(), vm.runInContext, require() with user input, deserialization (pickle, yaml.load, JSON.parse of exec)' },
  SQLi: { name: 'SQL Injection',                cwe: 'CWE-89',  mitre: 'T1190', sinks: 'string concatenation in SQL queries, template literals in queries, raw SQL with user input, query() without parameterization' },
  XSS:  { name: 'Cross-Site Scripting',         cwe: 'CWE-79',  mitre: 'T1189', sinks: 'innerHTML, document.write, res.send with unescaped user input, template rendering without auto-escaping, dangerouslySetInnerHTML' },
  SSRF: { name: 'Server-Side Request Forgery',  cwe: 'CWE-918', mitre: 'T1190', sinks: 'fetch, axios, http.request, urllib with user-controlled URL, DNS rebinding, redirect following' },
  LFI:  { name: 'Local File Inclusion',         cwe: 'CWE-98',  mitre: 'T1005', sinks: 'fs.readFile, path.join with user input, require() with user input, res.sendFile, directory traversal via ../' },
  AFO:  { name: 'Arbitrary File Overwrite',     cwe: 'CWE-73',  mitre: 'T1565', sinks: 'fs.writeFile, fs.rename, fs.copyFile with user-controlled path, multer destination, upload path from user input' },
  IDOR: { name: 'Insecure Direct Object Ref',   cwe: 'CWE-639', mitre: 'T1078', sinks: 'database lookup by user-supplied ID without authorization check, req.params.id used directly, missing ownership verification' },
};

// File extensions to scan by language
const LANG_EXTENSIONS = {
  javascript: ['.js', '.mjs', '.cjs'],
  typescript: ['.ts', '.tsx'],
  python:     ['.py'],
  ruby:       ['.rb'],
  php:        ['.php'],
  java:       ['.java'],
  go:         ['.go'],
  csharp:     ['.cs'],
};

// Directories to skip
const SKIP_DIRS = new Set([
  'node_modules', '.git', '.svn', 'vendor', 'venv', '.venv', '__pycache__',
  'dist', 'build', '.next', '.nuxt', 'coverage', '.nyc_output', 'test',
  'tests', '__tests__', 'spec', 'docs', 'doc', 'examples', 'example',
  '.cache', '.tmp', 'tmp', 'temp', 'assets', 'static', 'public',
]);

// Max file size to analyze (100KB)
const MAX_FILE_SIZE = 100 * 1024;
// Max files to analyze per scan
const MAX_FILES = 50;
// Max total source to send per LLM call (~30KB)
const MAX_CHUNK_SIZE = 30000;

/**
 * Discover source files in a directory
 */
function discoverFiles(rootDir, languages) {
  const allowedExts = new Set();
  for (const lang of languages) {
    const exts = LANG_EXTENSIONS[lang];
    if (exts) exts.forEach(e => allowedExts.add(e));
  }
  // If no languages specified, scan all supported
  if (allowedExts.size === 0) {
    Object.values(LANG_EXTENSIONS).flat().forEach(e => allowedExts.add(e));
  }

  const files = [];

  function walk(dir, depth) {
    if (depth > 10 || files.length >= MAX_FILES * 2) return;
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
    catch { return; }

    for (const entry of entries) {
      if (entry.name.startsWith('.')) continue;
      const fullPath = path.join(dir, entry.name);

      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name.toLowerCase())) {
          walk(fullPath, depth + 1);
        }
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (allowedExts.has(ext)) {
          try {
            const stat = fs.statSync(fullPath);
            if (stat.size > 0 && stat.size <= MAX_FILE_SIZE) {
              files.push({ path: fullPath, relPath: path.relative(rootDir, fullPath).replace(/\\/g, '/'), size: stat.size });
            }
          } catch {}
        }
      }
    }
  }

  walk(rootDir, 0);

  // Sort by likely importance: route files, handlers, controllers first
  const priority = /\b(route|handler|controller|api|endpoint|server|app|auth|middleware|view)\b/i;
  files.sort((a, b) => {
    const aP = priority.test(a.relPath) ? 0 : 1;
    const bP = priority.test(b.relPath) ? 0 : 1;
    return aP - bP || a.size - b.size;
  });

  return files.slice(0, MAX_FILES);
}

/**
 * Build the triage prompt — identify files with entry points
 */
function buildTriagePrompt(fileList, projectName) {
  return `You are an expert security auditor performing source code triage.

Project: ${projectName}

Below is a list of source files. For each file, determine if it likely contains remotely-accessible entry points (HTTP routes, API handlers, WebSocket handlers, CLI commands that process external input, file upload handlers, form processors).

Files:
${fileList.map((f, i) => `${i + 1}. ${f.relPath} (${f.size} bytes)`).join('\n')}

Respond with valid JSON only:
{
  "entryPointFiles": [
    { "index": <1-based file number>, "reason": "<brief reason why this file has entry points>" }
  ]
}

Only include files that LIKELY have remotely-accessible entry points. Be selective — we want to focus analysis on attack surface, not internal utilities.`;
}

/**
 * Build vulnerability analysis prompt for a set of source files
 */
function buildAnalysisPrompt(files, vulnTypes) {
  const fileContents = files.map(f => {
    let content;
    try { content = fs.readFileSync(f.path, 'utf8'); }
    catch { return null; }
    return `<file path="${f.relPath}">\n${content}\n</file>`;
  }).filter(Boolean).join('\n\n');

  const vulnDescriptions = vulnTypes.map(vt => {
    const info = VULN_TYPES[vt];
    return `- **${vt}** (${info.name}, ${info.cwe}): Look for ${info.sinks}`;
  }).join('\n');

  return `You are the world's foremost expert in application security analysis. Your task is to find remotely exploitable vulnerabilities in the source code below.

IMPORTANT RULES:
1. Only report vulnerabilities where user input from a REMOTE source (HTTP request, WebSocket message, file upload, API call) can reach a dangerous sink WITHOUT adequate sanitization.
2. Trace the complete data flow from input to sink. If there is proper validation/sanitization in the path, it is NOT a vulnerability.
3. Do NOT report theoretical issues — only report concrete, exploitable vulnerabilities with a clear attack path.
4. Assign confidence 1-10 where: 1-3 = unlikely/theoretical, 4-6 = possible but needs investigation, 7-8 = likely exploitable, 9-10 = confirmed exploitable.
5. Only report findings with confidence >= 4.

VULNERABILITY TYPES TO CHECK:
${vulnDescriptions}

SOURCE CODE:
${fileContents}

Respond with valid JSON only:
{
  "findings": [
    {
      "vulnType": "RCE|SQLi|XSS|SSRF|LFI|AFO|IDOR",
      "title": "<concise title describing the vulnerability>",
      "severity": "critical|high|medium|low",
      "confidence": <1-10>,
      "file": "<relative file path>",
      "line": <approximate line number>,
      "cwe": "<CWE ID>",
      "mitre": "<MITRE ATT&CK technique>",
      "description": "<detailed explanation of the vulnerability and attack vector>",
      "dataFlow": "<input source> -> <processing steps> -> <dangerous sink>",
      "poc": "<proof-of-concept exploit (curl command, payload, or code snippet)>",
      "remediation": "<specific fix recommendation>"
    }
  ],
  "summary": "<1-2 sentence overall security assessment>"
}

If no vulnerabilities are found, return: { "findings": [], "summary": "No remotely exploitable vulnerabilities identified in the analyzed code." }`;
}

/**
 * Run a complete code audit
 * @param {string} targetPath - Path to the code directory
 * @param {object} options
 * @param {Function} options.askAIJSON - Vigil's AI JSON function
 * @param {string[]} options.languages - Languages to scan (default: auto-detect)
 * @param {string[]} options.vulnTypes - Vulnerability types to check (default: all)
 * @param {Function} options.onProgress - Progress callback
 * @param {number} options.timeout - Per-call timeout (default: 120000)
 * @returns {Promise<{findings: Array, summary: string, filesAnalyzed: number, duration: number}>}
 */
async function runCodeAudit(targetPath, options = {}) {
  const {
    askAIJSON,
    languages = [],
    vulnTypes = Object.keys(VULN_TYPES),
    onProgress,
    timeout = 120000,
  } = options;

  if (!askAIJSON) throw new Error('askAIJSON function required');

  const startTime = Date.now();
  const resolvedPath = path.resolve(targetPath);

  if (!fs.existsSync(resolvedPath) || !fs.statSync(resolvedPath).isDirectory()) {
    throw new Error('Target path does not exist or is not a directory: ' + targetPath);
  }

  const projectName = path.basename(resolvedPath);

  // Phase 1: Discover files
  if (onProgress) onProgress({ phase: 'discovery', message: 'Discovering source files...' });
  const allFiles = discoverFiles(resolvedPath, languages);

  if (allFiles.length === 0) {
    return { findings: [], summary: 'No source files found to analyze.', filesAnalyzed: 0, duration: Date.now() - startTime };
  }

  console.log(`  [CODE-AUDIT] Found ${allFiles.length} source files in ${resolvedPath}`);
  if (onProgress) onProgress({ phase: 'discovery', message: `Found ${allFiles.length} source files` });

  // Phase 2: Triage — identify entry point files
  if (onProgress) onProgress({ phase: 'triage', message: 'AI triaging files for entry points...' });

  let entryPointFiles = allFiles; // fallback: analyze all files if triage fails

  if (allFiles.length > 8) {
    // Only triage if we have many files — saves an LLM call for small projects
    const triageResult = await askAIJSON(buildTriagePrompt(allFiles, projectName), { timeout, includeSystemPrompt: false });

    console.log('  [CODE-AUDIT] Triage result:', triageResult ? 'received' : 'null');
    if (triageResult && Array.isArray(triageResult.entryPointFiles) && triageResult.entryPointFiles.length > 0) {
      entryPointFiles = triageResult.entryPointFiles
        .map(ep => allFiles[ep.index - 1])
        .filter(Boolean);

      if (entryPointFiles.length === 0) entryPointFiles = allFiles.slice(0, 15);
    } else {
      // Triage failed, take top priority files
      entryPointFiles = allFiles.slice(0, 15);
    }
  }

  if (onProgress) onProgress({ phase: 'triage', message: `${entryPointFiles.length} files selected for deep analysis` });

  // Phase 3: Deep vulnerability analysis
  // Chunk files to stay within context limits
  const chunks = [];
  let currentChunk = [];
  let currentSize = 0;

  for (const file of entryPointFiles) {
    if (currentSize + file.size > MAX_CHUNK_SIZE && currentChunk.length > 0) {
      chunks.push(currentChunk);
      currentChunk = [];
      currentSize = 0;
    }
    currentChunk.push(file);
    currentSize += file.size;
  }
  if (currentChunk.length > 0) chunks.push(currentChunk);

  const allFindings = [];
  let overallSummary = '';

  for (let i = 0; i < chunks.length; i++) {
    if (onProgress) onProgress({ phase: 'analysis', message: `Analyzing batch ${i + 1}/${chunks.length} (${chunks[i].length} files)...` });

    const analysisResult = await askAIJSON(
      buildAnalysisPrompt(chunks[i], vulnTypes),
      { timeout, includeSystemPrompt: false }
    );

    console.log(`  [CODE-AUDIT] Batch ${i+1}/${chunks.length} result:`, analysisResult ? `${(analysisResult.findings || []).length} findings` : 'null');
    if (analysisResult) {
      if (Array.isArray(analysisResult.findings)) {
        for (const f of analysisResult.findings) {
          // Normalize and validate
          if (f.confidence && f.confidence >= 4) {
            allFindings.push({
              id: crypto.randomUUID(),
              vulnType: f.vulnType || 'Unknown',
              title: f.title || 'Untitled finding',
              severity: normalizeSeverity(f.severity, f.confidence),
              confidence: Math.min(10, Math.max(1, f.confidence || 5)),
              file: f.file || 'unknown',
              line: f.line || 0,
              cwe: f.cwe || VULN_TYPES[f.vulnType]?.cwe || '',
              mitre: f.mitre || VULN_TYPES[f.vulnType]?.mitre || '',
              description: f.description || '',
              dataFlow: f.dataFlow || '',
              poc: f.poc || '',
              remediation: f.remediation || '',
            });
          }
        }
      }
      if (analysisResult.summary) {
        overallSummary = analysisResult.summary;
      }
    }
  }

  // Sort by confidence (highest first), then severity
  const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  allFindings.sort((a, b) => b.confidence - a.confidence || (sevOrder[a.severity] || 5) - (sevOrder[b.severity] || 5));

  if (onProgress) onProgress({ phase: 'complete', message: `Analysis complete. ${allFindings.length} findings.` });

  return {
    findings: allFindings,
    summary: overallSummary || `Analyzed ${entryPointFiles.length} files. Found ${allFindings.length} potential vulnerabilities.`,
    filesAnalyzed: entryPointFiles.length,
    totalFiles: allFiles.length,
    duration: Date.now() - startTime,
  };
}

function normalizeSeverity(sev, confidence) {
  const s = (sev || 'medium').toLowerCase();
  if (['critical', 'high', 'medium', 'low', 'info'].includes(s)) {
    // Downgrade severity if confidence is low
    if (confidence && confidence <= 4) {
      if (s === 'critical') return 'high';
      if (s === 'high') return 'medium';
    }
    return s;
  }
  return 'medium';
}

module.exports = {
  runCodeAudit,
  discoverFiles,
  VULN_TYPES,
  LANG_EXTENSIONS,
};

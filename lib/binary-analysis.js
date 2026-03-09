/**
 * Vigil — Binary Analysis Engine
 * Lightweight binary inspection using standard Linux tools (file, strings, readelf, objdump)
 * + AI-powered threat assessment. No Ghidra/radare2 dependency.
 *
 * Extracts: file type, architecture, strings (IOCs), imports, exports, sections, symbols
 * AI analyzes extracted metadata for malware indicators and suspicious patterns.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFile } = require('child_process');

// Max file size for analysis (50MB)
const MAX_FILE_SIZE = 50 * 1024 * 1024;

// Dangerous import patterns (Windows PE + Linux ELF)
const SUSPICIOUS_IMPORTS = new Set([
  // Process manipulation
  'CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory', 'NtCreateThreadEx',
  'CreateProcessA', 'CreateProcessW', 'WinExec', 'ShellExecuteA', 'ShellExecuteW',
  'system', 'execve', 'execvp', 'fork', 'popen', 'dlopen', 'dlsym',
  // Network
  'URLDownloadToFileA', 'InternetOpenA', 'InternetOpenUrlA', 'HttpSendRequestA',
  'WSAStartup', 'connect', 'send', 'recv', 'socket', 'bind', 'listen', 'accept',
  'getaddrinfo', 'gethostbyname',
  // Crypto / Obfuscation
  'CryptEncrypt', 'CryptDecrypt', 'CryptAcquireContextA', 'CryptCreateHash',
  // Registry / Persistence
  'RegSetValueExA', 'RegSetValueExW', 'RegCreateKeyExA', 'RegOpenKeyExA',
  // Injection
  'SetWindowsHookExA', 'OpenProcess', 'GetProcAddress', 'LoadLibraryA', 'LoadLibraryW',
  'NtUnmapViewOfSection', 'RtlCreateUserThread',
  // Anti-debug
  'IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess',
  'GetTickCount', 'QueryPerformanceCounter', 'OutputDebugStringA',
  // File operations
  'DeleteFileA', 'DeleteFileW', 'MoveFileA', 'CopyFileA',
  'unlink', 'rename', 'chmod', 'chown',
  // Keylogging
  'GetAsyncKeyState', 'GetKeyState', 'SetWindowsHookEx',
  // Privilege
  'AdjustTokenPrivileges', 'OpenProcessToken', 'setuid', 'setgid', 'ptrace',
]);

// IOC extraction patterns
const IOC_PATTERNS = {
  ipv4: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
  url: /https?:\/\/[a-zA-Z0-9][a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{4,}/g,
  email: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g,
  domain: /\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|tk|top|xyz|info|biz|cc|pw|su|onion)\b/gi,
  cve: /CVE-\d{4}-\d{4,}/g,
  registry: /HKEY_[A-Z_]+\\[^\s"']{5,}/g,
  filepath_win: /[A-Z]:\\(?:[^\s\\/"<>|:*?]{1,}\\)*[^\s\\/"<>|:*?]{1,}/g,
  filepath_unix: /\/(?:tmp|var|etc|usr|home|root|opt|dev|proc)\/[^\s"']{3,}/g,
  base64_long: /[A-Za-z0-9+/]{40,}={0,2}/g,
};

/**
 * Run a shell command and return stdout
 */
function runCmd(cmd, args, options = {}) {
  return new Promise((resolve) => {
    const child = execFile(cmd, args, {
      timeout: options.timeout || 15000,
      maxBuffer: 5 * 1024 * 1024,
      ...options,
    }, (err, stdout, stderr) => {
      resolve({ stdout: stdout || '', stderr: stderr || '', code: err ? err.code : 0 });
    });
  });
}

/**
 * Compute file hashes
 */
function computeHashes(filePath) {
  const data = fs.readFileSync(filePath);
  return {
    md5: crypto.createHash('md5').update(data).digest('hex'),
    sha1: crypto.createHash('sha1').update(data).digest('hex'),
    sha256: crypto.createHash('sha256').update(data).digest('hex'),
  };
}

/**
 * Detect file type and architecture
 */
async function detectFileType(filePath) {
  const result = await runCmd('file', ['-b', filePath]);
  const detail = result.stdout.trim();

  // Parse architecture and format
  const info = { detail, format: 'unknown', arch: 'unknown', bits: 0, endian: 'unknown', stripped: false, dynamic: false };

  if (/ELF/.test(detail)) {
    info.format = 'ELF';
    if (/64-bit/.test(detail)) info.bits = 64;
    else if (/32-bit/.test(detail)) info.bits = 32;
    if (/x86-64|x86_64|AMD64/.test(detail)) info.arch = 'x86_64';
    else if (/Intel 80386|i386/.test(detail)) info.arch = 'i386';
    else if (/ARM aarch64|aarch64/.test(detail)) info.arch = 'aarch64';
    else if (/ARM/.test(detail)) info.arch = 'arm';
    else if (/MIPS/.test(detail)) info.arch = 'mips';
    if (/LSB/.test(detail)) info.endian = 'little';
    else if (/MSB/.test(detail)) info.endian = 'big';
    if (/stripped/.test(detail)) info.stripped = true;
    if (/dynamically linked/.test(detail)) info.dynamic = true;
    if (/executable/.test(detail)) info.type = 'executable';
    else if (/shared object|\.so/.test(detail)) info.type = 'shared_library';
    else if (/relocatable/.test(detail)) info.type = 'object';
  } else if (/PE32\+?/.test(detail)) {
    info.format = 'PE';
    if (/PE32\+/.test(detail)) { info.bits = 64; info.arch = 'x86_64'; }
    else { info.bits = 32; info.arch = 'i386'; }
    info.endian = 'little';
    if (/DLL/.test(detail)) info.type = 'dll';
    else if (/executable/.test(detail)) info.type = 'executable';
  } else if (/Mach-O/.test(detail)) {
    info.format = 'Mach-O';
    if (/64-bit/.test(detail)) info.bits = 64;
    else info.bits = 32;
    if (/x86_64/.test(detail)) info.arch = 'x86_64';
    else if (/arm64/.test(detail)) info.arch = 'arm64';
  } else if (/Java/.test(detail)) {
    info.format = 'Java';
    info.type = 'class/jar';
  } else if (/PDF/.test(detail)) {
    info.format = 'PDF';
  } else if (/Microsoft/.test(detail) || /Composite Document/.test(detail)) {
    info.format = 'OLE';
    info.type = 'document';
  }

  return info;
}

/**
 * Extract strings and classify them
 */
async function extractStrings(filePath, minLen = 6) {
  // ASCII strings
  const ascii = await runCmd('strings', ['-n', String(minLen), filePath]);
  // Unicode strings (wide char)
  const unicode = await runCmd('strings', ['-n', String(minLen), '-e', 'l', filePath]);

  const allStrings = new Set();
  (ascii.stdout + '\n' + unicode.stdout).split('\n').forEach(s => {
    s = s.trim();
    if (s.length >= minLen && s.length < 2000) allStrings.add(s);
  });

  const strings = Array.from(allStrings);

  // Extract IOCs
  const iocs = { urls: [], ips: [], emails: [], domains: [], cves: [], registryKeys: [], filepaths: [], base64: [] };
  const fullText = strings.join('\n');

  const urlMatches = fullText.match(IOC_PATTERNS.url) || [];
  iocs.urls = [...new Set(urlMatches)].slice(0, 50);

  const ipMatches = fullText.match(IOC_PATTERNS.ipv4) || [];
  // Filter out common non-IOC IPs
  iocs.ips = [...new Set(ipMatches)].filter(ip => !ip.startsWith('0.') && !ip.startsWith('127.') && !ip.startsWith('255.')).slice(0, 50);

  const emailMatches = fullText.match(IOC_PATTERNS.email) || [];
  iocs.emails = [...new Set(emailMatches)].slice(0, 30);

  const domainMatches = fullText.match(IOC_PATTERNS.domain) || [];
  iocs.domains = [...new Set(domainMatches)].filter(d => !d.includes('example.') && !d.includes('localhost')).slice(0, 50);

  const cveMatches = fullText.match(IOC_PATTERNS.cve) || [];
  iocs.cves = [...new Set(cveMatches)].slice(0, 30);

  const regMatches = fullText.match(IOC_PATTERNS.registry) || [];
  iocs.registryKeys = [...new Set(regMatches)].slice(0, 30);

  const fpWin = fullText.match(IOC_PATTERNS.filepath_win) || [];
  const fpUnix = fullText.match(IOC_PATTERNS.filepath_unix) || [];
  iocs.filepaths = [...new Set([...fpWin, ...fpUnix])].slice(0, 50);

  const b64Matches = fullText.match(IOC_PATTERNS.base64_long) || [];
  iocs.base64 = [...new Set(b64Matches)].slice(0, 10);

  // Interesting strings (passwords, commands, crypto, shells, etc.)
  const interestingPatterns = /password|passwd|secret|token|api[_-]?key|authorization|credentials|cmd\.exe|powershell|bash|\/bin\/sh|wget|curl|chmod|nc\s+-|reverse.?shell|backdoor|keylog|inject|exploit|payload|dropper|c2|beacon|callback|encrypt|decrypt|ransom|bitcoin|monero|wallet|mining|xmr/i;
  const interesting = strings.filter(s => interestingPatterns.test(s)).slice(0, 100);

  return {
    total: strings.length,
    sample: strings.slice(0, 200), // First 200 for display
    iocs,
    interesting,
  };
}

/**
 * Get ELF sections, imports, exports, symbols
 */
async function analyzeELF(filePath) {
  const result = { sections: [], imports: [], exports: [], symbols: [], libraries: [] };

  // Sections
  const secResult = await runCmd('readelf', ['-S', '--wide', filePath]);
  if (secResult.stdout) {
    const secRegex = /\[\s*\d+\]\s+(\S+)\s+(\S+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)/g;
    let m;
    while ((m = secRegex.exec(secResult.stdout)) !== null) {
      result.sections.push({
        name: m[1],
        type: m[2],
        addr: '0x' + m[3],
        offset: '0x' + m[4],
        size: parseInt(m[5], 16),
      });
    }
  }

  // Dynamic symbols (imports + exports)
  const dynResult = await runCmd('readelf', ['--dyn-syms', '--wide', filePath]);
  if (dynResult.stdout) {
    const symRegex = /\d+:\s+([0-9a-f]+)\s+\d+\s+(\w+)\s+(\w+)\s+(\w+)\s+(\w+)\s+(.*)/g;
    let m;
    while ((m = symRegex.exec(dynResult.stdout)) !== null) {
      const addr = m[1];
      const type = m[2];
      const bind = m[3];
      const vis = m[4];
      const ndx = m[5];
      const name = m[6].trim().split('@')[0]; // Strip version
      if (!name || name === '') continue;

      if (ndx === 'UND' && name) {
        result.imports.push({ name, type, bind });
      } else if (bind === 'GLOBAL' && ndx !== 'UND' && name) {
        result.exports.push({ name, type, addr: '0x' + addr });
      }
    }
  }

  // Shared libraries
  const libResult = await runCmd('readelf', ['-d', filePath]);
  if (libResult.stdout) {
    const libRegex = /NEEDED.*\[([^\]]+)\]/g;
    let m;
    while ((m = libRegex.exec(libResult.stdout)) !== null) {
      result.libraries.push(m[1]);
    }
  }

  return result;
}

/**
 * Get PE imports/exports via objdump (works for PE files on Linux)
 */
async function analyzePE(filePath) {
  const result = { imports: [], exports: [], dlls: [], sections: [] };

  const objResult = await runCmd('objdump', ['-p', filePath]);
  if (objResult.stdout) {
    // DLL imports
    const dllRegex = /DLL Name:\s+(\S+)/g;
    let m;
    while ((m = dllRegex.exec(objResult.stdout)) !== null) {
      result.dlls.push(m[1]);
    }

    // Import names
    const importRegex = /\t([0-9a-f]+)\s+(\S+)/g;
    while ((m = importRegex.exec(objResult.stdout)) !== null) {
      if (m[2] && !m[2].match(/^[0-9a-f]+$/)) {
        result.imports.push({ name: m[2], hint: m[1] });
      }
    }
  }

  // Sections
  const secResult = await runCmd('objdump', ['-h', filePath]);
  if (secResult.stdout) {
    const secRegex = /\d+\s+(\.\S+)\s+([0-9a-f]+)\s+([0-9a-f]+)/g;
    let m;
    while ((m = secRegex.exec(secResult.stdout)) !== null) {
      result.sections.push({ name: m[1], size: parseInt(m[2], 16), addr: '0x' + m[3] });
    }
  }

  return result;
}

/**
 * Compute entropy for packer/encryption detection
 */
function computeEntropy(filePath) {
  const data = fs.readFileSync(filePath);
  const freq = new Array(256).fill(0);
  for (let i = 0; i < data.length; i++) freq[data[i]]++;

  let entropy = 0;
  for (let i = 0; i < 256; i++) {
    if (freq[i] > 0) {
      const p = freq[i] / data.length;
      entropy -= p * Math.log2(p);
    }
  }

  return {
    value: Math.round(entropy * 1000) / 1000,
    packed: entropy > 7.0,
    encrypted: entropy > 7.5,
    assessment: entropy > 7.5 ? 'Likely encrypted or packed' :
                entropy > 7.0 ? 'Possibly packed or compressed' :
                entropy > 6.0 ? 'Normal compiled binary' :
                'Low entropy — may contain large data sections'
  };
}

/**
 * Flag suspicious imports
 */
function flagSuspiciousImports(imports) {
  const suspicious = [];
  for (const imp of imports) {
    const name = imp.name || '';
    if (SUSPICIOUS_IMPORTS.has(name)) {
      suspicious.push(name);
    }
  }
  return [...new Set(suspicious)];
}

/**
 * Run complete binary analysis
 */
async function analyzeBinary(filePath, options = {}) {
  const { askAI, onProgress, timeout = 120000 } = options;
  const startTime = Date.now();
  const resolvedPath = path.resolve(filePath);

  if (!fs.existsSync(resolvedPath)) {
    throw new Error('File does not exist: ' + filePath);
  }

  const stat = fs.statSync(resolvedPath);
  if (!stat.isFile()) throw new Error('Not a file: ' + filePath);
  if (stat.size > MAX_FILE_SIZE) throw new Error('File too large (max 50MB): ' + (stat.size / 1024 / 1024).toFixed(1) + 'MB');
  if (stat.size === 0) throw new Error('File is empty');

  const fileName = path.basename(resolvedPath);

  // Phase 1: File identification
  if (onProgress) onProgress({ phase: 'identify', message: 'Identifying file type and computing hashes...' });

  const [fileType, hashes] = await Promise.all([
    detectFileType(resolvedPath),
    Promise.resolve(computeHashes(resolvedPath)),
  ]);

  const entropy = computeEntropy(resolvedPath);

  // Phase 2: String extraction
  if (onProgress) onProgress({ phase: 'strings', message: 'Extracting strings and IOCs...' });
  const strings = await extractStrings(resolvedPath);

  // Phase 3: Binary structure analysis
  if (onProgress) onProgress({ phase: 'structure', message: 'Analyzing binary structure...' });

  let structure = { sections: [], imports: [], exports: [], libraries: [], dlls: [] };
  if (fileType.format === 'ELF') {
    structure = await analyzeELF(resolvedPath);
  } else if (fileType.format === 'PE') {
    structure = await analyzePE(resolvedPath);
  }

  // Flag suspicious imports
  const allImports = structure.imports || [];
  const suspiciousImports = flagSuspiciousImports(allImports);

  // Build result
  const result = {
    id: crypto.randomUUID(),
    file: fileName,
    path: resolvedPath,
    size: stat.size,
    hashes,
    fileType,
    entropy,
    strings: {
      total: strings.total,
      interesting: strings.interesting,
      sample: strings.sample.slice(0, 100),
    },
    iocs: strings.iocs,
    structure: {
      sections: structure.sections,
      imports: allImports.slice(0, 200),
      exports: (structure.exports || []).slice(0, 200),
      libraries: structure.libraries || structure.dlls || [],
    },
    suspiciousImports,
    riskIndicators: [],
    analyzedAt: new Date().toISOString(),
    duration: Date.now() - startTime,
  };

  // Build risk indicators
  if (entropy.packed) result.riskIndicators.push({ indicator: 'High entropy', detail: 'Binary may be packed or encrypted (entropy: ' + entropy.value + ')', severity: 'high' });
  if (suspiciousImports.length > 0) result.riskIndicators.push({ indicator: 'Suspicious API calls', detail: suspiciousImports.join(', '), severity: suspiciousImports.length > 5 ? 'critical' : 'high' });
  if (strings.iocs.urls.length > 0) result.riskIndicators.push({ indicator: 'Embedded URLs', detail: strings.iocs.urls.length + ' URLs found', severity: 'medium' });
  if (strings.iocs.ips.length > 0) result.riskIndicators.push({ indicator: 'Embedded IPs', detail: strings.iocs.ips.join(', ').substring(0, 200), severity: 'medium' });
  if (strings.iocs.registryKeys.length > 0) result.riskIndicators.push({ indicator: 'Registry key references', detail: strings.iocs.registryKeys.length + ' keys found', severity: 'medium' });
  if (strings.iocs.base64.length > 0) result.riskIndicators.push({ indicator: 'Base64-encoded data', detail: strings.iocs.base64.length + ' large base64 strings', severity: 'low' });
  if (strings.interesting.length > 10) result.riskIndicators.push({ indicator: 'Suspicious strings', detail: strings.interesting.length + ' interesting strings (passwords, shells, crypto)', severity: 'medium' });
  if (fileType.stripped) result.riskIndicators.push({ indicator: 'Stripped binary', detail: 'Debug symbols removed — harder to analyze', severity: 'low' });

  // Phase 4: AI threat assessment (optional)
  if (askAI) {
    if (onProgress) onProgress({ phase: 'ai', message: 'Running AI threat assessment...' });

    try {
      const aiPrompt = buildThreatPrompt(result);
      const aiResult = await askAI(aiPrompt, { timeout });

      result.aiAssessment = aiResult || 'AI assessment unavailable.';
    } catch (e) {
      result.aiAssessment = 'AI assessment failed: ' + e.message;
    }
  }

  result.duration = Date.now() - startTime;
  if (onProgress) onProgress({ phase: 'complete', message: 'Analysis complete.' });

  return result;
}

/**
 * Build AI threat assessment prompt
 */
function buildThreatPrompt(result) {
  const sections = (result.structure.sections || []).map(s => s.name).join(', ');
  const libs = (result.structure.libraries || []).join(', ');
  const suspImports = result.suspiciousImports.join(', ') || 'None';
  const interestingStr = (result.strings.interesting || []).slice(0, 30).join('\n  ');
  const urls = (result.iocs.urls || []).slice(0, 10).join('\n  ');
  const ips = (result.iocs.ips || []).slice(0, 10).join(', ');

  return `You are a senior malware analyst. Analyze this binary metadata and provide a threat assessment.

FILE INFORMATION:
- Name: ${result.file}
- Size: ${(result.size / 1024).toFixed(1)} KB
- Format: ${result.fileType.format} ${result.fileType.bits || ''}-bit ${result.fileType.arch || ''}
- Type: ${result.fileType.type || 'unknown'}
- Stripped: ${result.fileType.stripped ? 'Yes' : 'No'}
- Dynamic: ${result.fileType.dynamic ? 'Yes' : 'No'}
- Entropy: ${result.entropy.value} (${result.entropy.assessment})

HASHES:
- MD5: ${result.hashes.md5}
- SHA256: ${result.hashes.sha256}

SECTIONS: ${sections || 'N/A'}
LIBRARIES: ${libs || 'N/A'}
SUSPICIOUS IMPORTS (${result.suspiciousImports.length}): ${suspImports}
TOTAL IMPORTS: ${result.structure.imports.length}
TOTAL EXPORTS: ${result.structure.exports.length}

STRINGS ANALYSIS:
- Total strings: ${result.strings.total}
- Interesting strings: ${result.strings.interesting.length}
- URLs found: ${result.iocs.urls.length}
- IPs found: ${result.iocs.ips.length}
- Emails: ${result.iocs.emails.length}
- Registry keys: ${result.iocs.registryKeys.length}
- File paths: ${result.iocs.filepaths.length}

INTERESTING STRINGS (sample):
  ${interestingStr || 'None'}

EMBEDDED URLs (sample):
  ${urls || 'None'}

EMBEDDED IPs: ${ips || 'None'}

Provide a structured assessment with these sections:
## Threat Assessment
Overall risk level (Critical/High/Medium/Low/Clean) and reasoning.

## Binary Classification
What type of binary is this? (legitimate tool, potentially unwanted, suspicious, likely malicious)

## Capability Analysis
What capabilities does this binary appear to have based on imports, strings, and structure?

## IOC Summary
Key indicators of compromise found (IPs, URLs, suspicious strings, registry keys).

## Recommendations
What actions should a SOC analyst take with this binary?`;
}

module.exports = {
  analyzeBinary,
  detectFileType,
  extractStrings,
  analyzeELF,
  analyzePE,
  computeEntropy,
  computeHashes,
  flagSuspiciousImports,
  SUSPICIOUS_IMPORTS,
};

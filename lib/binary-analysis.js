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

// ════════════════════════════════════════════════════════════════════════
// DEEP ANALYSIS — vibe-re inspired (0xeb/vibe-re patterns)
// Per-section entropy, disassembly patterns, import taint chains,
// MITRE ATT&CK mapping, string obfuscation detection
// ════════════════════════════════════════════════════════════════════════

// MITRE ATT&CK tactic mapping: import name → { tactic, technique, name }
const MITRE_IMPORT_MAP = {
  // T1055 Process Injection
  CreateRemoteThread: { tactic: 'Defense Evasion', tid: 'T1055', name: 'Process Injection' },
  VirtualAllocEx: { tactic: 'Defense Evasion', tid: 'T1055', name: 'Process Injection' },
  WriteProcessMemory: { tactic: 'Defense Evasion', tid: 'T1055', name: 'Process Injection' },
  NtCreateThreadEx: { tactic: 'Defense Evasion', tid: 'T1055', name: 'Process Injection' },
  NtUnmapViewOfSection: { tactic: 'Defense Evasion', tid: 'T1055.012', name: 'Process Hollowing' },
  RtlCreateUserThread: { tactic: 'Defense Evasion', tid: 'T1055', name: 'Process Injection' },
  SetWindowsHookExA: { tactic: 'Credential Access', tid: 'T1056.001', name: 'Keylogging' },
  SetWindowsHookEx: { tactic: 'Credential Access', tid: 'T1056.001', name: 'Keylogging' },
  // T1059 Command Execution
  CreateProcessA: { tactic: 'Execution', tid: 'T1059', name: 'Command and Scripting' },
  CreateProcessW: { tactic: 'Execution', tid: 'T1059', name: 'Command and Scripting' },
  WinExec: { tactic: 'Execution', tid: 'T1059', name: 'Command and Scripting' },
  ShellExecuteA: { tactic: 'Execution', tid: 'T1059', name: 'Command and Scripting' },
  ShellExecuteW: { tactic: 'Execution', tid: 'T1059', name: 'Command and Scripting' },
  system: { tactic: 'Execution', tid: 'T1059.004', name: 'Unix Shell' },
  execve: { tactic: 'Execution', tid: 'T1059.004', name: 'Unix Shell' },
  execvp: { tactic: 'Execution', tid: 'T1059.004', name: 'Unix Shell' },
  popen: { tactic: 'Execution', tid: 'T1059.004', name: 'Unix Shell' },
  // T1071 C2 Communication
  URLDownloadToFileA: { tactic: 'Command and Control', tid: 'T1071', name: 'Application Layer Protocol' },
  InternetOpenA: { tactic: 'Command and Control', tid: 'T1071', name: 'Application Layer Protocol' },
  InternetOpenUrlA: { tactic: 'Command and Control', tid: 'T1071', name: 'Application Layer Protocol' },
  HttpSendRequestA: { tactic: 'Command and Control', tid: 'T1071.001', name: 'Web Protocols' },
  WSAStartup: { tactic: 'Command and Control', tid: 'T1095', name: 'Non-Application Layer Protocol' },
  socket: { tactic: 'Command and Control', tid: 'T1095', name: 'Non-Application Layer Protocol' },
  connect: { tactic: 'Command and Control', tid: 'T1095', name: 'Non-Application Layer Protocol' },
  send: { tactic: 'Exfiltration', tid: 'T1041', name: 'Exfiltration Over C2 Channel' },
  recv: { tactic: 'Command and Control', tid: 'T1095', name: 'Non-Application Layer Protocol' },
  bind: { tactic: 'Command and Control', tid: 'T1571', name: 'Non-Standard Port' },
  listen: { tactic: 'Command and Control', tid: 'T1571', name: 'Non-Standard Port' },
  accept: { tactic: 'Command and Control', tid: 'T1571', name: 'Non-Standard Port' },
  getaddrinfo: { tactic: 'Discovery', tid: 'T1016', name: 'System Network Configuration' },
  gethostbyname: { tactic: 'Discovery', tid: 'T1016', name: 'System Network Configuration' },
  // T1027 Obfuscation
  CryptEncrypt: { tactic: 'Defense Evasion', tid: 'T1027', name: 'Obfuscated Files or Information' },
  CryptDecrypt: { tactic: 'Defense Evasion', tid: 'T1027', name: 'Obfuscated Files or Information' },
  CryptAcquireContextA: { tactic: 'Defense Evasion', tid: 'T1027', name: 'Obfuscated Files or Information' },
  CryptCreateHash: { tactic: 'Defense Evasion', tid: 'T1027', name: 'Obfuscated Files or Information' },
  // T1547 Persistence
  RegSetValueExA: { tactic: 'Persistence', tid: 'T1547.001', name: 'Registry Run Keys' },
  RegSetValueExW: { tactic: 'Persistence', tid: 'T1547.001', name: 'Registry Run Keys' },
  RegCreateKeyExA: { tactic: 'Persistence', tid: 'T1547.001', name: 'Registry Run Keys' },
  RegOpenKeyExA: { tactic: 'Discovery', tid: 'T1012', name: 'Query Registry' },
  // T1129 Shared Modules
  LoadLibraryA: { tactic: 'Execution', tid: 'T1129', name: 'Shared Modules' },
  LoadLibraryW: { tactic: 'Execution', tid: 'T1129', name: 'Shared Modules' },
  GetProcAddress: { tactic: 'Execution', tid: 'T1129', name: 'Shared Modules' },
  dlopen: { tactic: 'Execution', tid: 'T1129', name: 'Shared Modules' },
  dlsym: { tactic: 'Execution', tid: 'T1129', name: 'Shared Modules' },
  // T1622 Anti-Debug
  IsDebuggerPresent: { tactic: 'Defense Evasion', tid: 'T1622', name: 'Debugger Evasion' },
  CheckRemoteDebuggerPresent: { tactic: 'Defense Evasion', tid: 'T1622', name: 'Debugger Evasion' },
  NtQueryInformationProcess: { tactic: 'Defense Evasion', tid: 'T1622', name: 'Debugger Evasion' },
  GetTickCount: { tactic: 'Defense Evasion', tid: 'T1497.003', name: 'Time Based Evasion' },
  QueryPerformanceCounter: { tactic: 'Defense Evasion', tid: 'T1497.003', name: 'Time Based Evasion' },
  OutputDebugStringA: { tactic: 'Defense Evasion', tid: 'T1622', name: 'Debugger Evasion' },
  // T1070 Indicator Removal
  DeleteFileA: { tactic: 'Defense Evasion', tid: 'T1070.004', name: 'File Deletion' },
  DeleteFileW: { tactic: 'Defense Evasion', tid: 'T1070.004', name: 'File Deletion' },
  unlink: { tactic: 'Defense Evasion', tid: 'T1070.004', name: 'File Deletion' },
  // T1056 Input Capture
  GetAsyncKeyState: { tactic: 'Collection', tid: 'T1056.001', name: 'Keylogging' },
  GetKeyState: { tactic: 'Collection', tid: 'T1056.001', name: 'Keylogging' },
  // T1134 Access Token Manipulation
  AdjustTokenPrivileges: { tactic: 'Privilege Escalation', tid: 'T1134', name: 'Access Token Manipulation' },
  OpenProcessToken: { tactic: 'Privilege Escalation', tid: 'T1134', name: 'Access Token Manipulation' },
  OpenProcess: { tactic: 'Privilege Escalation', tid: 'T1134', name: 'Access Token Manipulation' },
  setuid: { tactic: 'Privilege Escalation', tid: 'T1548.001', name: 'Setuid and Setgid' },
  setgid: { tactic: 'Privilege Escalation', tid: 'T1548.001', name: 'Setuid and Setgid' },
  ptrace: { tactic: 'Defense Evasion', tid: 'T1055.008', name: 'Ptrace System Calls' },
  fork: { tactic: 'Execution', tid: 'T1106', name: 'Native API' },
  chmod: { tactic: 'Defense Evasion', tid: 'T1222.002', name: 'Linux File Permissions' },
};

// Import taint chain definitions: multi-step exploitation patterns
const TAINT_CHAINS = [
  { name: 'Process Injection', severity: 'critical', imports: ['OpenProcess', 'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread'], minMatch: 3, description: 'Classic DLL injection sequence — allocate remote memory, write shellcode, create remote thread' },
  { name: 'Process Hollowing', severity: 'critical', imports: ['CreateProcessA||CreateProcessW', 'NtUnmapViewOfSection', 'VirtualAllocEx', 'WriteProcessMemory'], minMatch: 3, description: 'Suspend process, unmap original code, inject malicious image' },
  { name: 'Reflective DLL Loading', severity: 'critical', imports: ['VirtualAllocEx||VirtualAlloc', 'GetProcAddress', 'LoadLibraryA||LoadLibraryW'], minMatch: 2, description: 'Load DLL from memory without touching disk — common in fileless malware' },
  { name: 'Network Exfiltration', severity: 'high', imports: ['WSAStartup||socket', 'connect', 'send'], minMatch: 3, description: 'Socket-based data exfiltration chain — connect to remote host and send data' },
  { name: 'HTTP C2 Channel', severity: 'high', imports: ['InternetOpenA', 'InternetOpenUrlA||HttpSendRequestA'], minMatch: 2, description: 'WinInet-based HTTP C2 communication — common in commodity malware' },
  { name: 'Download & Execute', severity: 'critical', imports: ['URLDownloadToFileA', 'CreateProcessA||CreateProcessW||WinExec||ShellExecuteA'], minMatch: 2, description: 'Download payload from URL, execute it — classic dropper behavior' },
  { name: 'Credential Harvesting', severity: 'high', imports: ['OpenProcessToken', 'AdjustTokenPrivileges', 'RegOpenKeyExA||RegSetValueExA'], minMatch: 2, description: 'Token manipulation + registry access — credential theft or privilege escalation' },
  { name: 'Keylogger Pipeline', severity: 'high', imports: ['GetAsyncKeyState||GetKeyState||SetWindowsHookExA', 'send||WriteFile'], minMatch: 2, description: 'Capture keystrokes and exfiltrate them — input capture to data transmission' },
  { name: 'Anti-Analysis Suite', severity: 'medium', imports: ['IsDebuggerPresent||CheckRemoteDebuggerPresent||NtQueryInformationProcess', 'GetTickCount||QueryPerformanceCounter'], minMatch: 2, description: 'Multiple anti-debugging checks — debugger detection + timing checks' },
  { name: 'Persistence via Registry', severity: 'high', imports: ['RegCreateKeyExA||RegOpenKeyExA', 'RegSetValueExA||RegSetValueExW'], minMatch: 2, description: 'Registry modification for persistence — auto-start keys or configuration storage' },
  { name: 'Unix Reverse Shell', severity: 'critical', imports: ['socket', 'connect', 'execve||execvp||system'], minMatch: 3, description: 'Socket connect + exec — classic Unix reverse shell pattern' },
  { name: 'Shared Library Injection', severity: 'high', imports: ['dlopen', 'dlsym'], minMatch: 2, description: 'Dynamic library loading — runtime code injection on Linux/macOS' },
];

// Packer signatures (magic bytes at known offsets)
const PACKER_SIGNATURES = [
  { name: 'UPX', magic: 'UPX!', description: 'UPX packed executable — decompress with upx -d' },
  { name: 'UPX (section)', section: 'UPX0', description: 'UPX section header detected' },
  { name: 'UPX (section)', section: 'UPX1', description: 'UPX section header detected' },
  { name: 'ASPack', section: '.aspack', description: 'ASPack packer detected' },
  { name: 'Themida', section: '.themida', description: 'Themida/WinLicense protector' },
  { name: 'VMProtect', section: '.vmp0', description: 'VMProtect virtual machine obfuscator' },
  { name: 'VMProtect', section: '.vmp1', description: 'VMProtect virtual machine obfuscator' },
  { name: 'Enigma', section: '.enigma1', description: 'Enigma Protector' },
  { name: 'Enigma', section: '.enigma2', description: 'Enigma Protector' },
  { name: 'PECompact', section: 'PEC2', description: 'PECompact packer' },
  { name: 'MPRESS', section: '.MPRESS1', description: 'MPRESS packer' },
  { name: 'MPRESS', section: '.MPRESS2', description: 'MPRESS packer' },
  { name: 'Petite', section: '.petite', description: 'Petite packer' },
  { name: 'NSPack', section: '.nsp0', description: 'NSPack packer' },
  { name: 'MEW', section: 'MEW', description: 'MEW packer' },
];

// Disassembly patterns (regex on objdump output)
const DISASM_PATTERNS = [
  { name: 'ROP Gadget (ret)', pattern: /(?:pop\s+\w+\s*\n\s*[0-9a-f]+:.*){1,3}ret/gm, severity: 'medium', description: 'Return-oriented programming gadget — pop registers then return', category: 'exploitation' },
  { name: 'Syscall Invocation', pattern: /\bsyscall\b|\bint\s+0x80\b|\bsvc\s+#?0\b/gm, severity: 'high', description: 'Direct system call — bypasses libc, common in shellcode and rootkits', category: 'shellcode' },
  { name: 'NOP Sled', pattern: /(?:nop\s*\n\s*[0-9a-f]+:.*){4,}/gm, severity: 'high', description: 'NOP sled (4+ consecutive) — buffer overflow shellcode alignment', category: 'shellcode' },
  { name: 'Self-Modifying Code', pattern: /mov\s+.*\[.*\],\s*0x[0-9a-f]+.*\n.*call\s+/gm, severity: 'high', description: 'Write constant then call — possible runtime code patching', category: 'obfuscation' },
  { name: 'Stack Pivot', pattern: /xchg\s+.*esp|mov\s+esp,/gm, severity: 'critical', description: 'Stack pointer manipulation — stack pivoting for ROP chains', category: 'exploitation' },
  { name: 'PEB Access (fs:[0x30])', pattern: /mov\s+.*,.*\[fs:0x30\]|mov\s+.*,.*\[gs:0x60\]/gm, severity: 'high', description: 'PEB access via segment register — common in shellcode for API resolution', category: 'shellcode' },
  { name: 'XOR Decoder Loop', pattern: /xor\s+.*\[.*\].*\n.*(?:inc|add|loop|dec|jn)/gm, severity: 'high', description: 'XOR decode loop — runtime string/shellcode decryption', category: 'obfuscation' },
  { name: 'Call-Pop (PIC)', pattern: /call\s+[0-9a-f]+\s*\n\s*[0-9a-f]+:.*pop\s+/gm, severity: 'medium', description: 'Call-pop position-independent code — get EIP/RIP without hardcoded addresses', category: 'shellcode' },
  { name: 'Anti-Disassembly', pattern: /jmp\s+[0-9a-f]+\s*\n\s*[0-9a-f]+:.*\.byte|db\s+0x/gm, severity: 'medium', description: 'Junk bytes after jump — anti-disassembly technique', category: 'obfuscation' },
];

/**
 * Compute per-section entropy + packer detection (vibe-re inspired)
 */
async function analyzeEntropySections(filePath, sections, fileType) {
  const data = fs.readFileSync(filePath);
  const sectionEntropy = [];

  // Calculate entropy for each section based on offset/size
  for (const sec of sections) {
    if (!sec.size || sec.size < 16) continue;

    // Try to get section data from file offset
    const offset = parseInt(String(sec.offset || sec.addr || '0').replace('0x', ''), 16);
    const size = Math.min(sec.size, data.length - offset);
    if (offset >= data.length || size <= 0) continue;

    const chunk = data.subarray(offset, offset + size);
    const freq = new Array(256).fill(0);
    for (let i = 0; i < chunk.length; i++) freq[chunk[i]]++;

    let entropy = 0;
    for (let i = 0; i < 256; i++) {
      if (freq[i] > 0) {
        const p = freq[i] / chunk.length;
        entropy -= p * Math.log2(p);
      }
    }

    const val = Math.round(entropy * 1000) / 1000;
    const isExecutable = /\.text|\.code|CODE|UPX[01]/i.test(sec.name);
    const isData = /\.data|\.rdata|\.rodata|\.bss/i.test(sec.name);

    let assessment = 'normal';
    if (val > 7.5) assessment = 'encrypted';
    else if (val > 7.0) assessment = 'packed';
    else if (val > 6.5 && isData) assessment = 'compressed';
    else if (val < 1.0 && sec.size > 1024) assessment = 'sparse';
    else if (val < 4.0 && isExecutable) assessment = 'low (possible code cave)';

    // Flag anomalies: high entropy in data sections, low in code sections
    let anomaly = null;
    if (val > 7.0 && isData) anomaly = 'Data section with unusually high entropy — possible encrypted payload';
    if (val > 7.5 && isExecutable) anomaly = 'Code section with encryption-level entropy — likely packed or encrypted';
    if (val < 3.0 && isExecutable && sec.size > 4096) anomaly = 'Code section with very low entropy — possible code cave or padding';

    sectionEntropy.push({
      name: sec.name,
      size: sec.size,
      entropy: val,
      assessment,
      anomaly,
      executable: isExecutable,
    });
  }

  // Packer detection
  const packers = [];
  const fileStr = data.subarray(0, Math.min(data.length, 4096)).toString('ascii');

  for (const sig of PACKER_SIGNATURES) {
    if (sig.magic && fileStr.includes(sig.magic)) {
      packers.push({ name: sig.name, description: sig.description, match: 'magic bytes' });
    }
    if (sig.section) {
      const found = sections.find(s => s.name === sig.section);
      if (found) packers.push({ name: sig.name, description: sig.description, match: 'section: ' + sig.section });
    }
  }

  return { sectionEntropy, packers };
}

/**
 * Detect disassembly patterns via objdump (vibe-re inspired)
 * Scans for: ROP gadgets, shellcode, NOP sleds, PEB access, XOR decoders, code caves
 */
async function detectDisassemblyPatterns(filePath, fileType) {
  if (fileType.format !== 'ELF' && fileType.format !== 'PE') return [];

  // Get disassembly of .text section (first 500KB to avoid huge output)
  const args = fileType.format === 'ELF'
    ? ['-d', '-j', '.text', '--no-show-raw-insn', filePath]
    : ['-d', '--no-show-raw-insn', filePath];

  const result = await runCmd('objdump', args, { timeout: 20000, maxBuffer: 2 * 1024 * 1024 });
  if (!result.stdout || result.stdout.length < 100) return [];

  // Limit to first 500KB of disassembly
  const disasm = result.stdout.substring(0, 512 * 1024);
  const patterns = [];

  for (const pat of DISASM_PATTERNS) {
    const matches = disasm.match(pat.pattern);
    if (matches && matches.length > 0) {
      patterns.push({
        name: pat.name,
        severity: pat.severity,
        category: pat.category,
        description: pat.description,
        count: matches.length,
        sample: matches[0].trim().substring(0, 200),
      });
    }
  }

  return patterns;
}

/**
 * Build import taint chains (vibe-re inspired)
 * Detects multi-step exploitation patterns from import combinations
 */
function buildImportTaintChains(imports) {
  const importNames = new Set(imports.map(i => i.name || ''));
  const chains = [];

  for (const chain of TAINT_CHAINS) {
    let matched = 0;
    const matchedImports = [];

    for (const req of chain.imports) {
      // Support || for alternatives (e.g., 'CreateProcessA||CreateProcessW')
      const alts = req.split('||');
      const found = alts.find(a => importNames.has(a));
      if (found) {
        matched++;
        matchedImports.push(found);
      }
    }

    if (matched >= chain.minMatch) {
      chains.push({
        name: chain.name,
        severity: chain.severity,
        description: chain.description,
        matchedImports,
        matchRatio: matched + '/' + chain.imports.length,
        confidence: matched === chain.imports.length ? 'high' : 'medium',
      });
    }
  }

  return chains;
}

/**
 * Map imports + IOCs to MITRE ATT&CK tactics (vibe-re inspired)
 */
function mapMITREAttackTactics(imports, iocs, strings) {
  const tactics = {};

  // Map from imports
  for (const imp of imports) {
    const name = imp.name || '';
    const mapping = MITRE_IMPORT_MAP[name];
    if (mapping) {
      const key = mapping.tid;
      if (!tactics[key]) {
        tactics[key] = { ...mapping, evidence: [], count: 0 };
      }
      tactics[key].evidence.push('import: ' + name);
      tactics[key].count++;
    }
  }

  // Map from IOCs
  if (iocs.urls && iocs.urls.length > 0) {
    const key = 'T1071';
    if (!tactics[key]) tactics[key] = { tactic: 'Command and Control', tid: 'T1071', name: 'Application Layer Protocol', evidence: [], count: 0 };
    tactics[key].evidence.push(iocs.urls.length + ' embedded URLs');
    tactics[key].count++;
  }
  if (iocs.ips && iocs.ips.length > 0) {
    const key = 'T1095';
    if (!tactics[key]) tactics[key] = { tactic: 'Command and Control', tid: 'T1095', name: 'Non-Application Layer Protocol', evidence: [], count: 0 };
    tactics[key].evidence.push(iocs.ips.length + ' embedded IPs');
    tactics[key].count++;
  }
  if (iocs.registryKeys && iocs.registryKeys.length > 0) {
    const key = 'T1012';
    if (!tactics[key]) tactics[key] = { tactic: 'Discovery', tid: 'T1012', name: 'Query Registry', evidence: [], count: 0 };
    tactics[key].evidence.push(iocs.registryKeys.length + ' registry key references');
    tactics[key].count++;
  }

  // Map from interesting strings
  const strText = (strings.interesting || []).join(' ').toLowerCase();
  if (/ransom|encrypt.*files|bitcoin|monero|wallet/.test(strText)) {
    tactics['T1486'] = { tactic: 'Impact', tid: 'T1486', name: 'Data Encrypted for Impact', evidence: ['ransomware keywords in strings'], count: 1 };
  }
  if (/keylog|keystroke|getasynckeystate/i.test(strText)) {
    const key = 'T1056.001';
    if (!tactics[key]) tactics[key] = { tactic: 'Collection', tid: 'T1056.001', name: 'Keylogging', evidence: [], count: 0 };
    tactics[key].evidence.push('keylogger keywords in strings');
    tactics[key].count++;
  }
  if (/reverse.?shell|bind.?shell|nc\s+-|\/bin\/sh|\/bin\/bash/.test(strText)) {
    tactics['T1059.004'] = { tactic: 'Execution', tid: 'T1059.004', name: 'Unix Shell', evidence: ['shell command keywords in strings'], count: 1 };
  }
  if (/mining|xmr|stratum|hashrate|cryptonight/.test(strText)) {
    tactics['T1496'] = { tactic: 'Impact', tid: 'T1496', name: 'Resource Hijacking', evidence: ['cryptocurrency mining keywords'], count: 1 };
  }

  // Convert to sorted array
  return Object.values(tactics).sort((a, b) => b.count - a.count);
}

/**
 * Detect string obfuscation patterns (vibe-re inspired)
 * Chi-squared analysis + XOR/ROT pattern detection
 */
function detectStringObfuscation(filePath, strings) {
  const data = fs.readFileSync(filePath);
  const result = {
    obfuscationScore: 0,
    techniques: [],
    stats: { totalStrings: strings.total || 0, plaintextRatio: 0, suspiciousBlocks: 0 },
  };

  // 1. Chi-squared test on byte distribution (high value = more random = likely encrypted)
  const freq = new Array(256).fill(0);
  for (let i = 0; i < data.length; i++) freq[data[i]]++;
  const expected = data.length / 256;
  let chiSq = 0;
  for (let i = 0; i < 256; i++) chiSq += Math.pow(freq[i] - expected, 2) / expected;
  const normalizedChi = chiSq / 256;

  if (normalizedChi < 2) {
    result.techniques.push({ name: 'Uniform Distribution', detail: 'Very flat byte distribution (chi²/256 = ' + normalizedChi.toFixed(2) + ') — likely encrypted or compressed content', severity: 'high' });
    result.obfuscationScore += 30;
  }

  // 2. Look for XOR-encoded blocks: high entropy regions with repeating key patterns
  const blockSize = 256;
  let highEntropyBlocks = 0;
  for (let offset = 0; offset < data.length - blockSize; offset += blockSize) {
    const block = data.subarray(offset, offset + blockSize);
    const bf = new Array(256).fill(0);
    for (let i = 0; i < block.length; i++) bf[block[i]]++;
    let be = 0;
    for (let i = 0; i < 256; i++) {
      if (bf[i] > 0) { const p = bf[i] / blockSize; be -= p * Math.log2(p); }
    }
    if (be > 7.0) highEntropyBlocks++;
  }

  const totalBlocks = Math.floor(data.length / blockSize) || 1;
  const encryptedRatio = highEntropyBlocks / totalBlocks;
  result.stats.suspiciousBlocks = highEntropyBlocks;

  if (encryptedRatio > 0.5) {
    result.techniques.push({ name: 'Encrypted Payload', detail: Math.round(encryptedRatio * 100) + '% of blocks have entropy >7.0 — binary is predominantly encrypted', severity: 'high' });
    result.obfuscationScore += 25;
  } else if (encryptedRatio > 0.2) {
    result.techniques.push({ name: 'Partial Encryption', detail: Math.round(encryptedRatio * 100) + '% of blocks have high entropy — embedded encrypted sections', severity: 'medium' });
    result.obfuscationScore += 15;
  }

  // 3. Detect XOR/ROT patterns in string data
  const sampleStrings = (strings.sample || []).slice(0, 100);
  let printableRatio = 0;
  let xorCandidates = 0;

  for (const s of sampleStrings) {
    const printable = s.split('').filter(c => c.charCodeAt(0) >= 32 && c.charCodeAt(0) < 127).length;
    printableRatio += printable / s.length;

    // Check if XOR with single byte would produce readable text
    for (let key = 1; key < 256; key++) {
      const decoded = s.split('').map(c => String.fromCharCode(c.charCodeAt(0) ^ key)).join('');
      const decodedPrintable = decoded.split('').filter(c => c.charCodeAt(0) >= 32 && c.charCodeAt(0) < 127).length;
      if (decodedPrintable / decoded.length > 0.85 && decodedPrintable > 6) {
        xorCandidates++;
        break;
      }
    }
  }

  if (sampleStrings.length > 0) {
    result.stats.plaintextRatio = Math.round((printableRatio / sampleStrings.length) * 100);
  }

  if (xorCandidates > 5) {
    result.techniques.push({ name: 'XOR-Encoded Strings', detail: xorCandidates + ' strings decode to readable text with single-byte XOR — likely runtime string decryption', severity: 'high' });
    result.obfuscationScore += 20;
  } else if (xorCandidates > 0) {
    result.techniques.push({ name: 'Possible XOR Strings', detail: xorCandidates + ' strings may be XOR-encoded', severity: 'low' });
    result.obfuscationScore += 5;
  }

  // 4. Check string-to-size ratio (low ratio = hidden strings)
  const stringDensity = (strings.total || 0) / (data.length / 1024); // strings per KB
  if (stringDensity < 0.5 && data.length > 10000) {
    result.techniques.push({ name: 'Low String Density', detail: stringDensity.toFixed(2) + ' strings/KB — unusually few readable strings for binary size, possible string obfuscation', severity: 'medium' });
    result.obfuscationScore += 10;
  }

  result.obfuscationScore = Math.min(100, result.obfuscationScore);
  return result;
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
  const { askAI, onProgress, timeout = 120000, deepAnalysis = true } = options;
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

  // Phase 4: Deep Analysis (vibe-re inspired) — section entropy, disasm patterns, taint chains, MITRE, obfuscation
  if (deepAnalysis) {
    if (onProgress) onProgress({ phase: 'deep', message: 'Running deep analysis (section entropy, disassembly patterns, taint chains)...' });

    // 4a: Per-section entropy + packer detection
    const entropyResult = await analyzeEntropySections(resolvedPath, structure.sections, fileType);
    result.sectionEntropy = entropyResult.sectionEntropy;
    result.packers = entropyResult.packers;

    // Add packer risk indicators
    for (const p of entropyResult.packers) {
      result.riskIndicators.push({ indicator: 'Packer Detected: ' + p.name, detail: p.description + ' (' + p.match + ')', severity: 'high' });
    }
    // Flag anomalous sections
    for (const se of entropyResult.sectionEntropy) {
      if (se.anomaly) result.riskIndicators.push({ indicator: 'Section Anomaly: ' + se.name, detail: se.anomaly + ' (entropy: ' + se.entropy + ')', severity: 'medium' });
    }

    // 4b: Disassembly pattern detection
    const disasmPatterns = await detectDisassemblyPatterns(resolvedPath, fileType);
    result.disasmPatterns = disasmPatterns;

    for (const pat of disasmPatterns) {
      result.riskIndicators.push({ indicator: pat.name + ' (' + pat.count + 'x)', detail: pat.description, severity: pat.severity });
    }

    // 4c: Import taint chains
    const taintChains = buildImportTaintChains(allImports);
    result.taintChains = taintChains;

    for (const chain of taintChains) {
      result.riskIndicators.push({ indicator: 'Taint Chain: ' + chain.name, detail: chain.description + ' — matched: ' + chain.matchedImports.join(' → '), severity: chain.severity });
    }

    // 4d: MITRE ATT&CK mapping
    result.mitreTactics = mapMITREAttackTactics(allImports, strings.iocs, strings);

    // 4e: String obfuscation detection
    result.obfuscation = detectStringObfuscation(resolvedPath, strings);

    if (result.obfuscation.obfuscationScore > 30) {
      result.riskIndicators.push({ indicator: 'String Obfuscation Detected', detail: 'Obfuscation score: ' + result.obfuscation.obfuscationScore + '/100 — ' + result.obfuscation.techniques.map(t => t.name).join(', '), severity: result.obfuscation.obfuscationScore > 60 ? 'high' : 'medium' });
    }
  }

  // Phase 5: AI threat assessment (optional)
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

  // Deep analysis context (vibe-re inspired)
  const packerInfo = (result.packers || []).map(p => p.name + ' (' + p.match + ')').join(', ') || 'None detected';
  const chainInfo = (result.taintChains || []).map(c => c.name + ' [' + c.severity + ']: ' + c.matchedImports.join(' → ')).join('\n  ') || 'None';
  const mitreInfo = (result.mitreTactics || []).slice(0, 10).map(t => t.tid + ' ' + t.name + ' (' + t.tactic + ') — ' + t.evidence.slice(0, 3).join(', ')).join('\n  ') || 'None';
  const disasmInfo = (result.disasmPatterns || []).map(p => p.name + ' (' + p.count + 'x, ' + p.severity + ')').join(', ') || 'None';
  const obfScore = result.obfuscation ? result.obfuscation.obfuscationScore + '/100' : 'N/A';
  const obfTechniques = result.obfuscation ? (result.obfuscation.techniques || []).map(t => t.name).join(', ') || 'None' : 'N/A';
  const sectionEntropyInfo = (result.sectionEntropy || []).filter(s => s.anomaly).map(s => s.name + ': ' + s.entropy + ' (' + s.anomaly + ')').join('\n  ') || 'No anomalies';

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

DEEP ANALYSIS (vibe-re):
- Packers: ${packerInfo}
- Obfuscation Score: ${obfScore} — techniques: ${obfTechniques}
- Disassembly Patterns: ${disasmInfo}
- Section Entropy Anomalies:
  ${sectionEntropyInfo}

IMPORT TAINT CHAINS:
  ${chainInfo}

MITRE ATT&CK MAPPING:
  ${mitreInfo}

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
What capabilities does this binary appear to have based on imports, strings, structure, taint chains, and MITRE mapping?

## MITRE ATT&CK Coverage
Which ATT&CK tactics and techniques are represented? What does the tactic coverage suggest about the binary's purpose?

## IOC Summary
Key indicators of compromise found (IPs, URLs, suspicious strings, registry keys, obfuscation indicators).

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
  analyzeEntropySections,
  detectDisassemblyPatterns,
  buildImportTaintChains,
  mapMITREAttackTactics,
  detectStringObfuscation,
  SUSPICIOUS_IMPORTS,
};

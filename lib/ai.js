// Vigil — BYOK AI provider wrapper
// Supported: claude-api, claude-cli, claude-code, codex, ollama, none
const { execCommand, execFileSafe } = require('./exec');

const SECURITY_SYSTEM_PROMPT = 'You are Vigil, an AI security analyst. You analyze threats, vulnerabilities, and security configurations with precision. Be concise, actionable, and cite specific CVEs, MITRE ATT&CK techniques, or CWE IDs when relevant.';

const DEFAULT_TIMEOUT = 120000;
const API_MODEL = 'claude-sonnet-4-20250514';
const API_MAX_TOKENS = 4096;

// Ollama defaults (overridden by env vars or settings)
const OLLAMA_DEFAULT_BASE_URL = 'http://localhost:11434';
const OLLAMA_DEFAULT_MODEL = 'qwen3:8b';

// Clean env for spawning AI CLIs — strip CLAUDECODE so claude doesn't refuse to start
function getCleanEnv() {
  const env = { ...process.env };
  delete env.CLAUDECODE;
  return env;
}

// Settings file for AI provider preference
const fs = require('fs');
const path = require('path');
const SETTINGS_FILE = path.join(__dirname, '..', 'data', 'settings.json');

/**
 * Get configured AI provider
 * @returns {string} - 'claude-api', 'claude-cli', 'claude-code', 'codex', or 'none'
 */
function getProvider() {
  // Check env first
  if (process.env.AI_PROVIDER) return process.env.AI_PROVIDER;

  // Check settings file
  try {
    if (fs.existsSync(SETTINGS_FILE)) {
      const settings = JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf8'));
      if (settings.aiProvider) return settings.aiProvider;
    }
  } catch {}

  // Auto-detect: if ANTHROPIC_API_KEY is set, use claude-api
  if (process.env.ANTHROPIC_API_KEY) return 'claude-api';

  return 'none';
}

/**
 * Get Ollama base URL and model from env or settings
 * @returns {{ baseUrl: string, model: string }}
 */
function getOllamaConfig() {
  let baseUrl = process.env.OLLAMA_BASE_URL || OLLAMA_DEFAULT_BASE_URL;
  let model = process.env.OLLAMA_MODEL || OLLAMA_DEFAULT_MODEL;

  try {
    if (fs.existsSync(SETTINGS_FILE)) {
      const settings = JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf8'));
      if (settings.ollamaBaseUrl) baseUrl = settings.ollamaBaseUrl;
      if (settings.ollamaModel) model = settings.ollamaModel;
    }
  } catch {}

  return { baseUrl, model };
}

/**
 * Call Ollama chat API (non-streaming)
 * @param {string} prompt
 * @param {object} options
 * @returns {Promise<string|null>}
 */
async function callOllamaAPI(prompt, options = {}) {
  const { baseUrl, model } = getOllamaConfig();
  const timeout = options.timeout || DEFAULT_TIMEOUT;
  const includeSystem = options.includeSystemPrompt !== false;

  const messages = [];
  if (includeSystem) messages.push({ role: 'system', content: SECURITY_SYSTEM_PROMPT });
  messages.push({ role: 'user', content: prompt });

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  try {
    const res = await fetch(`${baseUrl}/api/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ model, messages, stream: false }),
      signal: controller.signal,
    });

    if (!res.ok) {
      const errText = await res.text().catch(() => '');
      console.warn(`  AI: Ollama ${res.status}: ${errText.substring(0, 200)}`);
      return null;
    }

    const data = await res.json();
    return data.message?.content?.trim() || null;
  } catch (err) {
    if (err.name === 'AbortError') {
      console.warn('  AI: Ollama timed out after ' + timeout + 'ms');
    } else {
      console.error('  AI: Ollama error —', err.message);
    }
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Get the CLI command for the current provider
 * @returns {string|null}
 */
function getAICommand() {
  const provider = getProvider();
  switch (provider) {
    case 'claude-api': return 'claude-api';
    case 'claude-cli': return 'claude';
    case 'claude-code': return 'claude';
    case 'codex': return 'codex';
    default: return null;
  }
}

/**
 * Build the full CLI command for a prompt
 * @param {string} prompt
 * @param {object} options
 * @returns {string|null}
 */
function buildCommand(prompt, options = {}) {
  const provider = getProvider();
  // Escape the prompt for shell safety
  const escaped = prompt.replace(/'/g, "'\\''");

  switch (provider) {
    case 'claude-api':
      return null; // API mode, no CLI command
    case 'claude-cli':
    case 'claude-code':
      return `claude --print -p '${escaped}'`;
    case 'codex':
      return `codex -q '${escaped}'`;
    default:
      return null;
  }
}

/**
 * Call Anthropic Messages API directly (zero dependencies, uses Node 22 fetch)
 * @param {string} prompt - User prompt
 * @param {object} options
 * @returns {Promise<string|null>}
 */
async function callAnthropicAPI(prompt, options = {}) {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    console.warn('  AI: ANTHROPIC_API_KEY not set');
    return null;
  }

  const timeout = options.timeout || DEFAULT_TIMEOUT;
  const includeSystem = options.includeSystemPrompt !== false;
  const model = options.model || API_MODEL;
  const maxTokens = options.maxTokens || API_MAX_TOKENS;

  const body = {
    model,
    max_tokens: maxTokens,
    messages: [{ role: 'user', content: prompt }],
  };
  if (includeSystem) {
    body.system = SECURITY_SYSTEM_PROMPT;
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  try {
    const res = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify(body),
      signal: controller.signal,
    });

    if (!res.ok) {
      const errText = await res.text().catch(() => '');
      console.warn(`  AI: Anthropic API ${res.status}: ${errText.substring(0, 200)}`);
      return null;
    }

    const data = await res.json();
    const text = data.content
      ?.filter(b => b.type === 'text')
      .map(b => b.text)
      .join('') || null;

    return text;
  } catch (err) {
    if (err.name === 'AbortError') {
      console.warn('  AI: Anthropic API timed out after ' + timeout + 'ms');
    } else {
      console.error('  AI: Anthropic API error —', err.message);
    }
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Send a prompt to the configured AI provider
 * @param {string} prompt - The prompt to send
 * @param {object} options
 * @param {number} options.timeout - Timeout in ms
 * @param {boolean} options.includeSystemPrompt - Prepend security system prompt (default: true)
 * @returns {Promise<string|null>} - AI response or null
 */
async function askAI(prompt, options = {}) {
  const provider = getProvider();
  if (provider === 'none') return null;

  // Use Anthropic API directly
  if (provider === 'claude-api') {
    return callAnthropicAPI(prompt, options);
  }

  // Use local Ollama
  if (provider === 'ollama') {
    return callOllamaAPI(prompt, options);
  }

  const timeout = options.timeout || DEFAULT_TIMEOUT;
  const includeSystem = options.includeSystemPrompt !== false;

  const fullPrompt = includeSystem
    ? SECURITY_SYSTEM_PROMPT + '\n\n' + prompt
    : prompt;

  let bin, args;
  switch (provider) {
    case 'claude-cli':
    case 'claude-code':
      bin = 'claude'; args = ['--print', '-p', fullPrompt]; break;
    case 'codex':
      bin = 'codex'; args = ['-q', fullPrompt]; break;
    default:
      return null;
  }

  try {
    const result = await execFileSafe(bin, args, {
      timeout, env: getCleanEnv()
    });

    if (result.code !== 0) {
      console.warn('  AI: command failed (code ' + result.code + '):', result.stderr.substring(0, 200));
      return null;
    }

    return result.stdout.trim() || null;
  } catch (err) {
    console.error('  AI: error —', err.message);
    return null;
  }
}

/**
 * Send a prompt and parse JSON from the response
 * Falls back to regex extraction for ```json blocks
 * @param {string} prompt
 * @param {object} options
 * @returns {Promise<object|null>}
 */
async function askAIJSON(prompt, options = {}) {
  const jsonPrompt = prompt + '\n\nRespond with valid JSON only. No markdown, no explanation.';
  const response = await askAI(jsonPrompt, options);

  if (!response) return null;

  // Try direct JSON parse
  try {
    return JSON.parse(response);
  } catch {}

  // Try extracting from ```json blocks
  const jsonBlockMatch = response.match(/```(?:json)?\s*\n?([\s\S]*?)```/);
  if (jsonBlockMatch) {
    try {
      return JSON.parse(jsonBlockMatch[1].trim());
    } catch {}
  }

  // Try finding JSON object/array in response
  const objMatch = response.match(/\{[\s\S]*\}/);
  if (objMatch) {
    try {
      return JSON.parse(objMatch[0]);
    } catch {}
  }

  const arrMatch = response.match(/\[[\s\S]*\]/);
  if (arrMatch) {
    try {
      return JSON.parse(arrMatch[0]);
    } catch {}
  }

  console.warn('  AI: could not parse JSON from response');
  return null;
}

/**
 * Stream AI output via callback (for terminal/socket)
 * @param {string} prompt
 * @param {Function} onData - Callback for each chunk of output
 * @param {object} options
 * @returns {Promise<{success: boolean, output: string}>}
 */
async function streamAI(prompt, onData, options = {}) {
  const provider = getProvider();
  if (provider === 'none') {
    if (onData) onData('AI provider not configured\n');
    return { success: false, output: '' };
  }

  // For API mode, use streaming endpoint
  if (provider === 'claude-api') {
    const apiKey = process.env.ANTHROPIC_API_KEY;
    if (!apiKey) {
      if (onData) onData('ANTHROPIC_API_KEY not set\n');
      return { success: false, output: '' };
    }

    const timeout = options.timeout || 60000;
    const includeSystem = options.includeSystemPrompt !== false;
    const body = {
      model: API_MODEL,
      max_tokens: API_MAX_TOKENS,
      stream: true,
      messages: [{ role: 'user', content: prompt }],
    };
    if (includeSystem) body.system = SECURITY_SYSTEM_PROMPT;

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

    try {
      const res = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': apiKey,
          'anthropic-version': '2023-06-01',
        },
        body: JSON.stringify(body),
        signal: controller.signal,
      });

      if (!res.ok) {
        const errText = await res.text().catch(() => '');
        if (onData) onData('API error: ' + res.status + '\n');
        return { success: false, output: '' };
      }

      let output = '';
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });

        const lines = buffer.split('\n');
        buffer = lines.pop() || '';

        for (const line of lines) {
          if (!line.startsWith('data: ')) continue;
          const jsonStr = line.slice(6);
          if (jsonStr === '[DONE]') continue;
          try {
            const event = JSON.parse(jsonStr);
            if (event.type === 'content_block_delta' && event.delta?.text) {
              output += event.delta.text;
              if (onData) onData(event.delta.text);
            }
          } catch {}
        }
      }

      return { success: true, output };
    } catch (err) {
      if (onData) onData('Error: ' + err.message + '\n');
      return { success: false, output: '' };
    } finally {
      clearTimeout(timer);
    }
  }

  // Ollama streaming
  if (provider === 'ollama') {
    const { baseUrl, model } = getOllamaConfig();
    const timeout = options.timeout || 60000;
    const includeSystem = options.includeSystemPrompt !== false;

    const messages = [];
    if (includeSystem) messages.push({ role: 'system', content: SECURITY_SYSTEM_PROMPT });
    messages.push({ role: 'user', content: prompt });

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

    try {
      const res = await fetch(`${baseUrl}/api/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ model, messages, stream: true }),
        signal: controller.signal,
      });

      if (!res.ok) {
        if (onData) onData('Ollama error: ' + res.status + '\n');
        return { success: false, output: '' };
      }

      let output = '';
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });

        const lines = buffer.split('\n');
        buffer = lines.pop() || '';

        for (const line of lines) {
          if (!line.trim()) continue;
          try {
            const event = JSON.parse(line);
            if (event.message?.content) {
              output += event.message.content;
              if (onData) onData(event.message.content);
            }
          } catch {}
        }
      }

      return { success: true, output };
    } catch (err) {
      if (onData) onData('Error: ' + err.message + '\n');
      return { success: false, output: '' };
    } finally {
      clearTimeout(timer);
    }
  }

  // CLI-based streaming
  const { spawn } = require('child_process');
  const timeout = options.timeout || 60000;
  const includeSystem = options.includeSystemPrompt !== false;
  const fullPrompt = includeSystem
    ? SECURITY_SYSTEM_PROMPT + '\n\n' + prompt
    : prompt;

  return new Promise((resolve) => {
    let args;
    let bin;

    switch (provider) {
      case 'claude-cli':
      case 'claude-code':
        bin = 'claude';
        args = ['--print', '-p', fullPrompt];
        break;
      case 'codex':
        bin = 'codex';
        args = ['-q', fullPrompt];
        break;
      default:
        resolve({ success: false, output: '' });
        return;
    }

    let output = '';
    const proc = spawn(bin, args, {
      timeout,
      env: getCleanEnv(),
      windowsHide: true
    });

    proc.stdout.on('data', (data) => {
      const chunk = data.toString();
      output += chunk;
      if (onData) onData(chunk);
    });

    proc.stderr.on('data', (data) => {
      const chunk = data.toString();
      if (onData) onData(chunk);
    });

    proc.on('close', (code) => {
      resolve({ success: code === 0, output });
    });

    proc.on('error', (err) => {
      if (onData) onData('Error: ' + err.message + '\n');
      resolve({ success: false, output });
    });

    // Timeout kill
    setTimeout(() => {
      try { proc.kill(); } catch {}
    }, timeout);
  });
}

module.exports = {
  askAI,
  askAIJSON,
  getAICommand,
  getProvider,
  streamAI,
  SECURITY_SYSTEM_PROMPT
};

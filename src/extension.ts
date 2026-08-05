import * as vscode from 'vscode';
import { ChatLogger } from './chatLogger';
import { DLPEngine } from './dlpEngine';
import { ResponseScanner } from './responseScanner';

let logger: ChatLogger;
let dlpEngine: DLPEngine;
let responseScanner: ResponseScanner;
let isActive = false;

export function activate(context: vscode.ExtensionContext) {
  logger = new ChatLogger();
  dlpEngine = new DLPEngine(logger);
  responseScanner = new ResponseScanner(dlpEngine, logger);

  // Commands
  const startCmd = vscode.commands.registerCommand('agentx-dlp.start', () => {
    if (isActive) {
      vscode.window.showInformationMessage('AgentX DLP is already active');
      return;
    }
    start();
  });

  const stopCmd = vscode.commands.registerCommand('agentx-dlp.stop', () => {
    if (!isActive) {
      vscode.window.showInformationMessage('AgentX DLP is not active');
      return;
    }
    stop();
  });

  const showLogsCmd = vscode.commands.registerCommand('agentx-dlp.showLogs', () => {
    showLogsPanel(context);
  });

  const clearLogsCmd = vscode.commands.registerCommand('agentx-dlp.clearLogs', () => {
    logger.clearLogs();
    vscode.window.showInformationMessage('AgentX DLP: logs cleared');
  });

  context.subscriptions.push(startCmd, stopCmd, showLogsCmd, clearLogsCmd);
  context.subscriptions.push({ dispose: () => responseScanner.dispose() });

  // Auto-start unless disabled
  const config = vscode.workspace.getConfiguration('agentxDlp');
  if (config.get('enabled', true)) start();
}

export function deactivate() {
  if (isActive) stop();
  logger?.log('info', 'AgentX DLP deactivated');
}

function start() {
  try {
    responseScanner.start();
    isActive = true;
    vscode.window.showInformationMessage('AgentX DLP: monitoring started');
    logger.log('info', 'AgentX DLP started');
  } catch (err) {
    vscode.window.showErrorMessage(`AgentX DLP failed to start: ${err}`);
    logger.log('error', `Failed to start: ${err}`);
  }
}

function stop() {
  try {
    responseScanner.stop();
    isActive = false;
    vscode.window.showInformationMessage('AgentX DLP: monitoring stopped');
    logger.log('info', 'AgentX DLP stopped');
  } catch (err) {
    vscode.window.showErrorMessage(`AgentX DLP failed to stop: ${err}`);
  }
}

// ── Log viewer ────────────────────────────────────────────────────────────────

function showLogsPanel(context: vscode.ExtensionContext) {
  const panel = vscode.window.createWebviewPanel(
    'agentxDlpLogs',
    'AgentX DLP — Activity Log',
    vscode.ViewColumn.One,
    { enableScripts: true }
  );

  panel.webview.html = renderLogsHtml(logger.getLogs());

  panel.webview.onDidReceiveMessage(
    msg => {
      if (msg.command === 'refresh') {
        panel.webview.postMessage({ command: 'updateLogs', logs: logger.getLogs() });
      } else if (msg.command === 'clear') {
        logger.clearLogs();
        panel.webview.postMessage({ command: 'updateLogs', logs: [] });
      }
    },
    undefined,
    context.subscriptions
  );
}

function renderLogsHtml(logs: ReturnType<ChatLogger['getLogs']>): string {
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>AgentX DLP Logs</title>
<style>
  body { font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
         background:#1e1e1e; color:#d4d4d4; padding:20px; margin:0; line-height:1.5; }
  .header { background:#2d2d30; padding:18px 20px; margin:-20px -20px 18px;
            border-bottom:1px solid #3e3e42; }
  h1 { margin:0; color:#f97316; font-size:20px; }
  .subtitle { color:#858585; font-size:12px; margin-top:4px; }
  .controls { display:flex; gap:8px; margin-bottom:16px; }
  .btn { padding:6px 14px; border:none; border-radius:4px; cursor:pointer;
         font-size:13px; font-weight:500; }
  .btn-primary { background:#f97316; color:#fff; }
  .btn-secondary { background:#3c3c3c; color:#d4d4d4; }
  .log-entry { margin:8px 0; padding:12px 14px; border-left:3px solid #3e3e42;
               background:#2d2d30; border-radius:3px; }
  .log-entry.warn  { border-left-color:#fb923c; }
  .log-entry.error { border-left-color:#ef4444; }
  .log-entry.info  { border-left-color:#3b82f6; }
  .log-entry.debug { border-left-color:#6a9955; }
  .timestamp { color:#858585; font-size:11px; font-family:monospace; }
  .level { display:inline-block; padding:1px 7px; border-radius:10px; font-size:10px;
           font-weight:600; margin-right:6px; }
  .level.warn  { background:#fb923c; color:#1e1e1e; }
  .level.error { background:#ef4444; color:#fff; }
  .level.info  { background:#3b82f6; color:#fff; }
  .level.debug { background:#6a9955; color:#fff; }
  pre { margin:8px 0 0; padding:10px; background:#1e1e1e; border-radius:3px;
        font-size:11px; color:#9cdcfe; overflow-x:auto; }
  .empty { text-align:center; color:#858585; padding:40px; background:#2d2d30;
           border-radius:6px; border:1px dashed #3e3e42; }
</style></head>
<body>
<div class="header">
  <h1>&#128737; AgentX DLP — Activity Log</h1>
  <div class="subtitle">Total events: ${logs.length}</div>
</div>

<div class="controls">
  <button class="btn btn-primary"   onclick="refresh()">Refresh</button>
  <button class="btn btn-secondary" onclick="clearAll()">Clear</button>
</div>

<div id="log-container">
  ${renderLogEntries(logs)}
</div>

<script>
  const vscode = acquireVsCodeApi();
  function refresh()  { vscode.postMessage({ command:'refresh' }); }
  function clearAll() { if (confirm('Clear all logs?')) vscode.postMessage({ command:'clear' }); }

  window.addEventListener('message', e => {
    if (e.data.command === 'updateLogs') {
      document.getElementById('log-container').innerHTML = renderEntries(e.data.logs);
    }
  });

  function renderEntries(logs) {
    if (!logs.length) return '<div class="empty">No DLP events recorded yet.</div>';
    return logs.map(l => {
      const data = l.data ? '<pre>' + escapeHtml(JSON.stringify(l.data, null, 2)) + '</pre>' : '';
      return '<div class="log-entry ' + l.level + '">' +
             '<div class="timestamp">' + new Date(l.timestamp).toLocaleString() + '</div>' +
             '<span class="level ' + l.level + '">' + l.level.toUpperCase() + '</span>' +
             escapeHtml(l.message) + data + '</div>';
    }).join('');
  }
  function escapeHtml(s) {
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }
</script>
</body></html>`;
}

function renderLogEntries(logs: ReturnType<ChatLogger['getLogs']>): string {
  if (logs.length === 0) {
    return '<div class="empty">No DLP events recorded yet.</div>';
  }
  return logs.map(l => {
    const data = l.data ? `<pre>${escapeHtml(JSON.stringify(l.data, null, 2))}</pre>` : '';
    return `<div class="log-entry ${l.level}">
      <div class="timestamp">${new Date(l.timestamp).toLocaleString()}</div>
      <span class="level ${l.level}">${l.level.toUpperCase()}</span>${escapeHtml(l.message)}${data}
    </div>`;
  }).join('');
}

function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

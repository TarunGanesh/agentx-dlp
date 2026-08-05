import * as vscode from 'vscode';
import { DLPEngine, DLPMatch } from './dlpEngine';
import { IntentResult } from './intentAnalyzer';
import { ChatLogger } from './chatLogger';

/**
 * ResponseScanner
 *
 * Covers Scenarios A and C:
 *   A) AI suggests a public sharing destination in prose ("create a gist at…")
 *   C) AI embeds a public URL/command in a code block in the chat
 *
 * Approach:
 *   1. Monitor active text editor for AI-generated content containing exfil patterns
 *   2. Monitor clipboard: warn when the user copies/pastes text that contains
 *      exfil commands (catches "user follows AI suggestion" workflow)
 *   3. Monitor VS Code terminal write events for commands being executed
 *   4. Maintain a status-bar indicator showing DLP state
 */
export class ResponseScanner {
  private dlp: DLPEngine;
  private logger: ChatLogger;
  private isActive = false;
  private disposables: vscode.Disposable[] = [];
  private statusBarItem: vscode.StatusBarItem;
  private lastClipboard = '';
  private clipboardPollHandle: ReturnType<typeof setInterval> | null = null;

  // Track files the user is editing that are sensitive so we can apply
  // stricter warnings when those files are mentioned in AI responses.
  private openSensitiveFiles: Set<string> = new Set();

  constructor(dlp: DLPEngine, logger: ChatLogger) {
    this.dlp = dlp;
    this.logger = logger;

    this.statusBarItem = vscode.window.createStatusBarItem(
      vscode.StatusBarAlignment.Right,
      100
    );
    this.statusBarItem.command = 'cursor-chat-proxy.showLogs';
    this.setStatusBarSafe();
    this.statusBarItem.show();
  }

  start() {
    if (this.isActive) return;
    this.isActive = true;
    this.logger.log('info', 'ResponseScanner started');

    this.watchActiveEditor();
    this.watchDocumentSaves();
    this.watchTerminalOutput();
    this.startClipboardPolling();
    this.trackOpenFiles();

    this.setStatusBarActive();
  }

  stop() {
    if (!this.isActive) return;
    this.isActive = false;

    this.disposables.forEach(d => d.dispose());
    this.disposables = [];

    if (this.clipboardPollHandle) {
      clearInterval(this.clipboardPollHandle);
      this.clipboardPollHandle = null;
    }

    this.setStatusBarSafe();
    this.logger.log('info', 'ResponseScanner stopped');
  }

  dispose() {
    this.stop();
    this.statusBarItem.dispose();
  }

  // ── Watcher: active editor ─────────────────────────────────────────────────

  private watchActiveEditor() {
    const d = vscode.window.onDidChangeActiveTextEditor(editor => {
      if (!editor) return;
      this.scanDocument(editor.document);
    });
    this.disposables.push(d);

    // Also scan the current editor on start
    if (vscode.window.activeTextEditor) {
      this.scanDocument(vscode.window.activeTextEditor.document);
    }
  }

  private watchDocumentSaves() {
    // Re-scan on every save — catches the workflow where a user saves
    // an AI-generated markdown/text file containing exfil suggestions.
    const d = vscode.workspace.onDidSaveTextDocument(doc => {
      this.scanDocument(doc);
    });
    this.disposables.push(d);
  }

  private scanDocument(document: vscode.TextDocument) {
    const text = document.getText();
    if (text.length < 20) return; // Skip trivially short docs

    const result = this.dlp.scanAIResponse(text);
    if (result.violations.length === 0) return;

    const highViolations = result.violations.filter(v => v.severity === 'high');
    if (highViolations.length === 0) return;

    const contextNote = this.openSensitiveFiles.size > 0
      ? ` You currently have sensitive architecture/infrastructure files open.`
      : '';

    this.showDLPWarning(
      `AI response contains public sharing suggestions`,
      highViolations,
      contextNote
    );
  }

  // ── Watcher: terminal output ───────────────────────────────────────────────

  private watchTerminalOutput() {
    // onDidWriteTerminalData was added in VS Code 1.85. Guard for older hosts.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const api = vscode.window as any;
    if (typeof api.onDidWriteTerminalData !== 'function') return;

    const d = api.onDidWriteTerminalData((event: { data: string }) => {
      const result = this.dlp.scanCommand(event.data);
      if (result.violations.length > 0) {
        this.logger.log('warn', 'DLP: Exfil command detected in terminal output', {
          violations: result.violations,
        });
        this.showPostExecutionWarning(result.violations);
      }
    });
    this.disposables.push(d);
  }

  // ── Watcher: clipboard polling ─────────────────────────────────────────────
  // VS Code doesn't have a clipboard change event, so we poll every 2s.
  // This catches: user copies AI-suggested command → we warn before they run it.

  private startClipboardPolling() {
    this.clipboardPollHandle = setInterval(async () => {
      if (!this.isActive) return;
      try {
        const text = await vscode.env.clipboard.readText();
        if (text === this.lastClipboard || text.length < 5) return;
        this.lastClipboard = text;
        this.checkClipboard(text);
      } catch {
        // Clipboard read can fail on some platforms — ignore silently.
      }
    }, 2000);
  }

  private checkClipboard(text: string) {
    // Layer 1: fast pattern match
    const cmdResult = this.dlp.scanCommand(text);
    if (cmdResult.violations.length > 0) {
      this.showClipboardWarning(cmdResult.violations, 'command');
      return;
    }

    // Layer 2: AI response text patterns
    const responseResult = this.dlp.scanAIResponse(text);
    const highViolations = responseResult.violations.filter(v => v.severity === 'high');
    if (highViolations.length > 0) {
      this.showClipboardWarning(highViolations, 'suggestion');
      return;
    }

    // Layer 3: AI intent classification — runs when the clipboard text looks
    // like it might be moving data somewhere but patterns didn't catch it.
    // Only fires when there are data-movement signals to keep latency low.
    if (this.looksLikeDataMovement(text)) {
      const sensitiveFiles = [...this.openSensitiveFiles];
      const result = this.dlp.intentAnalyzer.analyze({ text, sensitiveFiles });
      if (!result.skipped && result.is_exfil && (result.risk === 'high' || result.risk === 'medium')) {
        this.showAIIntentWarning(result, 'clipboard');
      }
    }
  }

  private looksLikeDataMovement(text: string): boolean {
    return /\b(?:curl|wget|scp|rsync|sftp|nc\b|git\s+push|gh\s+gist|gh\s+repo|aws\s+s3|gsutil|docker\s+push|npm\s+publish|sendgrid|mailgun|webhook)\b/i.test(text);
  }

  // ── Watcher: track open sensitive files ───────────────────────────────────

  private trackOpenFiles() {
    // Build initial set from already-open editors
    vscode.window.visibleTextEditors.forEach(e => {
      if (this.dlp.isSensitiveFile(e.document.fileName)) {
        this.openSensitiveFiles.add(e.document.fileName);
      }
    });

    const onOpen = vscode.workspace.onDidOpenTextDocument(doc => {
      if (this.dlp.isSensitiveFile(doc.fileName)) {
        this.openSensitiveFiles.add(doc.fileName);
        this.logger.log('info', 'DLP: Sensitive file opened — stricter scanning active', {
          file: doc.fileName,
        });
        vscode.window.setStatusBarMessage(
          `$(shield) DLP: Sensitive file detected — enhanced monitoring active`,
          5000
        );
      }
    });

    const onClose = vscode.workspace.onDidCloseTextDocument(doc => {
      this.openSensitiveFiles.delete(doc.fileName);
    });

    this.disposables.push(onOpen, onClose);
  }

  // ── Notification helpers ───────────────────────────────────────────────────

  private showDLPWarning(
    title: string,
    violations: DLPMatch[],
    contextNote = ''
  ) {
    const detail = violations.map(v => `• ${v.description}`).join('\n');
    const message = `DLP Warning: ${title}.${contextNote}\n\n${detail}`;

    vscode.window.showWarningMessage(
      `$(shield) DLP: ${title}${contextNote}`,
      { modal: false },
      'View Details',
      'Dismiss'
    ).then(selection => {
      if (selection === 'View Details') {
        this.showDLPDetailPanel(title, violations, contextNote);
      }
    });

    this.logger.log('warn', `DLP Warning shown: ${title}`, { violations });
  }

  private showAIIntentWarning(result: IntentResult, source: string) {
    const label = result.risk === 'high'
      ? `$(error) DLP [AI]: Likely exfiltration attempt in ${source}`
      : `$(warning) DLP [AI]: Possible exfiltration in ${source}`;

    vscode.window.showWarningMessage(label, 'View Details', 'Dismiss')
      .then(sel => {
        if (sel === 'View Details') {
          this.showAIIntentDetailPanel(result, source);
        }
      });

    this.logger.log('warn', `DLP AI intent warning (${source})`, {
      risk: result.risk,
      reason: result.reason,
      destination: result.destination,
      technique: result.technique,
    });
  }

  private showAIIntentDetailPanel(result: IntentResult, source: string) {
    const panel = vscode.window.createWebviewPanel(
      'dlpAIWarning', 'DLP Alert — AI Detection', vscode.ViewColumn.Beside,
      { enableScripts: false }
    );
    panel.webview.html = buildAIDetailHtml(result, source);
  }

  private showPostExecutionWarning(violations: DLPMatch[]) {
    const descriptions = violations.map(v => `• ${v.description}`).join('\n');
    vscode.window.showErrorMessage(
      `$(error) DLP: Potential data exfiltration command executed in terminal!`,
      { modal: false },
      'View Details'
    ).then(selection => {
      if (selection === 'View Details') {
        this.showDLPDetailPanel('Exfiltration command executed', violations,
          '\n\nIf sensitive data was transmitted, notify your security team immediately.');
      }
    });
  }

  private showClipboardWarning(violations: DLPMatch[], type: 'command' | 'suggestion') {
    const label = type === 'command'
      ? 'Clipboard contains a data-exfiltration command'
      : 'Clipboard contains a suggestion to share data publicly';

    vscode.window.showWarningMessage(
      `$(shield) DLP: ${label}`,
      { modal: false },
      'View Details',
      'Dismiss'
    ).then(selection => {
      if (selection === 'View Details') {
        this.showDLPDetailPanel(label, violations);
      }
    });

    this.logger.log('warn', `DLP Clipboard warning: ${label}`, { violations });
  }

  private showDLPDetailPanel(
    title: string,
    violations: DLPMatch[],
    extraNote = ''
  ) {
    const panel = vscode.window.createWebviewPanel(
      'dlpWarning',
      'DLP Alert',
      vscode.ViewColumn.Beside,
      { enableScripts: false }
    );

    panel.webview.html = buildDetailHtml(title, violations, extraNote);
  }

  // ── Status bar ─────────────────────────────────────────────────────────────

  private setStatusBarSafe() {
    this.statusBarItem.text = '$(shield) DLP';
    this.statusBarItem.tooltip = 'DLP Monitor (inactive) — click to view logs';
    this.statusBarItem.backgroundColor = undefined;
  }

  private setStatusBarActive() {
    this.statusBarItem.text = '$(shield) DLP Active';
    this.statusBarItem.tooltip = 'DLP Monitor is active — click to view logs';
    this.statusBarItem.backgroundColor = undefined;
  }
}

// ── Detail panel HTML ────────────────────────────────────────────────────────

function buildDetailHtml(title: string, violations: DLPMatch[], extraNote: string): string {
  const rows = violations.map(v => `
    <tr class="${v.severity}">
      <td><span class="badge ${v.severity}">${v.severity.toUpperCase()}</span></td>
      <td>${escHtml(v.description)}</td>
      <td><code>${escHtml(v.matchedText)}</code></td>
    </tr>`).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DLP Alert</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         background:#1e1e1e; color:#d4d4d4; padding:24px; margin:0; }
  h1   { color:#f97316; font-size:20px; margin:0 0 4px; }
  .subtitle { color:#858585; font-size:13px; margin-bottom:20px; }
  table { width:100%; border-collapse:collapse; margin-top:16px; }
  th    { text-align:left; padding:8px 12px; background:#2d2d30;
          color:#858585; font-size:12px; text-transform:uppercase; }
  td    { padding:10px 12px; border-bottom:1px solid #3e3e42; vertical-align:top; }
  tr.high td { background: rgba(239,68,68,.07); }
  tr.medium td { background: rgba(251,146,60,.07); }
  .badge { display:inline-block; padding:2px 8px; border-radius:12px;
           font-size:11px; font-weight:600; }
  .badge.high   { background:#ef4444; color:#fff; }
  .badge.medium { background:#fb923c; color:#1e1e1e; }
  .badge.low    { background:#6a9955; color:#fff; }
  code { font-family:'SF Mono',Monaco,Consolas,monospace; font-size:12px;
         color:#9cdcfe; word-break:break-all; }
  .note { margin-top:20px; padding:14px; background:#2d2d30; border-left:3px solid #f97316;
          border-radius:4px; font-size:13px; line-height:1.6; }
  .alternatives { margin-top:20px; }
  .alternatives h3 { color:#9cdcfe; font-size:14px; margin:0 0 8px; }
  .alternatives li { margin:4px 0; font-size:13px; }
</style>
</head>
<body>
<h1>&#9888; DLP Policy Violation</h1>
<div class="subtitle">${escHtml(title)}</div>

<table>
  <thead><tr><th>Severity</th><th>Description</th><th>Matched</th></tr></thead>
  <tbody>${rows}</tbody>
</table>

${extraNote ? `<div class="note">${escHtml(extraNote)}</div>` : ''}

<div class="alternatives">
  <h3>Approved alternatives for sharing content:</h3>
  <ul>
    <li>GitHub Gist with <code>--secret</code> flag: <code>gh gist create --secret &lt;file&gt;</code></li>
    <li>Private GitHub repository: <code>gh repo create --private &lt;name&gt;</code></li>
    <li>Internal Confluence page (company knowledge base)</li>
    <li>Slack DM or private channel to specific recipients</li>
    <li>Company-managed Google Drive (with restricted sharing)</li>
  </ul>
</div>
</body>
</html>`;
}

function buildAIDetailHtml(result: IntentResult, source: string): string {
  const badgeColor = result.risk === 'high' ? '#ef4444' : result.risk === 'medium' ? '#fb923c' : '#6a9955';
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>DLP Alert</title>
<style>
  body { font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
         background:#1e1e1e; color:#d4d4d4; padding:24px; margin:0; }
  h1   { color:#f97316; font-size:20px; margin:0 0 4px; }
  .subtitle { color:#858585; font-size:13px; margin-bottom:20px; }
  .badge { display:inline-block; padding:3px 10px; border-radius:12px;
           font-size:12px; font-weight:600; background:${badgeColor}; color:#fff; }
  .field { margin:12px 0; }
  .label { color:#858585; font-size:11px; text-transform:uppercase; letter-spacing:.5px; margin-bottom:4px; }
  .value { font-size:14px; }
  .note { margin-top:20px; padding:14px; background:#2d2d30; border-left:3px solid #f97316;
          border-radius:4px; font-size:13px; line-height:1.6; }
  .alternatives li { margin:4px 0; font-size:13px; }
  code { font-family:'SF Mono',Monaco,Consolas,monospace; font-size:12px; color:#9cdcfe; }
</style>
</head>
<body>
<h1>&#9888; DLP Alert — Semantic Detection</h1>
<div class="subtitle">Source: ${escHtml(source)}</div>

<div class="field">
  <div class="label">Risk level</div>
  <span class="badge">${result.risk.toUpperCase()}</span>
</div>

<div class="field">
  <div class="label">Reason</div>
  <div class="value">${escHtml(result.reason)}</div>
</div>

${result.destination ? `
<div class="field">
  <div class="label">Identified destination</div>
  <div class="value"><code>${escHtml(result.destination)}</code></div>
</div>` : ''}

${result.technique ? `
<div class="field">
  <div class="label">Exfil technique</div>
  <div class="value">${escHtml(result.technique)}</div>
</div>` : ''}

<div class="note">
  This alert was raised by structural data-flow analysis (no AI call).<br>
  If this is a false positive, contact <strong>#security</strong> to refine the allowlist.
</div>

<div class="alternatives" style="margin-top:20px">
  <h3 style="color:#9cdcfe;font-size:14px;margin:0 0 8px">Approved sharing options:</h3>
  <ul>
    <li><code>gh gist create --secret &lt;file&gt;</code></li>
    <li><code>gh repo create --private &lt;name&gt;</code></li>
    <li>Confluence — your-company.atlassian.net</li>
    <li>Slack DM / private channel — your-company.slack.com</li>
  </ul>
</div>
</body></html>`;
}

function escHtml(s: string): string {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

import * as vscode from 'vscode';
import * as http from 'http';
import * as https from 'https';
import * as url from 'url';
import * as path from 'path';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface Finding {
  cwe: string;
  severity: string;
  title: string;
  description: string;
  remediation: string;
  line_number: number;
  original_line_content: string;
  dismissal_fingerprint?: string;
  source?: string;
}

interface ScanResponse {
  findings: Finding[];
  scan_time_ms: number;
  cache_hit: boolean;
  changed_lines: [number, number] | null;
}

// ---------------------------------------------------------------------------
// Config helpers
// ---------------------------------------------------------------------------

function cfg(): vscode.WorkspaceConfiguration {
  return vscode.workspace.getConfiguration('chakra');
}

function getServerUrl(): string {
  return cfg().get<string>('serverUrl', 'http://127.0.0.1:7777').replace(/\/$/, '');
}

function getOrgId(): string {
  return cfg().get<string>('organizationId', 'default');
}

function getDevId(): string {
  return cfg().get<string>('developerId', 'anon');
}

function getAuthToken(): string {
  return cfg().get<string>('authToken', '');
}

/** Returns true when serverUrl points at localhost / 127.x.x.x / ::1 */
function isLocalServer(): boolean {
  const raw = getServerUrl();
  try {
    const parsed = new url.URL(raw);
    const h = parsed.hostname.toLowerCase();
    return h === 'localhost' || h === '127.0.0.1' || h === '::1' || h.startsWith('127.');
  } catch {
    return true; // default safe
  }
}

/**
 * Build the filepath to send in requests.
 * - Localhost → absolute path (server can access the same filesystem)
 * - Remote   → workspace-relative path (server cannot read absolute local paths)
 */
function buildFilepath(documentUri: vscode.Uri): string {
  const absolute = documentUri.fsPath;
  if (isLocalServer()) {
    return absolute;
  }
  const folders = vscode.workspace.workspaceFolders;
  if (folders && folders.length > 0) {
    const rootPath = folders[0].uri.fsPath;
    const rel = path.relative(rootPath, absolute);
    return rel.replace(/\\/g, '/');
  }
  return path.basename(absolute);
}

/** Build HTTP/HTTPS request headers, injecting Auth if configured. */
function buildHeaders(extra?: Record<string, string>): Record<string, string> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...extra,
  };
  const token = getAuthToken();
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  return headers;
}

// ---------------------------------------------------------------------------
// HTTP utility
// ---------------------------------------------------------------------------

function httpPost(endpoint: string, body: object): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const raw = getServerUrl();
    const fullUrl = `${raw}${endpoint}`;
    let parsed: url.URL;
    try {
      parsed = new url.URL(fullUrl);
    } catch (e) {
      reject(new Error(`Invalid CHAKRA server URL: ${fullUrl}`));
      return;
    }

    const payload = Buffer.from(JSON.stringify(body));
    const options: http.RequestOptions = {
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: parsed.pathname,
      method: 'POST',
      headers: buildHeaders({ 'Content-Length': String(payload.length) }),
    };

    const transport = parsed.protocol === 'https:' ? https : http;
    const req = transport.request(options, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c: Buffer) => chunks.push(c));
      res.on('end', () => resolve(Buffer.concat(chunks)));
    });

    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

// ---------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------

const SEVERITY_MAP: Record<string, vscode.DiagnosticSeverity> = {
  critical: vscode.DiagnosticSeverity.Error,
  high: vscode.DiagnosticSeverity.Error,
  medium: vscode.DiagnosticSeverity.Warning,
  low: vscode.DiagnosticSeverity.Information,
  info: vscode.DiagnosticSeverity.Hint,
};

function buildDiagnostic(finding: Finding, doc: vscode.TextDocument): vscode.Diagnostic {
  const lineIdx = Math.max(0, (finding.line_number || 1) - 1);
  const line = doc.lineAt(Math.min(lineIdx, doc.lineCount - 1));
  const range = new vscode.Range(line.range.start, line.range.end);

  const sev = SEVERITY_MAP[finding.severity?.toLowerCase()] ?? vscode.DiagnosticSeverity.Warning;
  const message = `[CHAKRA ${finding.cwe}] ${finding.title}: ${finding.description}`;

  const diag = new vscode.Diagnostic(range, message, sev);
  diag.source = 'CHAKRA';
  diag.code = finding.cwe;
  // Store the full finding for CodeLens / hover use
  (diag as unknown as { chakraFinding: Finding }).chakraFinding = finding;
  return diag;
}

// ---------------------------------------------------------------------------
// CodeLens provider
// ---------------------------------------------------------------------------

class ChakraCodeLensProvider implements vscode.CodeLensProvider {
  private _onDidChangeCodeLenses = new vscode.EventEmitter<void>();
  readonly onDidChangeCodeLenses = this._onDidChangeCodeLenses.event;

  private findingsMap = new Map<string, Finding[]>();

  update(uri: vscode.Uri, findings: Finding[]): void {
    this.findingsMap.set(uri.toString(), findings);
    this._onDidChangeCodeLenses.fire();
  }

  clear(uri: vscode.Uri): void {
    this.findingsMap.delete(uri.toString());
    this._onDidChangeCodeLenses.fire();
  }

  provideCodeLenses(document: vscode.TextDocument): vscode.CodeLens[] {
    const findings = this.findingsMap.get(document.uri.toString()) ?? [];
    return findings.map((f) => {
      const lineIdx = Math.max(0, (f.line_number || 1) - 1);
      const line = document.lineAt(Math.min(lineIdx, document.lineCount - 1));
      const range = new vscode.Range(line.range.start, line.range.start);
      return new vscode.CodeLens(range, {
        title: `⚠ CHAKRA: ${f.cwe} — ${f.title} (click to dismiss)`,
        command: 'chakra.dismissFinding',
        arguments: [document.uri, f],
        tooltip: `${f.description}\n\nRemediation: ${f.remediation}`,
      });
    });
  }
}

// ---------------------------------------------------------------------------
// Status bar
// ---------------------------------------------------------------------------

type StatusState = 'idle' | 'scanning' | 'clean' | 'findings' | 'error';

function applyStatusState(
  item: vscode.StatusBarItem,
  state: StatusState,
  count?: number,
): void {
  switch (state) {
    case 'scanning':
      item.text = '$(sync~spin) CHAKRA: Scanning…';
      item.backgroundColor = undefined;
      item.tooltip = 'CHAKRA is scanning your file…';
      break;
    case 'clean':
      item.text = '$(shield) CHAKRA: Clean';
      item.backgroundColor = undefined;
      item.tooltip = 'No security findings detected by CHAKRA.';
      break;
    case 'findings':
      item.text = `$(warning) CHAKRA: ${count} finding${count === 1 ? '' : 's'}`;
      item.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
      item.tooltip = `CHAKRA found ${count} security issue${count === 1 ? '' : 's'} in this file.`;
      break;
    case 'error':
      item.text = '$(error) CHAKRA: Error';
      item.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
      item.tooltip = 'CHAKRA could not reach the backend server. Check chakra.serverUrl setting.';
      break;
    default:
      item.text = '$(shield) CHAKRA';
      item.backgroundColor = undefined;
      item.tooltip = 'CHAKRA Security — idle';
  }
}

// ---------------------------------------------------------------------------
// Extension state
// ---------------------------------------------------------------------------

let diagnosticCollection: vscode.DiagnosticCollection;
let statusBarItem: vscode.StatusBarItem;
let codeLensProvider: ChakraCodeLensProvider;
let scanTimer: NodeJS.Timeout | undefined;

// ---------------------------------------------------------------------------
// Core scan logic
// ---------------------------------------------------------------------------

async function scanDocument(doc: vscode.TextDocument): Promise<void> {
  if (doc.languageId !== 'python') {
    return;
  }

  applyStatusState(statusBarItem, 'scanning');

  const filepath = buildFilepath(doc.uri);
  const source = doc.getText();

  const body = {
    filepath,
    source,
    org_id: getOrgId(),
    dev_id: getDevId(),
  };

  let response: ScanResponse;
  try {
    const rawBuf = await httpPost('/scan', body);
    response = JSON.parse(rawBuf.toString()) as ScanResponse;
  } catch (err) {
    applyStatusState(statusBarItem, 'error');
    vscode.window.showErrorMessage(
      `CHAKRA: Failed to reach server at ${getServerUrl()}. ${(err as Error).message}`,
    );
    return;
  }

  const findings = response.findings ?? [];
  const diagnostics = findings.map((f) => buildDiagnostic(f, doc));

  diagnosticCollection.set(doc.uri, diagnostics);
  codeLensProvider.update(doc.uri, findings);

  if (findings.length === 0) {
    applyStatusState(statusBarItem, 'clean');
  } else {
    applyStatusState(statusBarItem, 'findings', findings.length);
  }

  const cacheNote = response.cache_hit ? ' (cached)' : '';
  const changedNote = response.changed_lines
    ? ` | lines ${response.changed_lines[0]}–${response.changed_lines[1]}`
    : '';
  statusBarItem.tooltip =
    `CHAKRA — ${findings.length} finding${findings.length === 1 ? '' : 's'}` +
    `${changedNote}${cacheNote} | ${response.scan_time_ms}ms`;
}

async function dismissFinding(uri: vscode.Uri, finding: Finding): Promise<void> {
  const body = {
    filepath: buildFilepath(uri),
    cwe: finding.cwe,
    original_line_content: finding.original_line_content,
    org_id: getOrgId(),
    dev_id: getDevId(),
  };

  try {
    await httpPost('/dismiss', body);
  } catch (err) {
    vscode.window.showErrorMessage(`CHAKRA: Could not dismiss finding. ${(err as Error).message}`);
    return;
  }

  // Refresh diagnostics & codelens by removing dismissed finding
  const existing = diagnosticCollection.get(uri);
  if (existing) {
    const updated = Array.from(existing).filter(
      (d) =>
        (d as unknown as { chakraFinding?: Finding }).chakraFinding?.dismissal_fingerprint !==
        finding.dismissal_fingerprint,
    );
    diagnosticCollection.set(uri, updated);
  }

  const doc = vscode.workspace.textDocuments.find((d) => d.uri.toString() === uri.toString());
  if (doc) {
    await scanDocument(doc);
  }
}

// ---------------------------------------------------------------------------
// Activation
// ---------------------------------------------------------------------------

export function activate(context: vscode.ExtensionContext): void {
  // Diagnostic collection
  diagnosticCollection = vscode.languages.createDiagnosticCollection('chakra');
  context.subscriptions.push(diagnosticCollection);

  // CodeLens
  codeLensProvider = new ChakraCodeLensProvider();
  context.subscriptions.push(
    vscode.languages.registerCodeLensProvider({ language: 'python' }, codeLensProvider),
  );

  // Status bar
  statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  statusBarItem.command = 'chakra.openDashboard';
  applyStatusState(statusBarItem, 'idle');
  statusBarItem.show();
  context.subscriptions.push(statusBarItem);

  // Commands
  context.subscriptions.push(
    vscode.commands.registerCommand('chakra.scanFile', async () => {
      const editor = vscode.window.activeTextEditor;
      if (editor) {
        await scanDocument(editor.document);
      }
    }),
  );

  context.subscriptions.push(
    vscode.commands.registerCommand(
      'chakra.dismissFinding',
      async (uri: vscode.Uri, finding: Finding) => {
        await dismissFinding(uri, finding);
      },
    ),
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('chakra.openDashboard', () => {
      const serverUrl = getServerUrl();
      const dashUrl = `${serverUrl}/dashboard`;
      vscode.env.openExternal(vscode.Uri.parse(dashUrl));
    }),
  );

  // Auto-scan on save
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument((doc) => {
      if (!cfg().get<boolean>('autoScanOnSave', true)) {
        return;
      }
      if (doc.languageId !== 'python') {
        return;
      }
      const delay = cfg().get<number>('autoScanDelay', 1500);
      if (scanTimer) {
        clearTimeout(scanTimer);
      }
      scanTimer = setTimeout(() => {
        scanDocument(doc).catch(() => {/* already handled */});
      }, delay);
    }),
  );

  // Auto-scan when switching to a Python file
  context.subscriptions.push(
    vscode.window.onDidChangeActiveTextEditor((editor) => {
      if (editor && editor.document.languageId === 'python') {
        scanDocument(editor.document).catch(() => {/* already handled */});
      } else if (!editor) {
        applyStatusState(statusBarItem, 'idle');
      }
    }),
  );

  // Clear diagnostics when a file is closed
  context.subscriptions.push(
    vscode.workspace.onDidCloseTextDocument((doc) => {
      diagnosticCollection.delete(doc.uri);
      codeLensProvider.clear(doc.uri);
    }),
  );

  // Scan the active document on startup if it's Python
  const active = vscode.window.activeTextEditor;
  if (active && active.document.languageId === 'python') {
    scanDocument(active.document).catch(() => {/* already handled */});
  }
}

export function deactivate(): void {
  if (scanTimer) {
    clearTimeout(scanTimer);
  }
}

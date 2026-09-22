import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { randomBytes } from "node:crypto";

export interface DashboardServerOptions {
  readonly port?: number;
  readonly host?: string;
}

export interface DashboardHandle {
  readonly server: Server;
  readonly token: string;
  readonly url: string;
  close(): Promise<void>;
}

const MAX_BODY_BYTES = 32_768;

function writeJson(response: ServerResponse, status: number, body: unknown): void {
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
  });
  response.end(JSON.stringify(body));
}

function writeHtml(response: ServerResponse, html: string): void {
  response.writeHead(200, {
    "content-type": "text/html; charset=utf-8",
    "cache-control": "no-store",
    "content-security-policy": "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'",
    "x-content-type-options": "nosniff",
  });
  response.end(html);
}

async function readJson(request: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  let bytes = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    bytes += buffer.byteLength;
    if (bytes > MAX_BODY_BYTES) {
      throw new Error("Request body exceeds the dashboard limit.");
    }
    chunks.push(buffer);
  }
  const text = Buffer.concat(chunks).toString("utf8");
  const parsed: unknown = JSON.parse(text);
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("A JSON object is required.");
  }
  return parsed as Record<string, unknown>;
}

function isLoopbackHost(host: string): boolean {
  return host === "127.0.0.1" || host === "localhost" || host === "::1";
}

export function dashboardHtml(): string {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AegisOS Enforced Console</title>
<style>
  :root{color-scheme:dark;font-family:ui-sans-serif,system-ui;background:#071016;color:#e7f1f4}
  body{max-width:980px;margin:0 auto;padding:2rem}h1{margin-bottom:.25rem}.muted{color:#9eb2ba}
  .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:1rem;margin:1.4rem 0}
  .card{background:#0e1c24;border:1px solid #23414d;border-radius:12px;padding:1rem}.ok{color:#75dfa6}.warn{color:#f5c56c}
  button{background:#157a6e;border:0;border-radius:6px;color:white;padding:.65rem .85rem;cursor:pointer;margin:.2rem 0}
  pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#041016;padding:1rem;border-radius:8px;border:1px solid #23414d}
</style></head><body>
<h1>AegisOS <span class="ok">ENFORCED</span></h1>
<p class="muted">Local, testnet-only review console. This UI cannot send a raw transaction or expose a signing key.</p>
<div class="grid"><section class="card"><h2>Stellar</h2><p>Testnet · Wallets Kit boundary</p><p class="warn">Owner signature required</p><button id="stellar">Connect Stellar wallet</button></section>
<section class="card"><h2>Ethereum</h2><p>Sepolia · Safe 2-of-2 boundary</p><p class="warn">Owner signature required</p><button id="metamask">Connect MetaMask</button></section>
<section class="card"><h2>Memory</h2><p>External content is untrusted by default.</p><p class="ok">No text can authorize funds.</p></section></div>
<h2>Runtime status</h2><pre id="status">Loading…</pre>
<script>
const out=document.getElementById('status');
fetch('/api/health').then(r=>r.json()).then(x=>out.textContent=JSON.stringify(x,null,2)).catch(e=>out.textContent=String(e));
document.getElementById('metamask').onclick=async()=>{try{if(!window.ethereum)throw new Error('MetaMask was not detected.');const a=await window.ethereum.request({method:'eth_requestAccounts'});out.textContent='Connected MetaMask account: '+a[0]+'\\nNo signing request was made.'}catch(e){out.textContent=String(e)}};
document.getElementById('stellar').onclick=()=>{out.textContent='Connect Stellar Wallets Kit in the host app, then pass only a reviewed XDR to the owner-signature boundary. Aegis never receives a wallet secret.'};
</script></body></html>`;
}

export async function startDashboard(options: DashboardServerOptions = {}): Promise<DashboardHandle> {
  const host = options.host ?? "127.0.0.1";
  if (!isLoopbackHost(host)) {
    throw new Error("Dashboard must bind to a loopback interface.");
  }
  const token = randomBytes(32).toString("hex");
  const server = createServer(async (request, response) => {
    const url = new URL(request.url ?? "/", `http://${host}`);
    if (request.method === "GET" && url.pathname === "/") {
      writeHtml(response, dashboardHtml());
      return;
    }
    if (request.method === "GET" && url.pathname === "/api/health") {
      writeJson(response, 200, {
        mode: "enforced",
        testnetOnly: true,
        signing: "external-owner-boundary-only",
        acceptedPayloads: ["typed intent drafts", "read-only status"],
        forbiddenPayloads: ["private keys", "raw XDR", "calldata", "RPC URLs"],
      });
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/drafts") {
      try {
        const draft = await readJson(request);
        writeJson(response, 202, {
          status: "DRAFT_ONLY",
          message: "The dashboard accepted a review draft; it did not sign or broadcast anything.",
          fields: Object.keys(draft).sort(),
        });
      } catch (error) {
        writeJson(response, 400, { error: error instanceof Error ? error.message : "Invalid input." });
      }
      return;
    }
    writeJson(response, 404, { error: "Not found." });
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(options.port ?? 0, host, () => {
      server.off("error", reject);
      resolve();
    });
  });
  const address = server.address();
  if (address === null || typeof address === "string") {
    throw new Error("Dashboard did not expose a TCP address.");
  }
  return {
    server,
    token,
    url: `http://${host}:${address.port}`,
    close: () => new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve())),
  };
}

if (process.argv[1] !== undefined && import.meta.url === new URL(`file://${process.argv[1].replaceAll("\\", "/")}`).href) {
  void startDashboard({ port: Number(process.env.AEGIS_DASHBOARD_PORT ?? "4173") }).then((dashboard) => {
    process.stdout.write(`AegisOS dashboard listening at ${dashboard.url}\n`);
  });
}

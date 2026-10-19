import { request as httpsRequest, Agent } from 'node:https';
import { connect, rootCertificates } from 'node:tls';
import type { ConnectionOptions } from 'node:tls';
import { lookup } from 'node:dns';
import { BlockList, isIP } from 'node:net';

export interface HttpTransport { fetch(request: Request, options?: { mode?: 'endpoint' | 'discovery' }): Promise<Response> }
export interface NetworkOptions { timeoutMs?: number; maxResponseBytes?: number; maxRequestBytes?: number; maxRedirects?: number; localExceptions?: readonly { hostname: string; addresses: readonly string[] }[]; ca?: string }
export class TransportError extends Error {
  constructor(readonly code: 'invalid_url' | 'blocked_address' | 'redirect_limit' | 'timeout' | 'body_limit' | 'network_error') { super(`Transport ${code}`); this.name = 'TransportError'; }
}
export function secureUrl(value: string): URL {
  let url: URL;
  try { url = new URL(value); } catch { throw new TransportError('invalid_url'); }
  if (url.protocol !== 'https:' || url.username || url.password || url.hash) throw new TransportError('invalid_url');
  return url;
}
function normalizedAddress(value: string): string { return value.replace(/^\[|\]$/g, '').toLowerCase(); }
const blockedV4 = new BlockList();
for (const [network, prefix] of [
  ['0.0.0.0', 8], // "this" network
  ['10.0.0.0', 8], // private
  ['100.64.0.0', 10], // carrier-grade NAT
  ['127.0.0.0', 8], // loopback
  ['169.254.0.0', 16], // link-local
  ['172.16.0.0', 12], // private
  ['192.0.0.0', 24], // IETF protocol assignments
  ['192.0.2.0', 24], // documentation
  ['192.88.99.0', 24], // 6to4 relay anycast
  ['192.168.0.0', 16], // private
  ['198.18.0.0', 15], // benchmarking
  ['198.51.100.0', 24], // documentation
  ['203.0.113.0', 24], // documentation
  ['224.0.0.0', 3], // multicast and reserved (224.0.0.0 to 255.255.255.255)
] as const) blockedV4.addSubnet(network, prefix, 'ipv4');
// IPv6 is allow-listed: only global unicast 2000::/3 minus special-purpose ranges.
const blockedV6 = new BlockList();
for (const [network, prefix] of [
  ['2001::', 23], // IETF protocol assignments (Teredo etc.)
  ['2001:db8::', 32], // documentation
  ['2002::', 16], // 6to4
  ['3fff::', 20], // documentation
] as const) blockedV6.addSubnet(network, prefix, 'ipv6');
const globalV6 = new BlockList();
globalV6.addSubnet('2000::', 3, 'ipv6');
export function isPublicAddress(value: string): boolean {
  const address = normalizedAddress(value);
  if (isIP(address) === 4) return !blockedV4.check(address, 'ipv4');
  // Zoned addresses (fe80::1%eth0) fail closed.
  if (isIP(address) !== 6 || address.includes('%')) return false;
  return globalV6.check(address, 'ipv6') && !blockedV6.check(address, 'ipv6');
}
export function createNodeTransport(options: NetworkOptions = {}): HttpTransport {
  const limits = { timeoutMs: options.timeoutMs ?? 15000, maxResponseBytes: options.maxResponseBytes ?? 1048576, maxRequestBytes: options.maxRequestBytes ?? 1048576, maxRedirects: options.maxRedirects ?? 5 };
  for (const [name, value] of Object.entries(limits)) if (!Number.isSafeInteger(value) || value < (name === 'maxRedirects' ? 0 : 1)) throw new TypeError('Invalid transport limit');
  function allowed(hostname: string, address: string): boolean {
    return isPublicAddress(address) || !!options.localExceptions?.some(entry => entry.hostname.toLowerCase() === hostname.toLowerCase() && entry.addresses.some(ip => normalizedAddress(ip) === normalizedAddress(address)));
  }
  return { async fetch(request, settings = {}) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(new TransportError('timeout')), limits.timeoutMs);
    const signal = AbortSignal.any([request.signal, controller.signal]);
    let body: Buffer | undefined;
    try {
      if (request.body) {
        const reader = request.body.getReader(); const chunks: Uint8Array[] = []; let length = 0;
        const abort = () => { void reader.cancel(signal.reason); };
        signal.addEventListener('abort', abort, { once: true });
        try { while (true) { signal.throwIfAborted(); const item = await reader.read(); if (item.done) break; length += item.value.length; if (length > limits.maxRequestBytes) throw new TransportError('body_limit'); chunks.push(item.value); } }
        finally { signal.removeEventListener('abort', abort); await reader.cancel().catch(() => {}); }
        body = Buffer.concat(chunks);
      }
      let url = secureUrl(request.url);
      if (request.headers.has('host') && request.headers.get('host') !== url.host) throw new TransportError('invalid_url');
      if (settings.mode === 'discovery' && (request.method !== 'GET' || body || ['authorization', 'dpop', 'cookie', 'proxy-authorization', 'host'].some(key => request.headers.has(key)))) throw new TransportError('invalid_url');
      for (let redirects = 0; ; redirects++) {
        signal.throwIfAborted();
        const hostname = normalizedAddress(url.hostname);
        const agent = new Agent({ keepAlive: false });
        // Return no socket until TLS and actual peer-address verification finish: HTTP cannot write early.
        agent.createConnection = ((connectionOptions: ConnectionOptions, callback: (error: Error | null, socket?: ReturnType<typeof connect>) => void) => {
          const socket = connect({ ...connectionOptions, host: hostname, servername: isIP(hostname) ? undefined : hostname, rejectUnauthorized: true, ca: options.ca ? [...rootCertificates, options.ca] : undefined,
            lookup: ((host: string, opts: { all?: boolean }, done: (error: Error | null, address?: string | { address: string; family: number }[], family?: number) => void) => {
              lookup(host, { all: true, verbatim: true }, (error, addresses) => {
                if (error) return done(new TransportError('network_error'));
                const selected = addresses.find(item => allowed(hostname, item.address));
                if (!selected) return done(new TransportError('blocked_address'));
                if (opts.all) done(null, [selected]); else done(null, selected.address, selected.family);
              });
            }) as typeof lookup });
          let settled = false;
          const finish = (error: Error | null) => { if (settled) return; settled = true; signal.removeEventListener('abort', abort); if (error) { socket.destroy(); callback(error); } else callback(null, socket); };
          const abort = () => finish(new TransportError(controller.signal.aborted ? 'timeout' : 'network_error'));
          signal.addEventListener('abort', abort, { once: true });
          socket.once('error', error => finish(error instanceof TransportError ? error : new TransportError('network_error')));
          socket.once('secureConnect', () => finish(socket.remoteAddress && allowed(hostname, socket.remoteAddress) ? null : new TransportError('blocked_address')));
          return undefined;
        }) as typeof agent.createConnection;
        if (isIP(hostname) && !allowed(hostname, hostname)) { agent.destroy(); throw new TransportError('blocked_address'); }
        const response = await new Promise<Response>((resolve, reject) => {
          const outgoing = httpsRequest(url, { method: request.method, headers: Object.fromEntries(request.headers), agent, signal }, incoming => {
            const chunks: Buffer[] = []; let size = 0;
            incoming.on('data', (chunk: Buffer) => { size += chunk.length; if (size > limits.maxResponseBytes) incoming.destroy(new TransportError('body_limit')); else chunks.push(chunk); });
            incoming.on('error', reject);
            incoming.on('end', () => {
              const headers = new Headers(); for (let i = 0; i < incoming.rawHeaders.length; i += 2) headers.append(incoming.rawHeaders[i], incoming.rawHeaders[i + 1]);
              const status = incoming.statusCode ?? 502;
              if (status < 200 || status > 599) { reject(new TransportError('network_error')); return; }
              const result = new Response([204, 205, 304].includes(status) || request.method === 'HEAD' ? null : Buffer.concat(chunks), { status, statusText: incoming.statusMessage, headers });
              Object.defineProperty(result, 'url', { value: url.href }); resolve(result);
            });
          });
          outgoing.on('error', reject); outgoing.end(body);
        }).finally(() => agent.destroy());
        if (settings.mode !== 'discovery' || ![301, 302, 303, 307, 308].includes(response.status)) return response;
        if (redirects >= limits.maxRedirects) throw new TransportError('redirect_limit');
        const location = response.headers.get('location'); if (!location) return response;
        url = secureUrl(new URL(location, url).href);
      }
    } catch (error) { if (error instanceof TransportError) throw error; throw new TransportError(controller.signal.aborted ? 'timeout' : 'network_error'); }
    finally { clearTimeout(timer); }
  } };
}

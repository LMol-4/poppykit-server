import { request as httpsRequest, Agent } from 'node:https';
import { connect, rootCertificates } from 'node:tls';
import type { ConnectionOptions, TLSSocket } from 'node:tls';
import { lookup } from 'node:dns';
import { BlockList, isIP } from 'node:net';

// waitMs: how long the peer may legitimately hold this request (a long poll); it is added to the timeout.
export interface HttpTransport { fetch(request: Request, options?: { mode?: 'endpoint' | 'discovery'; waitMs?: number }): Promise<Response>; stream?(request: Request): Promise<Response>; close?(): void }
export interface NetworkOptions { timeoutMs?: number; maxResponseBytes?: number; maxRequestBytes?: number; maxRedirects?: number; maxPools?: number; maxSockets?: number; maxRequests?: number; maxStreamBytes?: number; maxStreamMs?: number; localExceptions?: readonly { hostname: string; addresses: readonly string[] }[]; ca?: string }
export class TransportError extends Error {
  constructor(readonly code: 'invalid_url' | 'blocked_address' | 'redirect_limit' | 'timeout' | 'body_limit' | 'network_error' | 'overloaded' | 'closed') { super(`Transport ${code}`); this.name = 'TransportError'; }
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
  const limits = { timeoutMs: options.timeoutMs ?? 15000, maxResponseBytes: options.maxResponseBytes ?? 1048576, maxRequestBytes: options.maxRequestBytes ?? 1048576, maxRedirects: options.maxRedirects ?? 5, maxPools: options.maxPools ?? 8, maxSockets: options.maxSockets ?? 2, maxRequests: options.maxRequests ?? 32, maxStreamBytes: options.maxStreamBytes ?? 16777216, maxStreamMs: options.maxStreamMs ?? 300000 };
  for (const [name, value] of Object.entries(limits)) if (!Number.isSafeInteger(value) || value < (name === 'maxRedirects' ? 0 : 1) || (name.endsWith('Ms') && value > 2147483647)) throw new TypeError('Invalid transport limit');
  const pools = new Map<string, { agent: Agent; active: number; origin: string; mode: string }>();
  let active = 0, closed = false;
  const connecting = new Set<TLSSocket>();
  const shutdown = new AbortController();
  const allowed = (hostname: string, address: string) => isPublicAddress(address) || !!options.localExceptions?.some(entry => entry.hostname.toLowerCase() === hostname.toLowerCase() && entry.addresses.some(ip => normalizedAddress(ip) === normalizedAddress(address)));
  async function execute(request: Request, settings: { mode?: 'endpoint' | 'discovery'; waitMs?: number } = {}, streaming = false): Promise<Response> {
    if (closed) throw new TransportError('closed');
    if (active >= limits.maxRequests) throw new TransportError('overloaded');
    const discovery = settings.mode === 'discovery';
    const timeoutMs = streaming ? limits.maxStreamMs : (discovery ? Math.min(limits.timeoutMs, 5000) : limits.timeoutMs) + (settings.waitMs ?? 0);
    if (!Number.isSafeInteger(settings.waitMs ?? 0) || (settings.waitMs ?? 0) < 0 || timeoutMs > 2147483647) throw new TypeError('Invalid transport wait');
    active++;
    const controller = new AbortController(), signal = AbortSignal.any([request.signal, controller.signal, shutdown.signal]);
    const timer = setTimeout(() => controller.abort(new TransportError('timeout')), timeoutMs);
    let transferred = false, finished = false;
    const finish = () => { if (!finished) { finished = true; active--; clearTimeout(timer); } };
    try {
      signal.throwIfAborted();
      let body: Buffer | undefined;
      if (request.body) {
        const reader = request.body.getReader(), chunks: Uint8Array[] = []; let length = 0;
        const abort = () => { void reader.cancel(signal.reason); }; signal.addEventListener('abort', abort, { once: true });
        try { for (;;) { signal.throwIfAborted(); const item = await reader.read(); if (item.done) break; length += item.value.length; if (length > limits.maxRequestBytes) throw new TransportError('body_limit'); chunks.push(item.value); } }
        finally { signal.removeEventListener('abort', abort); await reader.cancel().catch(() => {}); reader.releaseLock(); }
        body = Buffer.concat(chunks);
      }
      let url = secureUrl(request.url);
      if (request.headers.has('host') && request.headers.get('host') !== url.host) throw new TransportError('invalid_url');
      if (discovery && (request.method !== 'GET' || body || ['authorization', 'dpop', 'cookie', 'proxy-authorization', 'host'].some(key => request.headers.has(key)))) throw new TransportError('invalid_url');
      for (let redirects = 0; ; redirects++) {
        signal.throwIfAborted();
        const hostname = normalizedAddress(url.hostname);
        const addresses = await new Promise<{ address: string; family: number }[]>((resolve, reject) => {
          const abort = () => reject(signal.reason); signal.addEventListener('abort', abort, { once: true });
          const done = (error: Error | null, found: { address: string; family: number }[]) => { signal.removeEventListener('abort', abort); error ? reject(new TransportError('network_error')) : resolve(found); };
          if (isIP(hostname)) done(null, [{ address: hostname, family: isIP(hostname) }]); else lookup(hostname, { all: true, verbatim: true }, done);
        });
        signal.throwIfAborted();
        const approved = addresses.filter(item => allowed(hostname, item.address)).sort((a, b) => a.address.localeCompare(b.address));
        if (!approved.length) throw new TransportError('blocked_address');
        const mode = discovery ? 'discovery' : streaming ? 'stream' : 'endpoint';
        const poolKey = JSON.stringify([url.origin, mode, approved, options.ca]);
        // Recheck DNS/policy before every assignment, including free sockets. Retire incompatible pools.
        for (const [key, pool] of pools) if (pool.origin === url.origin && pool.mode === mode && key !== poolKey) { pool.agent.destroy(); pools.delete(key); }
        let pool = pools.get(poolKey);
        if (!pool) {
          if (pools.size >= limits.maxPools) { const idle = [...pools].find(([, value]) => value.active === 0); if (!idle) throw new TransportError('overloaded'); idle[1].agent.destroy(); pools.delete(idle[0]); }
          const agent = new Agent({ keepAlive: true, maxSockets: limits.maxSockets, maxTotalSockets: limits.maxSockets, maxFreeSockets: 1, timeout: limits.timeoutMs });
          agent.createConnection = ((connectionOptions: ConnectionOptions, callback: (error: Error | null, socket?: ReturnType<typeof connect>) => void) => {
            const selected = approved[0];
            const socket = connect({ ...connectionOptions, host: selected.address, servername: isIP(hostname) ? undefined : hostname, rejectUnauthorized: true, minVersion: 'TLSv1.2', ca: options.ca ? [...rootCertificates, options.ca] : undefined });
            const connectSignal = (connectionOptions as ConnectionOptions & { transportSignal?: AbortSignal }).transportSignal;
            const abortConnect = () => settle(new TransportError('network_error'));
            connecting.add(socket); socket.setTimeout?.(limits.timeoutMs, () => socket.destroy(new TransportError('timeout')));
            let settled = false;
            const settle = (error: Error | null) => { if (settled) return; settled = true; connectSignal?.removeEventListener('abort',abortConnect); connecting.delete(socket); socket.setTimeout?.(0); if (error) { socket.destroy(); callback(error); } else callback(null, socket); };
            connectSignal?.addEventListener('abort',abortConnect,{once:true}); if(connectSignal?.aborted)queueMicrotask(abortConnect);
            socket.once('error', error => settle(error instanceof TransportError ? error : new TransportError('network_error')));
            socket.once('secureConnect', () => settle(socket.remoteAddress && approved.some(item => normalizedAddress(item.address) === normalizedAddress(socket.remoteAddress!)) && allowed(hostname, socket.remoteAddress) ? null : new TransportError('blocked_address')));
            return undefined;
          }) as typeof agent.createConnection;
          agent.reuseSocket = (duplex, outgoing) => {
            const socket = duplex as TLSSocket;
            if (!socket.remoteAddress || !approved.some(item => normalizedAddress(item.address) === normalizedAddress(socket.remoteAddress!)) || !allowed(hostname,socket.remoteAddress)) {
              const error = new TransportError('blocked_address'); socket.destroy(error); outgoing.destroy(error); return;
            }
            Agent.prototype.reuseSocket.call(agent,socket,outgoing);
          };
          pool = { agent, active: 0, origin: url.origin, mode }; pools.set(poolKey, pool);
        }
        const selectedPool = pool;
        // No hidden Agent queue: callers retry overload, after fresh DNS and policy validation.
        if (selectedPool.active >= limits.maxSockets) throw new TransportError('overloaded');
        selectedPool.active++;
        let releaseCalled = false;
        const release = () => { if (!releaseCalled) { releaseCalled = true; selectedPool.active--; } };
        const response = await new Promise<Response>((resolve, reject) => {
          const outgoing = httpsRequest(url, { method: request.method, headers: Object.fromEntries(request.headers), agent: selectedPool.agent, signal, ...{ transportSignal: signal } }, incoming => {
            const headers = new Headers(); for (let i = 0; i < incoming.rawHeaders.length; i += 2) headers.append(incoming.rawHeaders[i], incoming.rawHeaders[i + 1]);
            const status = incoming.statusCode ?? 502;
            if (status < 200 || status > 599) { incoming.destroy(); reject(new TransportError('network_error')); return; }
            const noBody = [204, 205, 304].includes(status) || request.method === 'HEAD';
            if (streaming && !noBody) {
              incoming.pause(); let bytes = 0;
              const iterator = incoming[Symbol.asyncIterator]();
              const stream = new ReadableStream<Uint8Array>({
                async pull(target) { try { const item = await iterator.next(); if (item.done) { target.close(); release(); finish(); } else { bytes += item.value.length; if (bytes > limits.maxStreamBytes) throw new TransportError('body_limit'); target.enqueue(item.value); } } catch (error) { target.error(error); incoming.destroy(); release(); finish(); } },
                async cancel() { incoming.destroy(); await iterator.return?.(); release(); finish(); },
              }, { highWaterMark: 0 });
              incoming.once('close', () => { release(); finish(); });
              transferred = true;
              const result = new Response(stream, { status, headers }); Object.defineProperty(result, 'url', { value: url.href }); resolve(result);
            } else {
              const chunks: Buffer[] = []; let size = 0;
              incoming.on('data', (chunk: Buffer) => { size += chunk.length; if (size > (discovery ? Math.min(limits.maxResponseBytes, 102400) : limits.maxResponseBytes)) incoming.destroy(new TransportError('body_limit')); else chunks.push(chunk); });
              incoming.on('error', reject);
              incoming.on('end', () => { const result = new Response(noBody ? null : Buffer.concat(chunks), { status, headers }); Object.defineProperty(result, 'url', { value: url.href }); release(); resolve(result); });
            }
          });
          outgoing.on('error', error => { release(); reject(error); }); outgoing.end(body);
        }).catch(error => { release(); throw error; });
        if (!discovery || ![301, 302, 303, 307, 308].includes(response.status)) return response;
        if (redirects >= limits.maxRedirects) throw new TransportError('redirect_limit');
        const location = response.headers.get('location'); if (!location) return response;
        url = secureUrl(new URL(location, url).href);
      }
    } catch (error) { if (closed) throw new TransportError('closed'); if (error instanceof TransportError) throw error; throw new TransportError(controller.signal.aborted ? 'timeout' : 'network_error'); }
    finally { if (!transferred) finish(); }
  }
  return { fetch: (request, settings) => execute(request, settings), stream: request => execute(request, {}, true), close() { closed = true; shutdown.abort(new TransportError('closed')); for (const socket of connecting) socket.destroy(); connecting.clear(); for (const pool of pools.values()) pool.agent.destroy(); pools.clear(); } };
}

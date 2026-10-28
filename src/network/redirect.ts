import { secureUrl } from './transport.js';

// RFC 8252 loopback callbacks are a return address, never a metadata/fetch exception.
export function loopbackRedirect(value: string): boolean {
  if (!/^http:\/\/(127\.0\.0\.1|\[::1\])(?::[0-9]+)?\//.test(value) || /[\\\s\x00-\x1f]/.test(value)) return false;
  try { const url = new URL(value); return !url.username && !url.password && !url.hash; } catch { return false; }
}

export function validRedirect(value: string, clientId: string): boolean {
  if (/[\\\s\x00-\x1f]/.test(value)) return false;
  if (loopbackRedirect(value)) return true;
  try { return secureUrl(value).hostname === secureUrl(clientId).hostname; } catch { return false; }
}

export function registeredRedirect(value: string, registered: readonly string[], clientId: string): boolean {
  if (!validRedirect(value, clientId)) return false;
  return registered.some(entry => {
    if (entry === value) return true;
    if (!loopbackRedirect(entry) || !loopbackRedirect(value)) return false;
    // Compare the original URI strings: only the literal port may differ.
    const withoutPort = (uri: string) => uri.replace(/^(http:\/\/(?:127\.0\.0\.1|\[::1\]))(?::[0-9]+)?(?=\/)/, '$1');
    return withoutPort(entry) === withoutPort(value);
  });
}

/**
 * Trust-boundary validation for storage node addresses.
 *
 * `ip` and `port` on a Snode come from a seed node's `get_n_master_nodes` reply
 * or another storage node's `get_mnodes_for_pubkey` reply. Both are untrusted:
 * a hostile node can return anything it likes. Before these values are used to
 * build a request URL they must be proven to be literal, publicly routable IP
 * addresses -- otherwise a value like "attacker.tld/collect?x=" rewrites the
 * host, path and query of the next request (SSRF / request redirection).
 */
import net from 'net';
import type { Snode } from '../types.js';

/** RFC1918 + loopback + link-local + CGNAT + multicast/reserved. */
function isPrivateV4(ip: string): boolean {
  const parts = ip.split('.').map(Number);
  const [a, b] = parts as [number, number];
  if (a === 0 || a === 10 || a === 127) return true;
  if (a === 169 && b === 254) return true; // link-local
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
  if (a >= 224) return true; // multicast + reserved
  return false;
}

function isPrivateV6(ip: string): boolean {
  const s = ip.toLowerCase();
  if (s === '::' || s === '::1') return true;
  if (/^fe[89ab]/.test(s)) return true; // fe80::/10 link-local
  if (/^f[cd]/.test(s)) return true; // fc00::/7 unique-local
  if (s.startsWith('::ffff:')) return true; // IPv4-mapped; reject rather than re-parse
  return false;
}

export type AddressPolicy = {
  /**
   * Permit loopback/RFC1918 targets. Off by default; only for pointing the SDK
   * at a storage node on your own machine during development.
   */
  allowPrivateNodes?: boolean;
};

/**
 * Throws unless `ip` is a literal IP address and `port` a valid TCP port.
 * Returns the normalised port.
 */
export function assertSnodeAddress(
  ip: unknown,
  port: unknown,
  policy: AddressPolicy = {}
): number {
  if (typeof ip !== 'string' || ip.length === 0) {
    throw new Error(`snode ip is missing or not a string: ${JSON.stringify(ip)}`);
  }

  const family = net.isIP(ip);
  if (family === 0) {
    // Catches "evil.tld", "1.2.3.4/x?", "user:pass@host", and every other
    // attempt to smuggle URL syntax through this field.
    throw new Error(`snode ip is not a literal IP address: ${JSON.stringify(ip)}`);
  }

  if (!policy.allowPrivateNodes) {
    if (family === 4 && isPrivateV4(ip)) {
      throw new Error(`snode ip is not publicly routable: ${ip}`);
    }
    if (family === 6 && isPrivateV6(ip)) {
      throw new Error(`snode ip is not publicly routable: ${ip}`);
    }
  }

  const p = Number(port);
  if (!Number.isInteger(p) || p < 1 || p > 65535) {
    throw new Error(`snode port is invalid: ${String(port)}`);
  }
  return p;
}

/** True when the address passes `assertSnodeAddress`. Use to filter node lists. */
export function isUsableSnode(node: Partial<Snode>, policy: AddressPolicy = {}): boolean {
  try {
    assertSnodeAddress(node?.ip, node?.port, policy);
    return true;
  } catch {
    return false;
  }
}

/**
 * Build a storage-node RPC URL without string interpolation, so nothing in the
 * host field can escape into the path or query.
 */
export function buildSnodeUrl(ip: string, port: number, path: string): string {
  const url = new URL('https://placeholder');
  url.hostname = net.isIP(ip) === 6 ? `[${ip}]` : ip;
  url.port = String(port);
  url.pathname = path;

  // Defence in depth: if anything above moved the host, port or path, refuse.
  // Note `url.port` is '' when it matches the protocol default (443 for https),
  // and `url.host` elides it too — so compare the parts, not the combination.
  const expectedHostname = net.isIP(ip) === 6 ? `[${ip}]` : ip;
  const effectivePort = url.port === '' ? 443 : Number(url.port);
  if (url.hostname !== expectedHostname || effectivePort !== port || url.pathname !== path) {
    throw new Error(`refusing to build request URL for suspicious address ${ip}:${port}`);
  }
  return url.toString();
}

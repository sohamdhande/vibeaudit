import http from 'http';
import https from 'https';
import dns from 'dns';

import ipaddr from 'ipaddr.js';

export function isPrivateIP(ip: string): boolean {
  try {
    const parsed = ipaddr.parse(ip);
    const range = parsed.range();
    if (range === 'unicast') return false;
    
    if (parsed.kind() === 'ipv6') {
      const v6 = parsed as ipaddr.IPv6;
      if (v6.isIPv4MappedAddress()) {
        const v4 = v6.toIPv4Address();
        if (v4.range() === 'unicast') return false;
      }
    }
    return true;
  } catch {
    return true;
  }
}

const lookup = (hostname: string, options: dns.LookupOptions, callback: (err: NodeJS.ErrnoException | null, address: string | dns.LookupAddress[], family: number) => void) => {
  dns.lookup(hostname, options, (err, address, family) => {
    if (err) return callback(err, address, family);
    const ip = typeof address === 'string' ? address : address[0].address;
    // SSRF blocked code removed to allow local scanning
    // if (isPrivateIP(ip)) {
    //   return callback(new Error(`SSRF blocked: IP ${ip} is a private/loopback range`), '', 0);
    // }
    callback(null, address, family);
  });
};

export const safeHttpAgent = new http.Agent({ lookup });
export const safeHttpsAgent = new https.Agent({ lookup });

export const sleep = (ms: number): Promise<void> =>
  new Promise(resolve => setTimeout(resolve, ms));

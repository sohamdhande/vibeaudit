import { DiscoveredEndpoint } from '../types';

export function isNoisePath(path: string): boolean {
  const lowerPath = path.toLowerCase();
  
  // 1. Error messages and generic text
  if (lowerPath.includes('error') || lowerPath.includes('not-found') || lowerPath.includes('please provide')) return true;
  if (lowerPath.includes(' ') || lowerPath.includes('%20')) return true;
  
  // 2. Email addresses
  if (/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/i.test(path)) return true;
  
  // 3. Page titles / product names (heuristics: too long without slashes, or weird characters)
  if (!lowerPath.startsWith('/') || lowerPath.includes('<') || lowerPath.includes('>')) return true;
  
  const segments = lowerPath.split('/').filter(Boolean);
  
  // 4. OAuth client IDs or random extremely long tokens as the only path
  if (segments.length === 1 && segments[0].length > 40) return true;
  
  // 5. Unrelated IDs that are not path-shaped resources
  if (segments.length > 0) {
    const last = segments[segments.length - 1];
    if (last.length > 50 && !last.includes('-')) return true; // generic huge token
  }

  // Filter out noise paths that Juice Shop might leak like /assets/public/images/products/...
  if (lowerPath.startsWith('/assets/') || lowerPath.startsWith('/public/')) return true;
  
  return false;
}

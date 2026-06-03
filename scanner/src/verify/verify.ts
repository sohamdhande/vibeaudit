import axios from 'axios';
import { safeHttpAgent, safeHttpsAgent } from '../utils/agent';

export async function verifyPatch(
  targetUrl: string,
  endpoint: string,
  attackerToken: string,
  authType: 'cookie' | 'jwt' | 'unknown',
  emit: (msg: string) => void,
  signal?: AbortSignal
): Promise<boolean> {
  if (signal?.aborted) throw new Error('Scan aborted');
  emit('[VERIFY] Re-running exploit against patched route...');

  try {
    const headers = authType === 'jwt'
      ? { Authorization: `Bearer ${attackerToken}` }
      : { Cookie: attackerToken };

    const res = await axios.get(`${targetUrl}${endpoint}`, {
      headers,
      validateStatus: () => true,
      timeout: 10000,
      httpAgent: safeHttpAgent,
      httpsAgent: safeHttpsAgent,
    });

    if (res.status === 403) {
      emit('[VERIFY] Response: 403 Forbidden');
      emit('[SECURE] Exploit blocked. Patch confirmed effective.');
      return true;
    } else {
      emit(`[VERIFY] Response: ${res.status} — patch may not be applied yet`);
      return false;
    }
  } catch (err: unknown) {
    const errorMessage = err instanceof Error ? err.message : String(err);
    emit(`[VERIFY] Error during verification request: ${errorMessage}`);
    return false;
  }
}

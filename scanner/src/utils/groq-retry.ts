import Groq from 'groq-sdk';
import type { ChatCompletion } from 'groq-sdk/resources/chat/completions';

/**
 * Shared Groq client singleton.
 * Initialized lazily on first use from process.env.GROQ_API_KEY.
 */
let _groqClient: Groq | null = null;

export function getGroqClient(): Groq {
  if (!_groqClient) {
    const apiKey = process.env.GROQ_API_KEY;
    if (!apiKey || apiKey.length < 10) {
      throw new Error('GROQ_API_KEY is not set or too short');
    }
    _groqClient = new Groq({ apiKey });
  }
  return _groqClient;
}

/**
 * Type alias for the params accepted by groq.chat.completions.create().
 */
export type GroqChatParams = Parameters<Groq['chat']['completions']['create']>[0];

/**
 * Wraps a Groq chat completion call with exponential backoff retry on 429
 * rate-limit errors. All other errors are thrown immediately.
 *
 * Backoff schedule: 1s → 2s → 4s → 8s (doubling each retry).
 *
 * @param params  - The full chat completion params (model, messages, etc.)
 * @param maxRetries - Maximum number of retry attempts (default 4)
 * @returns The chat completion response
 */
export async function groqWithRetry(
  params: GroqChatParams,
  maxRetries: number = 4
): Promise<ChatCompletion> {
  const client = getGroqClient();
  let lastError: unknown;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return (await client.chat.completions.create(params)) as ChatCompletion;
    } catch (err: unknown) {
      lastError = err;

      // Detect rate-limit errors
      const isRateLimit =
        (typeof (err as any)?.status === 'number' && (err as any).status === 429) ||
        (err instanceof Error && /rate.?limit/i.test(err.message));

      if (!isRateLimit) {
        // Non-rate-limit error — fail fast
        throw err;
      }

      if (attempt < maxRetries) {
        const delayMs = Math.pow(2, attempt) * 1000; // 1s, 2s, 4s, 8s
        console.log(
          `[GROQ RETRY] Rate limited (attempt ${attempt + 1}/${maxRetries + 1}). ` +
          `Waiting ${delayMs / 1000}s before retry...`
        );
        await new Promise((resolve) => setTimeout(resolve, delayMs));
      }
    }
  }

  // All retries exhausted
  const errorMessage = lastError instanceof Error ? lastError.message : String(lastError);
  throw new Error(
    `Groq API rate limit: all ${maxRetries + 1} attempts exhausted. Last error: ${errorMessage}`
  );
}

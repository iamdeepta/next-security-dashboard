import * as http from 'node:http';
import * as https from 'node:https';

/**
 * A minimal GET client built on node:http / node:https.
 *
 * Why not global fetch? The host app may monkey-patch global fetch
 * (for example, a request-logging instrumentation.ts that wraps fetch and
 * rebuilds the Response). A patch that rebuilds the response without
 * copying its headers makes every "check the running app" request look
 * header-less, even though the server sends the headers. Talking to the
 * socket directly bypasses all such patches, so the checks below observe
 * exactly what the server sends — the same thing curl sees.
 *
 * Node runtime only. The scan route already requires Node (it shells out
 * to npm audit), so this adds no new runtime constraint.
 */

export interface DirectFetchResponse {
  status: number;
  ok: boolean;
  headers: Headers;
  url: string;
  text: () => Promise<string>;
  arrayBuffer: () => Promise<ArrayBuffer>;
}

export interface DirectFetchOptions {
  /** Request timeout in ms. Defaults to 10000. */
  timeoutMs?: number;
  /** Maximum redirects to follow. Defaults to 5. */
  maxRedirects?: number;
  /** Maximum response body to buffer, in bytes. Defaults to 5MB. */
  maxBodyBytes?: number;
}

const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_REDIRECTS = 5;
const DEFAULT_MAX_BODY_BYTES = 5 * 1024 * 1024;

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

function buildHeaders(raw: http.IncomingHttpHeaders): Headers {
  const headers = new Headers();
  for (const [name, value] of Object.entries(raw)) {
    if (value === undefined) continue;
    if (name.toLowerCase() === 'set-cookie' && Array.isArray(value)) {
      // Keep each cookie separate so getSetCookie() can split them back.
      for (const cookie of value) headers.append(name, cookie);
    } else {
      headers.append(name, Array.isArray(value) ? value.join(', ') : value);
    }
  }
  return headers;
}

function requestOnce(
  url: URL,
  timeoutMs: number,
  maxBodyBytes: number,
): Promise<{ status: number; headers: Headers; url: string; body: Buffer }> {
  return new Promise((resolve, reject) => {
    const lib = url.protocol === 'https:' ? https : http;
    const req = lib.request(
      url,
      {
        method: 'GET',
        headers: {
          accept: '*/*',
          'accept-encoding': 'identity',
          'user-agent': 'next-security-dashboard',
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        let total = 0;
        let failed = false;
        res.on('data', (chunk: Buffer) => {
          if (failed) return;
          total += chunk.length;
          if (total > maxBodyBytes) {
            failed = true;
            res.destroy();
            reject(new Error(`Response body exceeded ${maxBodyBytes} bytes`));
            return;
          }
          chunks.push(chunk);
        });
        res.on('end', () => {
          if (failed) return;
          resolve({
            status: res.statusCode ?? 0,
            headers: buildHeaders(res.headers),
            url: url.toString(),
            body: Buffer.concat(chunks),
          });
        });
        res.on('error', (err) => {
          if (failed) return;
          failed = true;
          reject(err);
        });
      },
    );
    req.setTimeout(timeoutMs, () => {
      req.destroy(new Error(`Request timed out after ${timeoutMs}ms`));
    });
    req.on('error', reject);
    req.end();
  });
}

export async function directFetch(
  rawUrl: string,
  options: DirectFetchOptions = {},
): Promise<DirectFetchResponse> {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxRedirects = options.maxRedirects ?? DEFAULT_MAX_REDIRECTS;
  const maxBodyBytes = options.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;

  let current = new URL(rawUrl);
  let redirectsLeft = maxRedirects;

  for (;;) {
    if (current.protocol !== 'http:' && current.protocol !== 'https:') {
      throw new Error(`Unsupported protocol: ${current.protocol}`);
    }
    const { status, headers, url, body } = await requestOnce(
      current,
      timeoutMs,
      maxBodyBytes,
    );
    const location = headers.get('location');
    if (REDIRECT_STATUSES.has(status) && location && redirectsLeft > 0) {
      redirectsLeft -= 1;
      current = new URL(location, current);
      continue;
    }
    const bodyCopy = () => Buffer.from(body);
    return {
      status,
      ok: status >= 200 && status < 300,
      headers,
      url,
      text: async () => bodyCopy().toString('utf8'),
      arrayBuffer: async () => {
        const copy = bodyCopy();
        return copy.buffer.slice(
          copy.byteOffset,
          copy.byteOffset + copy.byteLength,
        );
      },
    };
  }
}

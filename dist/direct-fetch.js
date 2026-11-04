import * as http from 'node:http';
import * as https from 'node:https';
const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_REDIRECTS = 5;
const DEFAULT_MAX_BODY_BYTES = 5 * 1024 * 1024;
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
function buildHeaders(raw) {
    const headers = new Headers();
    for (const [name, value] of Object.entries(raw)) {
        if (value === undefined)
            continue;
        if (name.toLowerCase() === 'set-cookie' && Array.isArray(value)) {
            // Keep each cookie separate so getSetCookie() can split them back.
            for (const cookie of value)
                headers.append(name, cookie);
        }
        else {
            headers.append(name, Array.isArray(value) ? value.join(', ') : value);
        }
    }
    return headers;
}
function requestOnce(url, timeoutMs, maxBodyBytes) {
    return new Promise((resolve, reject) => {
        const lib = url.protocol === 'https:' ? https : http;
        const req = lib.request(url, {
            method: 'GET',
            headers: {
                accept: '*/*',
                'accept-encoding': 'identity',
                'user-agent': 'next-security-dashboard',
            },
        }, (res) => {
            const chunks = [];
            let total = 0;
            let failed = false;
            res.on('data', (chunk) => {
                if (failed)
                    return;
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
                if (failed)
                    return;
                resolve({
                    status: res.statusCode ?? 0,
                    headers: buildHeaders(res.headers),
                    url: url.toString(),
                    body: Buffer.concat(chunks),
                });
            });
            res.on('error', (err) => {
                if (failed)
                    return;
                failed = true;
                reject(err);
            });
        });
        req.setTimeout(timeoutMs, () => {
            req.destroy(new Error(`Request timed out after ${timeoutMs}ms`));
        });
        req.on('error', reject);
        req.end();
    });
}
export async function directFetch(rawUrl, options = {}) {
    const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    const maxRedirects = options.maxRedirects ?? DEFAULT_MAX_REDIRECTS;
    const maxBodyBytes = options.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;
    let current = new URL(rawUrl);
    let redirectsLeft = maxRedirects;
    for (;;) {
        if (current.protocol !== 'http:' && current.protocol !== 'https:') {
            throw new Error(`Unsupported protocol: ${current.protocol}`);
        }
        const { status, headers, url, body } = await requestOnce(current, timeoutMs, maxBodyBytes);
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
                return copy.buffer.slice(copy.byteOffset, copy.byteOffset + copy.byteLength);
            },
        };
    }
}

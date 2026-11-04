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
export declare function directFetch(rawUrl: string, options?: DirectFetchOptions): Promise<DirectFetchResponse>;

import type { HeadersResult, HeaderStatus } from './types.js';
export declare function analyzeHeaders(headers: Headers, url: string, statusCode: number | null): HeadersResult;
/** Fetch the app's own origin and analyse the response headers. Uses a
 * direct node:http/https request (see direct-fetch.ts) instead of global
 * fetch, so a fetch monkey-patch in the host app cannot hide the headers
 * the server actually sends. */
export declare function fetchAndAnalyzeHeaders(origin: string): Promise<HeadersResult>;
export type { HeaderStatus };

import type { HeadersResult, HeaderStatus } from './types.js';
export declare function analyzeHeaders(headers: Headers, url: string, statusCode: number | null): HeadersResult;
/** Fetch the app's own origin and analyse the response headers. */
export declare function fetchAndAnalyzeHeaders(origin: string): Promise<HeadersResult>;
export type { HeaderStatus };

export interface Authority {
  readonly name: string;
  readonly certificates: Uint8Array[];
  readonly publicKey: Uint8Array;
  readonly ownerHash: string;
  readonly subjectKeyIdentifier: Uint8Array;
  verify(data: Uint8Array, signature: Uint8Array): boolean;
}
export interface LocalAuthority extends Authority { sign(data: Uint8Array): Promise<Uint8Array>; }
export type Trailers = HeadersInit | Promise<HeadersInit> | (() => HeadersInit | Promise<HeadersInit>);
export interface FetchOptions extends RequestInit {
  trailers?: Trailers;
  ownerHash?: string;
  /** Total exchange deadline, in milliseconds. */
  timeout?: number;
}
export interface DhttpResponse extends Response {
  readonly remoteAuthority: Authority | null;
  readonly rawHeaders: [string, string][];
  readonly trailers: Promise<Headers>;
  authority(): Authority | null;
  release(): Promise<void>;
}
export interface ServerRequest extends Request {
  readonly localAuthority: LocalAuthority;
  readonly remoteAuthority: Authority | null;
  readonly rawHeaders: [string, string][];
  readonly trailers: Promise<Headers>;
  authority(): Authority | null;
  release(): Promise<void>;
}
export interface ServerResponse extends Response { trailers?: Trailers; rawHeaders?: [string, string][]; }
export type Scope = 'loopback' | 'internal' | 'external';
export interface Listener { close(): Promise<void>; }
export class Endpoint {
  private constructor();
  readonly name: string | null;
  static load(name: string): Promise<Endpoint>;
  static loadFrom(path: string): Promise<Endpoint>;
  localAuthority(): Promise<LocalAuthority | null>;
  reload(): Promise<void>;
  fetch(input: RequestInfo | URL, options?: FetchOptions): Promise<DhttpResponse>;
  listen(scopes: Iterable<Scope>, handler: (request: ServerRequest) => ServerResponse | Promise<ServerResponse>): Promise<Listener>;
  close(): Promise<void>;
}
export const Anonymous: Pick<Endpoint, 'fetch' | 'close'>;
export function init(options?: {peers?: Record<string, string> | Map<string, string> | [string, string][]; rootCertificates?: Uint8Array}): Promise<void>;
export function addresses(): string[];
export class DhttpError extends Error { readonly code: string; readonly protocolCode?: number; }
export const Request: typeof globalThis.Request;
export const Response: typeof globalThis.Response;
export const Headers: typeof globalThis.Headers;
export const ReadableStream: typeof globalThis.ReadableStream;

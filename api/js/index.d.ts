export type DnsScheme = "mdns" | "http" | "h3" | "system";
export type FetchInput = string | URL | Request;
export type FetchHandler = (request: Request) => Response | Promise<Response>;
export type RawHandler = (
  request: import("@genmeta/dhttp/raw").UnresolvedRequest,
) => void | Promise<void>;

export interface EndpointOptions {
  identity?: Identity | null;
  dnsSchemes?: Iterable<DnsScheme>;
  bindPatterns?: Iterable<string>;
}

export interface LocalAuthority {
  name(): string;
  certChainDer(): Uint8Array[];
  publicKeyDer(): Uint8Array;
  sign(data: Uint8Array): Promise<Uint8Array>;
  verify(data: Uint8Array, signature: Uint8Array): Promise<boolean>;
}

export interface RemoteAuthority {
  name(): string;
  certChainDer(): Uint8Array[];
  publicKeyDer(): Uint8Array;
  verify(data: Uint8Array, signature: Uint8Array): Promise<boolean>;
}

export interface Service extends RawHandler {
  route(path: string, handler: FetchHandler | Service): Service;
  on(method: string, path: string, handler: FetchHandler | Service): Service;
  options(path: string, handler: FetchHandler | Service): Service;
  get(path: string, handler: FetchHandler | Service): Service;
  post(path: string, handler: FetchHandler | Service): Service;
  put(path: string, handler: FetchHandler | Service): Service;
  delete(path: string, handler: FetchHandler | Service): Service;
  head(path: string, handler: FetchHandler | Service): Service;
  trace(path: string, handler: FetchHandler | Service): Service;
  connect(path: string, handler: FetchHandler | Service): Service;
  patch(path: string, handler: FetchHandler | Service): Service;
  fallback(handler: FetchHandler | Service): Service;
}

export const Service: {
  new (): Service;
  from(handler: FetchHandler): Service;
};

export class DhttpHome {
  constructor(path: string);
  static load(): DhttpHome;
  path(): string;
  identityProfile(name: string): IdentityProfile;
  resolveIdentityProfile(name: string): Promise<IdentityProfile>;
  identityProfileExists(name: string): Promise<boolean>;
  identityProfileNames(): Promise<string[]>;
}

export class IdentityProfile {
  static fromPath(path: string): IdentityProfile;
  name(): string;
  path(): string;
  loadIdentity(): Promise<Identity>;
}

export class Identity {
  name(): string;
  certChainDer(): Uint8Array[];
  publicKeyDer(): Uint8Array;
  sign(data: Uint8Array): Uint8Array;
  verify(data: Uint8Array, signature: Uint8Array): boolean;
  asLocalAuthority(): LocalAuthority;
  asRemoteAuthority(): RemoteAuthority;
}

export class ServeHandle {
  shutdown(): Promise<void>;
  abort(): void;
  isFinished(): boolean;
  closed(): Promise<void>;
}

export class Endpoint {
  static create(options?: EndpointOptions | null): Promise<Endpoint>;
  static load(name: string): Promise<Endpoint>;
  static loadFrom(path: string): Promise<Endpoint>;
  identity(): Identity | null;
  bindPatterns(): string[];
  fetch(input: FetchInput, init?: RequestInit): Promise<Response>;
  listen(handler: RawHandler): ServeHandle;
  listen(service: Service): ServeHandle;
  connect(authority: string): Promise<import("@genmeta/dhttp/raw").Connection>;
}

export type DnsScheme = "mdns" | "http" | "h3" | "system";
export type FetchInput = string | URL | Request;
export interface DhttpRequest extends Request {
  authority(): RemoteAuthority | null;
}

export interface DhttpResponse extends Response {
  authority(): RemoteAuthority | null;
}

export type FetchHandler = (request: DhttpRequest) => Response | Promise<Response>;
export type RawHandler = (
  request: import("@genmeta/dhttp/raw").UnresolvedRequest,
) => void | Promise<void>;
export type CertificateChainKind = "primary" | "secondary";

export interface CertificateChainKey {
  sequence: number;
  kind: CertificateChainKind;
}

export interface DhttpSubjectKeyIdentifier {
  value: string;
  chain: CertificateChainKey;
  ownerHash: string;
}

export function parseDhttpSubjectKeyIdentifier(
  value: Uint8Array | string,
): DhttpSubjectKeyIdentifier;

export interface EndpointOptions {
  identity?: Identity | null;
  dnsSchemes?: Iterable<DnsScheme>;
  bindPatterns?: Iterable<string>;
}

export class LocalAuthority {
  private constructor();
  private readonly __dhttpAuthorityBrand: never;
  name(): string;
  certChainDer(): Uint8Array[];
  publicKeyDer(): Uint8Array;
  subjectKeyIdentifier(): Uint8Array | null;
  dhttpSubjectKeyIdentifier(): DhttpSubjectKeyIdentifier;
  sign(data: Uint8Array): Promise<Uint8Array>;
  verify(data: Uint8Array, signature: Uint8Array): Promise<boolean>;
}

export class RemoteAuthority {
  private constructor();
  private readonly __dhttpAuthorityBrand: never;
  name(): string;
  certChainDer(): Uint8Array[];
  publicKeyDer(): Uint8Array;
  subjectKeyIdentifier(): Uint8Array | null;
  dhttpSubjectKeyIdentifier(): DhttpSubjectKeyIdentifier;
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
  subjectKeyIdentifier(): Uint8Array | null;
  dhttpSubjectKeyIdentifier(): DhttpSubjectKeyIdentifier;
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
  fetch(input: FetchInput, init?: RequestInit): Promise<DhttpResponse>;
  listen(handler: RawHandler): ServeHandle;
  listen(service: Service): ServeHandle;
  connect(authority: string): Promise<import("@genmeta/dhttp/raw").Connection>;
}

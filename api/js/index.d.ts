export type FetchInput = string | URL | Request;
export type FetchHandler = (request: Request) => Response | Promise<Response>;

export interface LocalAuthorityLike {
  name(): string;
  certChainDer(): Uint8Array[];
  publicKeyDer(): Uint8Array;
  sign(data: Uint8Array): Promise<Uint8Array>;
  verify(data: Uint8Array, signature: Uint8Array): Promise<boolean>;
}

export interface RemoteAuthorityLike {
  name(): string;
  certChainDer(): Uint8Array[];
  publicKeyDer(): Uint8Array;
  verify(data: Uint8Array, signature: Uint8Array): Promise<boolean>;
}

export class LocalAuthority implements LocalAuthorityLike {
  name(): string;
  certChainDer(): Uint8Array[];
  publicKeyDer(): Uint8Array;
  sign(data: Uint8Array): Promise<Uint8Array>;
  verify(data: Uint8Array, signature: Uint8Array): Promise<boolean>;
}

export class RemoteAuthority implements RemoteAuthorityLike {
  name(): string;
  certChainDer(): Uint8Array[];
  publicKeyDer(): Uint8Array;
  verify(data: Uint8Array, signature: Uint8Array): Promise<boolean>;
}

export interface EndpointCreateOptions {
  identity?: Identity | null;
  dnsSchemes?: Iterable<string>;
  bindPatterns?: Iterable<string>;
}

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

export class EndpointOptions {
  constructor();
  identity(): Identity | null;
  setIdentity(identity: Identity): void;
  clearIdentity(): void;
  addDnsScheme(scheme: string): void;
  dnsSchemes(): string[];
  clearDnsSchemes(): void;
  addBindPattern(pattern: string): void;
  bindPatterns(): string[];
  clearBindPatterns(): void;
}

export class ServeHandle {
  shutdown(): Promise<void>;
  abort(): void;
  isFinished(): boolean;
  closed(): Promise<void>;
}

export class Endpoint {
  static create(options?: EndpointOptions | EndpointCreateOptions | null): Promise<Endpoint>;
  static load(name: string): Promise<Endpoint>;
  static loadFrom(path: string): Promise<Endpoint>;
  identity(): Identity | null;
  bindPatterns(): string[];
  fetch(input: FetchInput, init?: RequestInit): Promise<Response>;
  listen(handler: FetchHandler): ServeHandle;
}

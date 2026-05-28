export type FetchInput = string | URL | Request;
export type FetchHandler = (request: Request) => Response | Promise<Response>;

export type SchemeLike = SignatureScheme | number | string;

export enum SignatureScheme {
  RsaPkcs1Sha256 = 0x0401,
  RsaPkcs1Sha384 = 0x0501,
  RsaPkcs1Sha512 = 0x0601,
  EcdsaNistp256Sha256 = 0x0403,
  EcdsaNistp384Sha384 = 0x0503,
  RsaPssSha256 = 0x0804,
  RsaPssSha384 = 0x0805,
  RsaPssSha512 = 0x0806,
  Ed25519 = 0x0807,
}

export interface LocalAgentLike {
  name(): string;
  certChainDer(): Uint8Array[];
  publicKeyDer(): Uint8Array;
  sign(scheme: SchemeLike, data: Uint8Array): Promise<Uint8Array>;
  verify(scheme: SchemeLike, data: Uint8Array, signature: Uint8Array): Promise<boolean>;
}

export interface RemoteAgentLike {
  name(): string;
  certChainDer(): Uint8Array[];
  publicKeyDer(): Uint8Array;
  verify(scheme: SchemeLike, data: Uint8Array, signature: Uint8Array): Promise<boolean>;
}

export class LocalAgent implements LocalAgentLike {
  name(): string;
  certChainDer(): Uint8Array[];
  publicKeyDer(): Uint8Array;
  sign(scheme: SchemeLike, data: Uint8Array): Promise<Uint8Array>;
  verify(scheme: SchemeLike, data: Uint8Array, signature: Uint8Array): Promise<boolean>;
}

export class RemoteAgent implements RemoteAgentLike {
  name(): string;
  certChainDer(): Uint8Array[];
  publicKeyDer(): Uint8Array;
  verify(scheme: SchemeLike, data: Uint8Array, signature: Uint8Array): Promise<boolean>;
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
  sign(scheme: SchemeLike, data: Uint8Array): Uint8Array;
  verify(scheme: SchemeLike, data: Uint8Array, signature: Uint8Array): boolean;
  asLocalAgent(): LocalAgent;
  asRemoteAgent(): RemoteAgent;
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
  serve(handler: FetchHandler): ServeHandle;
}

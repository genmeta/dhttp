export type FetchInput = string | URL | Request;
export type FetchHandler = (request: Request) => Response | Promise<Response>;

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

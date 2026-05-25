export type FetchInput = string | URL | Request;
export type FetchHandler = (request: Request) => Response | Promise<Response>;

export class Config {
  constructor(path: string);
  static load(): Config;
  path(): string;
  identityConfig(name: string): IdentityConfig;
  loadIdentity(name: string): Promise<IdentityConfig>;
  identityExists(name: string): Promise<boolean>;
  identities(): Promise<string[]>;
}

export class IdentityConfig {
  static fromPath(path: string): IdentityConfig;
  name(): string;
  path(): string;
  identity(): Promise<Identity>;
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
  static create(options?: EndpointOptions | null): Promise<Endpoint>;
  static load(name: string): Promise<Endpoint>;
  static loadFrom(path: string): Promise<Endpoint>;
  identity(): Identity | null;
  bindPatterns(): string[];
  fetch(input: FetchInput, init?: RequestInit): Promise<Response>;
  serve(handler: FetchHandler): ServeHandle;
}

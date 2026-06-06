export interface HeaderField {
  name: Uint8Array;
  value: Uint8Array;
}

export class Connection {
  openRequest(): Promise<UnresolvedRequest>;
  localAuthority(): Promise<import("@genmeta/dhttp").LocalAuthority | null>;
  remoteAuthority(): Promise<import("@genmeta/dhttp").RemoteAuthority | null>;
}

export class UnresolvedRequest {
  get streamId(): number;
  get reader(): MessageReader;
  get writer(): MessageWriter;
  localAuthority(): Promise<import("@genmeta/dhttp").LocalAuthority | null>;
  remoteAuthority(): Promise<import("@genmeta/dhttp").RemoteAuthority | null>;
}

export class MessageReader {
  readHeader(): Promise<HeaderField[] | null>;
  readData(): Promise<Uint8Array | null>;
  stop(code: number): Promise<void>;
}

export class MessageWriter {
  writeHeader(headers: HeaderField[]): Promise<void>;
  writeData(data: Uint8Array): Promise<void>;
  flush(): Promise<void>;
  close(): Promise<void>;
  reset(code: number): Promise<void>;
}

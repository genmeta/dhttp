import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const mod = require('./raw.js');

export const Connection = mod.Connection;
export const UnresolvedRequest = mod.UnresolvedRequest;
export const MessageReader = mod.MessageReader;
export const MessageWriter = mod.MessageWriter;

export default mod;

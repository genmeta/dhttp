import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const mod = require('./index.js');

export const Endpoint = mod.Endpoint;
export const Service = mod.Service;
export const DhttpHome = mod.DhttpHome;
export const IdentityProfile = mod.IdentityProfile;
export const Identity = mod.Identity;
export const ServeHandle = mod.ServeHandle;

export default mod;

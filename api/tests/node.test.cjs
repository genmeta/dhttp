'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const packageRoot = process.env.DHTTP_TEST_NODE_PACKAGE ?? path.resolve(__dirname, '..');
const sdk = require(packageRoot);

test('CommonJS/ESM exports and invalid profile error', async () => {
  assert.equal(typeof sdk.Endpoint.loadFrom, 'function');
  assert.equal(typeof sdk.Anonymous.fetch, 'function');
  const esm = await import(require('node:url').pathToFileURL(path.join(packageRoot, 'js/index.mjs')).href);
  assert.equal(esm.Endpoint, sdk.Endpoint);
  await assert.rejects(sdk.Endpoint.loadFrom('/does-not-exist/alice'), error => error.code === 'ERR_IDENTITY');
});

const root = process.env.DHTTP_TEST_PROFILE_ROOT;
test('real Node HTTP3 streaming, identity, cancellation and close', {skip: !root, timeout: 25000}, async () => {
  await sdk.init({rootCertificates: fs.readFileSync(path.join(root, 'ca.crt'))});
  const server = await sdk.Endpoint.loadFrom(path.join(root, 'server'));
  const alice = await sdk.Endpoint.loadFrom(path.join(root, 'alice'));
  const bob = await sdk.Endpoint.loadFrom(path.join(root, 'bob'));
  const payload = Buffer.alloc(512 * 1024, 0x5a);
  const {spawn} = require('node:child_process');
  const child = spawn(process.execPath, [path.join(__dirname, 'node-server.cjs'), root], {stdio: ['ignore', 'inherit', 'inherit', 'ipc']});
  let id = 0;
  const rpc = command => new Promise((resolve, reject) => {
    const requestId = ++id;
    const receive = message => { if (message.id === requestId) { child.off('message', receive); message.error ? reject(new Error(message.error)) : resolve(message); } };
    child.on('message', receive); child.send({id: requestId, ...command});
  });
  const ready = await new Promise((resolve,reject) => { child.once('message',resolve); child.once('error',reject); });
  const exited = new Promise(resolve => child.once('exit', resolve));
  try {
    const address = ready.address;
    await sdk.init({peers: {'server.dhttp.net': address, 'alice.dhttp.net': address}});
    await server.reload(); await alice.reload();
    const local = await alice.localAuthority();
    const signature = await local.sign(Buffer.from('hello'));
    assert.equal(local.verify(Buffer.from('hello'), signature), true);
    assert.equal(local.verify(Buffer.from('other'), signature), false);
    const anonymous = await sdk.Anonymous.fetch('https://server~/anonymous');
    assert.equal(anonymous.remoteAuthority.name, 'server.dhttp.net');
    assert.equal(await anonymous.text(), 'ok');
    assert.equal((await anonymous.trailers).size, undefined);
    let releaseUpload;
    const gate = new Promise(resolve => { releaseUpload = resolve; });
    const input = new ReadableStream({async start(controller) { await gate; controller.enqueue(payload); controller.close(); }});
    const response = await alice.fetch('https://server~/echo', {method: 'POST', body: input,
      headers: [['x-repeat', 'one'], ['x-repeat', 'two']], trailers: [['x-end', 'one'], ['x-end', 'two']]});
    // Headers arrive while the upload producer is still waiting.
    assert.equal(response.status, 200);
    releaseUpload();
    assert.deepEqual(Buffer.from(await response.arrayBuffer()), payload);
    assert.equal((await response.trailers).get('x-response-end'), 'one, two');
    const reverse = await alice.listen(['loopback', 'internal'], request => {
      assert.equal(request.remoteAuthority.name, 'server.dhttp.net');
      return new Response('reverse');
    });
    assert.equal((await rpc({action: 'reverse', address: sdk.addresses().find(address => !address.startsWith('['))})).result, 'reverse');
    await reverse.close();
    let failUpload;
    const failedInput = new ReadableStream({async pull() { await new Promise(resolve => { failUpload = resolve; }); throw new Error('producer exploded'); }});
    const broken = await alice.fetch('https://server~/pending', {method: 'POST', body: failedInput});
    failUpload();
    await assert.rejects(broken.text(), error => error.code === 'ERR_PRODUCER');
    const failed = await alice.fetch('https://server~/error');
    assert.equal(failed.status, 500); assert.equal(await failed.text(), '');
    await assert.rejects(alice.fetch('https://server~/ok', {ownerHash: 'f'.repeat(64)}), error => error.code === 'ERR_REMOTE_IDENTITY_CHANGED');
    const controller = new AbortController();
    const pending = alice.fetch('https://server~/hang', {signal: controller.signal});
    setTimeout(() => controller.abort(), 20);
    await assert.rejects(pending, error => error.name === 'AbortError');
    await assert.rejects(alice.fetch('https://server~/hang', {timeout: 30}), error => error.code === 'ERR_DEADLINE_EXCEEDED');
    const stalled = await alice.fetch('https://server~/pending');
    await alice.close();
    await assert.rejects(stalled.text(), error => error.code === 'ERR_CLOSED');
    assert.equal(await (await bob.fetch('https://server~/ok')).text(), 'ok');
    await rpc({action: 'relisten'});
    assert.equal(await (await bob.fetch('https://server~/ok')).text(), 'ok');
  } finally {
    await rpc({action: 'close'}); await exited; await Promise.all([server.close(), alice.close(), bob.close(), sdk.Anonymous.close()]);
  }
});

'use strict';
const sdk = require(process.env.DHTTP_TEST_NODE_PACKAGE ?? '../js/index.js');
const fs = require('node:fs');
const path = require('node:path');
const handler = require('./node-handler.cjs')();
(async () => {
  const root = process.argv[2];
  await sdk.init({rootCertificates: fs.readFileSync(path.join(root, 'ca.crt'))});
  const server = await sdk.Endpoint.loadFrom(path.join(root, 'server'));
  let listener = await server.listen(['loopback', 'internal'], handler);
  await server.reload();
  process.send({address: sdk.addresses().find(address => !address.startsWith('['))});
  process.on('message', async command => {
    try {
      if (command.action === 'relisten') { await listener.close(); await listener.close(); listener = await server.listen(['loopback', 'internal'], handler); }
      if (command.action === 'reverse') { await sdk.init({peers: {'alice.dhttp.net': command.address}}); const response = await server.fetch('https://alice~/reverse'); command.result = await response.text(); }
      if (command.action === 'close') { await listener.close(); await server.close(); await sdk.Anonymous.close(); }
      process.send({id: command.id, result: command.result});
      if (command.action === 'close') process.disconnect();
    } catch (error) { process.send({id: command.id, error: error.stack}); }
  });
})().catch(error => { console.error(error); process.exitCode = 1; process.disconnect(); });

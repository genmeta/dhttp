'use strict';
const assert = require('node:assert/strict');
module.exports = () => {
  const handler = async request => {
    assert.equal(request.localAuthority.name, 'server.dhttp.net');
    if (request.url.endsWith('/echo')) {
      assert.equal(request.remoteAuthority.name, 'alice.dhttp.net');
      assert.deepEqual(request.rawHeaders.filter(([name]) => name === 'x-repeat').map(([,value]) => value), ['one', 'two']);
      const response = new Response(request.body, {headers: [['x-repeat', 'one'], ['x-repeat', 'two']]});
      Object.defineProperty(response, 'trailers', {value: async () => {
        const end = await request.trailers;
        assert.equal(end.get('x-end'), 'one, two');
        return [['x-response-end', 'one'], ['x-response-end', 'two']];
      }});
      return response;
    }
    if (request.url.endsWith('/error')) throw new Error('private exception');
    if (request.url.endsWith('/hang')) return new Promise(() => {});
    if (request.url.endsWith('/pending')) return new Response(new ReadableStream({pull() {return new Promise(() => {});}}));
    if (request.url.endsWith('/anonymous')) assert.equal(request.remoteAuthority, null);
    return new Response('ok');
  };
return handler;
};

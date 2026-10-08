import {Endpoint, Anonymous, Response, type DhttpResponse, type ServerRequest} from '../js/index.js';
async function example() {
  const endpoint = await Endpoint.load('alice');
  const result: DhttpResponse = await Anonymous.fetch('https://bob~/hello');
  await result.trailers;
  const listener = await endpoint.listen(['internal'], async (request: ServerRequest) => new Response(await request.text()));
  await listener.close();
  await endpoint.close();
}
void example;

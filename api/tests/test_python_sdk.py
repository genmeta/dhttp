import asyncio
import os
from pathlib import Path
import unittest
import json
import sys
import dhttpy

class SDKTests(unittest.IsolatedAsyncioTestCase):
    async def test_shape_and_invalid_profile(self):
        self.assertTrue(callable(dhttpy.Endpoint.load_from))
        with self.assertRaises(dhttpy.DhttpError) as caught:
            await dhttpy.Endpoint.load_from('/does-not-exist/alice')
        self.assertEqual(caught.exception.code, 'ERR_IDENTITY')
        self.assertEqual(dhttpy.Headers([('x','one'),('X','two')]).getall('x'), ['one','two'])

    @unittest.skipUnless(os.getenv('DHTTP_TEST_PROFILE_ROOT'), 'requires temporary test profiles and UDP permission')
    async def test_real_http3_streams_identity_cancellation_and_close(self):
        root = Path(os.environ['DHTTP_TEST_PROFILE_ROOT'])
        await dhttpy.init(root_certificates=(root/'ca.crt').read_bytes())
        server = await dhttpy.Endpoint.load_from(root/'server')
        alice = await dhttpy.Endpoint.load_from(root/'alice')
        bob = await dhttpy.Endpoint.load_from(root/'bob')
        payload = b'Z' * (512 * 1024)
        child = await asyncio.create_subprocess_exec(sys.executable, str(Path(__file__).with_name('python_server.py')), str(root), stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE)
        ready = json.loads(await asyncio.wait_for(child.stdout.readline(), 5))
        async def rpc(action):
            child.stdin.write((json.dumps({'action':action})+'\n').encode())
            await child.stdin.drain()
            return json.loads(await child.stdout.readline())
        try:
            address = ready["address"]
            await dhttpy.init(peers={'server.dhttp.net':address})
            await server.reload(); await alice.reload()
            local = await alice.local_authority()
            signature = await local.sign(b'hello')
            self.assertTrue(local.verify(b'hello', signature))
            self.assertFalse(local.verify(b'other', signature))
            async with dhttpy.Anonymous.get('https://server~/anonymous') as response:
                self.assertEqual(response.remote_authority.name, 'server.dhttp.net')
                self.assertEqual(await response.text(), 'ok')
                self.assertEqual(len(await response.trailers()), 0)
            gate = asyncio.Event()
            async def input():
                await gate.wait()
                yield payload
            response = await alice.post('https://server~/echo', data=input(), headers=[('x-repeat','one'),('x-repeat','two')], trailers=[('x-end','one'),('x-end','two')])
            self.assertEqual(response.status, 200)
            gate.set()
            self.assertEqual(await response.read(), payload)
            self.assertEqual((await response.trailers()).getall('x-response-end'), ['one','two'])
            await response.release()
            fail = asyncio.Event()
            async def failed_input():
                await fail.wait()
                raise RuntimeError('producer exploded')
                yield b'never'
            broken = await alice.post('https://server~/pending', data=failed_input())
            fail.set()
            with self.assertRaises(dhttpy.DhttpError) as caught: await broken.read()
            self.assertEqual(caught.exception.code, 'ERR_PRODUCER')
            async with alice.get('https://server~/error') as response:
                self.assertEqual(response.status,500)
                self.assertEqual(await response.read(),b'')
            with self.assertRaises(dhttpy.DhttpError) as caught:
                await alice.get('https://server~/ok',owner_hash='f'*64)
            self.assertEqual(caught.exception.code,'ERR_REMOTE_IDENTITY_CHANGED')
            task = asyncio.ensure_future(alice.get('https://server~/hang'))
            await asyncio.sleep(.02); task.cancel()
            with self.assertRaises(asyncio.CancelledError): await task
            with self.assertRaises(dhttpy.DhttpError) as caught:
                await alice.get('https://server~/hang',timeout=.03)
            self.assertEqual(caught.exception.code,'ERR_DEADLINE_EXCEEDED')
            stalled = await alice.get('https://server~/pending')
            await alice.close()
            with self.assertRaises(dhttpy.DhttpError) as caught: await stalled.read()
            self.assertEqual(caught.exception.code,'ERR_CLOSED')
            async with bob.get('https://server~/ok') as response: self.assertEqual(await response.text(),'ok')
            await rpc('relisten')
        finally:
            await rpc('close')
            child.stdin.close()
            await asyncio.wait_for(child.wait(),5)
            self.assertEqual(child.returncode,0)
            await asyncio.gather(server.close(),alice.close(),bob.close(),dhttpy.Anonymous.close())
        # SDK-owned asyncio producer and handler tasks have all been reclaimed.
        await asyncio.sleep(0)
        self.assertFalse([task for task in asyncio.all_tasks() if task is not asyncio.current_task() and not task.done()])

if __name__ == '__main__': unittest.main()

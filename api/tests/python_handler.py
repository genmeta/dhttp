import asyncio
import dhttpy
def make_handler(self):
    async def handler(request):
        self.assertEqual(request.local_authority.name, 'server.dhttp.net')
        if request.url.endswith('/echo'):
            self.assertEqual(request.remote_authority.name, 'alice.dhttp.net')
            self.assertEqual(request.headers.getall('x-repeat'), ['one', 'two'])
            async def output():
                async for chunk in request.content: yield chunk
            async def end():
                fields = await request.trailers()
                self.assertEqual(fields.getall('x-end'), ['one', 'two'])
                return [('x-response-end','one'),('x-response-end','two')]
            return dhttpy.Response(output(), headers=[('x-repeat','one'),('x-repeat','two')], trailers=end)
        if request.url.endswith('/error'): raise RuntimeError('private exception')
        if request.url.endswith('/hang'): await asyncio.Event().wait()
        if request.url.endswith('/pending'):
            async def output():
                await asyncio.Event().wait()
                yield b'never'
            return dhttpy.Response(output())
        if request.url.endswith('/anonymous'): self.assertIsNone(request.remote_authority)
        return dhttpy.Response.text('ok')
    return handler

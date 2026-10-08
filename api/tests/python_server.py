import asyncio
import json
import sys
import unittest
from pathlib import Path
import dhttpy
from python_handler import make_handler

async def main():
    root = Path(sys.argv[1])
    await dhttpy.init(root_certificates=(root/'ca.crt').read_bytes())
    server = await dhttpy.Endpoint.load_from(root/'server')
    handler = make_handler(unittest.TestCase())
    listener = await server.listen(['loopback','internal'],handler)
    await server.reload()
    print(json.dumps({'address':next(address for address in dhttpy.addresses() if not address.startswith('['))}),flush=True)
    try:
        while line := await asyncio.to_thread(sys.stdin.readline):
            action = json.loads(line)['action']
            if action == 'relisten':
                await listener.close(); await listener.close()
                listener = await server.listen(['loopback','internal'],handler)
            if action == 'close':
                await listener.close(); await server.close(); await dhttpy.Anonymous.close()
            print(json.dumps({'ok':True}),flush=True)
            if action == 'close': break
    finally:
        await listener.close(); await server.close()

asyncio.run(main())

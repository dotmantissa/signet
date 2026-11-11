"""Direct-runner routing for real contract code with isolated in-memory storage.

The direct runner has one storage context and no delivery scheduler. This test
adapter isolates deployed contracts and routes actual view calls. Finalized
messages are queued, never automatically treated as network finality proof.
Studio integration tests exercise the real message scheduler and consensus.
"""
from contextlib import contextmanager


class BoundContract:
    def __init__(self, world, contract, address, storage):
        self.world, self.contract, self.address, self.storage = world, contract, address, storage

    def __getattr__(self, name):
        with self.world.context(self):
            attr = getattr(self.contract, name)
        if callable(attr):
            def invoke(*args, **kwargs):
                with self.world.context(self):
                    return attr(*args, **kwargs)
            return invoke
        return attr


class World:
    def __init__(self, vm, deploy):
        self.vm, self.deploy_raw = vm, deploy
        self.contracts, self.messages = {}, []
        vm._gl_call_hook = self.route

    @contextmanager
    def context(self, target):
        from genlayer import gl
        vm = self.vm
        old = (vm._storage, vm._contract_address, gl.message, dict(gl.message_raw))
        vm._storage = target.storage
        vm._contract_address = target.address
        vm._refresh_gl_message()
        gl.message = gl.message._replace(contract_address=target.address)
        gl.message_raw.update({'contract_address':target.address, 'datetime':vm._datetime})
        try:
            yield
        finally:
            vm._storage, vm._contract_address, gl.message, raw = old
            gl.message_raw.clear()
            gl.message_raw.update(raw)

    def deploy(self, path, *args):
        from gltest.direct.vm import InmemManager
        import sys
        if 'genlayer.gl.genvm_contracts' in sys.modules:
            sys.modules['genlayer.gl.genvm_contracts'].__known_contract__ = None
        self.vm._storage = InmemManager()
        contract = self.deploy_raw(path, *args)
        from genlayer import Address
        import hashlib
        address = Address(hashlib.sha256((path + str(len(self.contracts))).encode()).digest()[:20])
        bound = BoundContract(self, contract, address, self.vm._storage)
        self.contracts[str(address).lower()] = bound
        return bound

    def route(self, vm, request):
        from genlayer import gl
        from genlayer.py import calldata
        if 'PostMessage' in request:
            message = dict(request['PostMessage'])
            message['sender'] = gl.message.contract_address
            self.messages.append(message)
            return {'ok': None}
        if 'CallContract' in request:
            call = request['CallContract']
            target = self.contracts[str(call['address']).lower()]
            cd = call['calldata']
            with vm.prank(gl.message.contract_address):
                value = getattr(target, cd['method'])(*cd.get('args', []), **cd.get('kwargs', {}))
            return b'\x00' + calldata.encode(value)
        return None

    def run_next(self, method):
        index = next((i for i, m in enumerate(self.messages) if m['calldata']['method'] == method), None)
        if index is None:
            return False
        message = self.messages.pop(index)
        target = self.contracts[str(message['address']).lower()]
        cd = message['calldata']
        with self.vm.prank(message['sender']):
            getattr(target, cd['method'])(*cd.get('args', []), **cd.get('kwargs', {}))
        return True

    def drain(self, on='finalized', limit=100):
        for _ in range(limit):
            eligible = next((i for i, m in enumerate(self.messages) if m['on'] == on), None)
            if eligible is None:
                return
            message = self.messages.pop(eligible)
            target = self.contracts[str(message['address']).lower()]
            cd = message['calldata']
            with self.vm.prank(message['sender']):
                getattr(target, cd['method'])(*cd.get('args', []), **cd.get('kwargs', {}))
        raise AssertionError('unbounded callback sequence')

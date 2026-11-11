# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
from genlayer import *
from dataclasses import dataclass
import hashlib

@allow_storage
@dataclass
class Record:
    digest: str
    generation: u64

class RuntimeProbe(gl.Contract):
    owner: Address
    records: TreeMap[str, Record]
    history: DynArray[str]
    finalized: bool

    def __init__(self):
        self.owner = gl.message.sender_address
        self.records['probe'] = Record(hashlib.sha256(b'Signet').hexdigest(), u64(1))
        self.history.append('probe')
        self.finalized = False
        gl.get_contract_at(gl.message.contract_address).emit(on='finalized').confirm()

    @gl.public.write
    def confirm(self) -> None:
        if gl.message.sender_address != gl.message.contract_address:
            raise gl.UserError('Only self')
        self.finalized = True

    @gl.public.view
    def inspect(self) -> dict:
        return {'digest': self.records['probe'].digest, 'generation': int(self.records['probe'].generation), 'finalized': self.finalized, 'datetime': gl.message_raw.get('datetime', '')}

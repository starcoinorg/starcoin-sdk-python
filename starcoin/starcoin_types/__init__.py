# pyre-strict
from dataclasses import dataclass
import typing
from starcoin import serde_types as st
from starcoin import bcs


@dataclass(frozen=True)
class AcceptTokenEvent:
    token_code: "TokenCode"

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, AcceptTokenEvent)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'AcceptTokenEvent':
        v, buffer = bcs.deserialize(input, AcceptTokenEvent)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


@dataclass(frozen=True)
class AccessPath:
    address: "AccountAddress"
    path: "DataPath"

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, AccessPath)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'AccessPath':
        v, buffer = bcs.deserialize(input, AccessPath)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


@dataclass(frozen=True)
class AccountAddress:
    value: typing.Tuple[st.uint8, st.uint8, st.uint8, st.uint8, st.uint8, st.uint8, st.uint8,
                        st.uint8, st.uint8, st.uint8, st.uint8, st.uint8, st.uint8, st.uint8, st.uint8, st.uint8]

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, AccountAddress)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'AccountAddress':
        v, buffer = bcs.deserialize(input, AccountAddress)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v

    @staticmethod
    def from_hex(addr: str) -> 'AccountAddress':
        """Create an account address from bytes."""
        return AccountAddress(tuple(st.uint8(x) for x in bytes.fromhex(addr)))


@dataclass(frozen=True)
class AccountResource:
    authentication_key: bytes
    withdrawal_capability: typing.Optional["WithdrawCapabilityResource"]
    key_rotation_capability: typing.Optional["KeyRotationCapabilityResource"]
    received_events: "EventHandle"
    sent_events: "EventHandle"
    accept_token_events: "EventHandle"
    sequence_number: st.uint64

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, AccountResource)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'AccountResource':
        v, buffer = bcs.deserialize(input, AccountResource)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


@dataclass(frozen=True)
class BalanceResource:
    token: st.uint128

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, BalanceResource)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'BalanceResource':
        v, buffer = bcs.deserialize(input, BalanceResource)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


@dataclass(frozen=True)
class BlockMetadata:
    parent_hash: "HashValue"
    timestamp: st.uint64
    author: "AccountAddress"
    auth_key_prefix: bytes
    uncles: st.uint64
    number: st.uint64

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, BlockMetadata)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'BlockMetadata':
        v, buffer = bcs.deserialize(input, BlockMetadata)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


@dataclass(frozen=True)
class BlockRewardEvent:
    block_number: st.uint64
    block_reward: st.uint128
    gas_fees: st.uint128
    miner: "AccountAddress"

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, BlockRewardEvent)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'BlockRewardEvent':
        v, buffer = bcs.deserialize(input, BlockRewardEvent)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


@dataclass(frozen=True)
class BurnEvent:
    amount: st.uint128
    token_code: "TokenCode"

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, BurnEvent)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'BurnEvent':
        v, buffer = bcs.deserialize(input, BurnEvent)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


@dataclass(frozen=True)
class ChainId:
    value: st.uint8

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, ChainId)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'ChainId':
        v, buffer = bcs.deserialize(input, ChainId)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


@dataclass(frozen=True)
class ChangeSet:
    write_set: "WriteSet"
    events: typing.Sequence["ContractEvent"]

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, ChangeSet)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'ChangeSet':
        v, buffer = bcs.deserialize(input, ChangeSet)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


class ContractEvent:
    VARIANTS = []  # type: typing.Sequence[typing.Type[ContractEvent]]

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, ContractEvent)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'ContractEvent':
        v, buffer = bcs.deserialize(input, ContractEvent)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


@dataclass(frozen=True)
class ContractEvent__V0(ContractEvent):
    INDEX = 0  # type: int
    value: "ContractEventV0"


ContractEvent.VARIANTS = [
    ContractEvent__V0,
]


@dataclass(frozen=True)
class ContractEventV0:
    key: "EventKey"
    sequence_number: st.uint64
    type_tag: "TypeTag"
    event_data: bytes

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, ContractEventV0)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'ContractEventV0':
        v, buffer = bcs.deserialize(input, ContractEventV0)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


class DataPath:
    VARIANTS = []  # type: typing.Sequence[typing.Type[DataPath]]

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, DataPath)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'DataPath':
        v, buffer = bcs.deserialize(input, DataPath)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


@dataclass(frozen=True)
class DataPath__Code(DataPath):
    INDEX = 0  # type: int
    value: "Identifier"


@dataclass(frozen=True)
class DataPath__Resource(DataPath):
    INDEX = 1  # type: int
    value: "StructTag"


DataPath.VARIANTS = [
    DataPath__Code,
    DataPath__Resource,
]


@dataclass(frozen=True)
class DepositEvent:
    amount: st.uint128
    token_code: "TokenCode"
    metadata: typing.Sequence[st.uint8]

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, DepositEvent)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'DepositEvent':
        v, buffer = bcs.deserialize(input, DepositEvent)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


@dataclass(frozen=True)
class Ed25519PublicKey:
    value: bytes

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, Ed25519PublicKey)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'Ed25519PublicKey':
        v, buffer = bcs.deserialize(input, Ed25519PublicKey)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


@dataclass(frozen=True)
class Ed25519Signature:
    value: bytes

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, Ed25519Signature)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'Ed25519Signature':
        v, buffer = bcs.deserialize(input, Ed25519Signature)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


@dataclass(frozen=True)
class EventFilter:
    from_block: typing.Optional[st.uint64]
    to_block: typing.Optional[st.uint64]
    event_keys: typing.Sequence["EventKey"]
    limit: typing.Optional[st.uint64]

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, EventFilter)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'EventFilter':
        v, buffer = bcs.deserialize(input, EventFilter)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


@dataclass(frozen=True)
class EventHandle:
    count: st.uint64
    key: bytes

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, EventHandle)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'EventHandle':
        v, buffer = bcs.deserialize(input, EventHandle)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


@dataclass(frozen=True)
class EventKey:
    salt: st.uint64
    address: AccountAddress

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, EventKey)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'EventKey':
        v, buffer = bcs.deserialize(input, EventKey)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


class GeneralMetadata:
    VARIANTS = []  # type: typing.Sequence[typing.Type[GeneralMetadata]]

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, GeneralMetadata)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'GeneralMetadata':
        v, buffer = bcs.deserialize(input, GeneralMetadata)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


@dataclass(frozen=True)
class GeneralMetadata__GeneralMetadataVersion0(GeneralMetadata):
    INDEX = 0  # type: int
    value: "GeneralMetadataV0"


GeneralMetadata.VARIANTS = [
    GeneralMetadata__GeneralMetadataVersion0,
]


@dataclass(frozen=True)
class GeneralMetadataV0:
    to_subaddress: typing.Optional[bytes]
    from_subaddress: typing.Optional[bytes]
    referenced_event: typing.Optional[st.uint64]

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, GeneralMetadataV0)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'GeneralMetadataV0':
        v, buffer = bcs.deserialize(input, GeneralMetadataV0)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


@dataclass(frozen=True)
class HashValue:
    value: bytes

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, HashValue)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'HashValue':
        v, buffer = bcs.deserialize(input, HashValue)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


@dataclass(frozen=True)
class Identifier:
    value: str

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, Identifier)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'Identifier':
        v, buffer = bcs.deserialize(input, Identifier)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


@dataclass(frozen=True)
class KeyRotationCapabilityResource:
    account_address: "AccountAddress"

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, KeyRotationCapabilityResource)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'KeyRotationCapabilityResource':
        v, buffer = bcs.deserialize(input, KeyRotationCapabilityResource)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


class Kind:
    VARIANTS = []  # type: typing.Sequence[typing.Type[Kind]]

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, Kind)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'Kind':
        v, buffer = bcs.deserialize(input, Kind)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


@dataclass(frozen=True)
class Kind__NewHeads(Kind):
    INDEX = 0  # type: int
    pass


@dataclass(frozen=True)
class Kind__Events(Kind):
    INDEX = 1  # type: int
    pass


@dataclass(frozen=True)
class Kind__NewPendingTransactions(Kind):
    INDEX = 2  # type: int
    pass


@dataclass(frozen=True)
class Kind__NewMintBlock(Kind):
    INDEX = 3  # type: int
    pass


Kind.VARIANTS = [
    Kind__NewHeads,
    Kind__Events,
    Kind__NewPendingTransactions,
    Kind__NewMintBlock,
]


class Metadata:
    VARIANTS = []  # type: typing.Sequence[typing.Type[Metadata]]

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, Metadata)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'Metadata':
        v, buffer = bcs.deserialize(input, Metadata)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


@dataclass(frozen=True)
class Metadata__Undefined(Metadata):
    INDEX = 0  # type: int
    pass


@dataclass(frozen=True)
class Metadata__GeneralMetadata(Metadata):
    INDEX = 1  # type: int
    value: "GeneralMetadata"


@dataclass(frozen=True)
class Metadata__TravelRuleMetadata(Metadata):
    INDEX = 2  # type: int
    value: "TravelRuleMetadata"


@dataclass(frozen=True)
class Metadata__UnstructuredBytesMetadata(Metadata):
    INDEX = 3  # type: int
    value: "UnstructuredBytesMetadata"


Metadata.VARIANTS = [
    Metadata__Undefined,
    Metadata__GeneralMetadata,
    Metadata__TravelRuleMetadata,
    Metadata__UnstructuredBytesMetadata,
]


@dataclass(frozen=True)
class MintEvent:
    amount: st.uint128
    token_code: "TokenCode"

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, MintEvent)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'MintEvent':
        v, buffer = bcs.deserialize(input, MintEvent)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


@dataclass(frozen=True)
class Module:
    code: bytes

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, Module)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'Module':
        v, buffer = bcs.deserialize(input, Module)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


@dataclass(frozen=True)
class ModuleId:
    address: "AccountAddress"
    name: "Identifier"

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, ModuleId)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'ModuleId':
        v, buffer = bcs.deserialize(input, ModuleId)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


@dataclass(frozen=True)
class MultiEd25519PublicKey:
    value: bytes

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, MultiEd25519PublicKey)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'MultiEd25519PublicKey':
        v, buffer = bcs.deserialize(input, MultiEd25519PublicKey)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


@dataclass(frozen=True)
class MultiEd25519Signature:
    value: bytes

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, MultiEd25519Signature)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'MultiEd25519Signature':
        v, buffer = bcs.deserialize(input, MultiEd25519Signature)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


@dataclass(frozen=True)
class NewBlockEvent:
    number: st.uint64
    author: "AccountAddress"
    timestamp: st.uint64
    uncles: st.uint64

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, NewBlockEvent)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'NewBlockEvent':
        v, buffer = bcs.deserialize(input, NewBlockEvent)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


@dataclass(frozen=True)
class Package:
    package_address: "AccountAddress"
    modules: typing.Sequence["Module"]
    init_script: "Script"

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, Package)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'Package':
        v, buffer = bcs.deserialize(input, Package)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


@dataclass(frozen=True)
class ProposalCreatedEvent:
    proposal_id: st.uint64
    proposer: "AccountAddress"

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, ProposalCreatedEvent)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'ProposalCreatedEvent':
        v, buffer = bcs.deserialize(input, ProposalCreatedEvent)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


@dataclass(frozen=True)
class RawTransaction:
    sender: "AccountAddress"
    sequence_number: st.uint64
    payload: "TransactionPayload"
    max_gas_amount: st.uint64
    gas_unit_price: st.uint64
    gas_token_code: str
    expiration_timestamp_secs: st.uint64
    chain_id: "ChainId"

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, RawTransaction)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'RawTransaction':
        v, buffer = bcs.deserialize(input, RawTransaction)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


@dataclass(frozen=True)
class Script:
    code: bytes
    ty_args: typing.Sequence["TypeTag"]
    args: typing.Sequence["TransactionArgument"]

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, Script)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'Script':
        v, buffer = bcs.deserialize(input, Script)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


@dataclass(frozen=True)
class ScriptFunction:
    module: "ModuleId"
    function: "Identifier"
    ty_args: typing.Sequence["TypeTag"]
    args: typing.Sequence["bytes"]

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, ScriptFunction)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'ScriptFunction':
        v, buffer = bcs.deserialize(input, ScriptFunction)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


@dataclass(frozen=True)
class SignedUserTransaction:
    raw_txn: "RawTransaction"
    authenticator: "TransactionAuthenticator"

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, SignedUserTransaction)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'SignedUserTransaction':
        v, buffer = bcs.deserialize(input, SignedUserTransaction)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


@dataclass(frozen=True)
class StructTag:
    address: "AccountAddress"
    module: "Identifier"
    name: "Identifier"
    type_params: typing.Sequence["TypeTag"]

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, StructTag)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'StructTag':
        v, buffer = bcs.deserialize(input, StructTag)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


@dataclass(frozen=True)
class TokenCode:
    address: "AccountAddress"
    module: str
    name: str

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, TokenCode)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'TokenCode':
        v, buffer = bcs.deserialize(input, TokenCode)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


class Transaction:
    VARIANTS = []  # type: typing.Sequence[typing.Type[Transaction]]

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, Transaction)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'Transaction':
        v, buffer = bcs.deserialize(input, Transaction)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


@dataclass(frozen=True)
class Transaction__UserTransaction(Transaction):
    INDEX = 0  # type: int
    value: "SignedUserTransaction"


@dataclass(frozen=True)
class Transaction__BlockMetadata(Transaction):
    INDEX = 1  # type: int
    value: "BlockMetadata"


Transaction.VARIANTS = [
    Transaction__UserTransaction,
    Transaction__BlockMetadata,
]


class TransactionArgument:
    VARIANTS = []  # type: typing.Sequence[typing.Type[TransactionArgument]]

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, TransactionArgument)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'TransactionArgument':
        v, buffer = bcs.deserialize(input, TransactionArgument)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


@dataclass(frozen=True)
class TransactionArgument__U8(TransactionArgument):
    INDEX = 0  # type: int
    value: st.uint8


@dataclass(frozen=True)
class TransactionArgument__U64(TransactionArgument):
    INDEX = 1  # type: int
    value: st.uint64


@dataclass(frozen=True)
class TransactionArgument__U128(TransactionArgument):
    INDEX = 2  # type: int
    value: st.uint128


@dataclass(frozen=True)
class TransactionArgument__Address(TransactionArgument):
    INDEX = 3  # type: int
    value: "AccountAddress"


@dataclass(frozen=True)
class TransactionArgument__U8Vector(TransactionArgument):
    INDEX = 4  # type: int
    value: bytes


@dataclass(frozen=True)
class TransactionArgument__Bool(TransactionArgument):
    INDEX = 5  # type: int
    value: bool


TransactionArgument.VARIANTS = [
    TransactionArgument__U8,
    TransactionArgument__U64,
    TransactionArgument__U128,
    TransactionArgument__Address,
    TransactionArgument__U8Vector,
    TransactionArgument__Bool,
]


class TransactionAuthenticator:
    VARIANTS = []  # type: typing.Sequence[typing.Type[TransactionAuthenticator]]

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, TransactionAuthenticator)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'TransactionAuthenticator':
        v, buffer = bcs.deserialize(input, TransactionAuthenticator)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


@dataclass(frozen=True)
class TransactionAuthenticator__Ed25519(TransactionAuthenticator):
    INDEX = 0  # type: int
    public_key: "Ed25519PublicKey"
    signature: "Ed25519Signature"


@dataclass(frozen=True)
class TransactionAuthenticator__MultiEd25519(TransactionAuthenticator):
    INDEX = 1  # type: int
    public_key: "MultiEd25519PublicKey"
    signature: "MultiEd25519Signature"


TransactionAuthenticator.VARIANTS = [
    TransactionAuthenticator__Ed25519,
    TransactionAuthenticator__MultiEd25519,
]


class TransactionPayload:
    VARIANTS = []  # type: typing.Sequence[typing.Type[TransactionPayload]]

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, TransactionPayload)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'TransactionPayload':
        v, buffer = bcs.deserialize(input, TransactionPayload)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


@dataclass(frozen=True)
class TransactionPayload__Script(TransactionPayload):
    INDEX = 0  # type: int
    value: "Script"


@dataclass(frozen=True)
class TransactionPayload__Package(TransactionPayload):
    INDEX = 1  # type: int
    value: "Package"


@dataclass(frozen=True)
class TransactionPayload__ScriptFunction(TransactionPayload):
    INDEX = 2  # type: int
    value: "ScriptFunction"


TransactionPayload.VARIANTS = [
    TransactionPayload__Script,
    TransactionPayload__Package,
    TransactionPayload__ScriptFunction,
]


class TravelRuleMetadata:
    VARIANTS = []  # type: typing.Sequence[typing.Type[TravelRuleMetadata]]

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, TravelRuleMetadata)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'TravelRuleMetadata':
        v, buffer = bcs.deserialize(input, TravelRuleMetadata)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


@dataclass(frozen=True)
class TravelRuleMetadata__TravelRuleMetadataVersion0(TravelRuleMetadata):
    INDEX = 0  # type: int
    value: "TravelRuleMetadataV0"


TravelRuleMetadata.VARIANTS = [
    TravelRuleMetadata__TravelRuleMetadataVersion0,
]


@dataclass(frozen=True)
class TravelRuleMetadataV0:
    off_chain_reference_id: typing.Optional[str]

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, TravelRuleMetadataV0)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'TravelRuleMetadataV0':
        v, buffer = bcs.deserialize(input, TravelRuleMetadataV0)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


class TypeTag:
    VARIANTS = []  # type: typing.Sequence[typing.Type[TypeTag]]

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, TypeTag)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'TypeTag':
        v, buffer = bcs.deserialize(input, TypeTag)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


@dataclass(frozen=True)
class TypeTag__Bool(TypeTag):
    INDEX = 0  # type: int
    pass


@dataclass(frozen=True)
class TypeTag__U8(TypeTag):
    INDEX = 1  # type: int
    pass


@dataclass(frozen=True)
class TypeTag__U64(TypeTag):
    INDEX = 2  # type: int
    pass


@dataclass(frozen=True)
class TypeTag__U128(TypeTag):
    INDEX = 3  # type: int
    pass


@dataclass(frozen=True)
class TypeTag__Address(TypeTag):
    INDEX = 4  # type: int
    pass


@dataclass(frozen=True)
class TypeTag__Signer(TypeTag):
    INDEX = 5  # type: int
    pass


@dataclass(frozen=True)
class TypeTag__Vector(TypeTag):
    INDEX = 6  # type: int
    value: "TypeTag"


@dataclass(frozen=True)
class TypeTag__Struct(TypeTag):
    INDEX = 7  # type: int
    value: "StructTag"


TypeTag.VARIANTS = [
    TypeTag__Bool,
    TypeTag__U8,
    TypeTag__U64,
    TypeTag__U128,
    TypeTag__Address,
    TypeTag__Signer,
    TypeTag__Vector,
    TypeTag__Struct,
]


@dataclass(frozen=True)
class UnstructuredBytesMetadata:
    metadata: typing.Optional[bytes]

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, UnstructuredBytesMetadata)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'UnstructuredBytesMetadata':
        v, buffer = bcs.deserialize(input, UnstructuredBytesMetadata)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


@dataclass(frozen=True)
class VoteChangedEvent:
    proposal_id: st.uint64
    proposer: "AccountAddress"
    voter: "AccountAddress"
    agree: bool
    vote: st.uint128

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, VoteChangedEvent)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'VoteChangedEvent':
        v, buffer = bcs.deserialize(input, VoteChangedEvent)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


@dataclass(frozen=True)
class WithdrawCapabilityResource:
    account_address: "AccountAddress"

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, WithdrawCapabilityResource)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'WithdrawCapabilityResource':
        v, buffer = bcs.deserialize(input, WithdrawCapabilityResource)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


@dataclass(frozen=True)
class WithdrawEvent:
    amount: st.uint128
    token_code: "TokenCode"
    metadata: typing.Sequence[st.uint8]

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, WithdrawEvent)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'WithdrawEvent':
        v, buffer = bcs.deserialize(input, WithdrawEvent)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


class WriteOp:
    VARIANTS = []  # type: typing.Sequence[typing.Type[WriteOp]]

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, WriteOp)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'WriteOp':
        v, buffer = bcs.deserialize(input, WriteOp)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


@dataclass(frozen=True)
class WriteOp__Deletion(WriteOp):
    INDEX = 0  # type: int
    pass


@dataclass(frozen=True)
class WriteOp__Value(WriteOp):
    INDEX = 1  # type: int
    value: bytes


WriteOp.VARIANTS = [
    WriteOp__Deletion,
    WriteOp__Value,
]


@dataclass(frozen=True)
class WriteSet:
    value: "WriteSetMut"

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, WriteSet)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'WriteSet':
        v, buffer = bcs.deserialize(input, WriteSet)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


@dataclass(frozen=True)
class WriteSetMut:
    write_set: typing.Sequence[typing.Tuple["AccessPath", "WriteOp"]]

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, WriteSetMut)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'WriteSetMut':
        v, buffer = bcs.deserialize(input, WriteSetMut)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


class WriteSetPayload:
    VARIANTS = []  # type: typing.Sequence[typing.Type[WriteSetPayload]]

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, WriteSetPayload)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'WriteSetPayload':
        v, buffer = bcs.deserialize(input, WriteSetPayload)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


@dataclass(frozen=True)
class WriteSetPayload__Direct(WriteSetPayload):
    INDEX = 0  # type: int
    value: "ChangeSet"


@dataclass(frozen=True)
class WriteSetPayload__Script(WriteSetPayload):
    INDEX = 1  # type: int
    execute_as: "AccountAddress"
    script: "Script"


WriteSetPayload.VARIANTS = [
    WriteSetPayload__Direct,
    WriteSetPayload__Script,
]


@dataclass(frozen=True)
class SigningMessage:
    value: bytes

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, SigningMessage)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'SigningMessage':
        v, buffer = bcs.deserialize(input, SigningMessage)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


@dataclass(frozen=True)
class SignedMessage:
    account: AccountAddress
    signing_message: SigningMessage
    authenticator: TransactionAuthenticator
    chain_id: ChainId

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, SignedMessage)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'SignedMessage':
        v, buffer = bcs.deserialize(input, SignedMessage)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v

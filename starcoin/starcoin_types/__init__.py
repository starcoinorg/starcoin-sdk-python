# pyre-strict
from dataclasses import dataclass
import typing
from starcoin import serde_types as st
from starcoin import bcs


@dataclass(frozen=True)
class AccessPath:
    value: typing.Tuple["AccountAddress", "DataPath"]

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
    authentication_key: typing.Sequence[st.uint8]
    withdrawal_capability: typing.Optional["WithdrawCapabilityResource"]
    key_rotation_capability: typing.Optional["KeyRotationCapabilityResource"]
    withdraw_events: "EventHandle"
    deposit_events: "EventHandle"
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
class ArgumentABI:
    name: str
    type_tag: "TypeTag"

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, ArgumentABI)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'ArgumentABI':
        v, buffer = bcs.deserialize(input, ArgumentABI)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


@dataclass(frozen=True)
class AuthenticationKey:
    value: bytes

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, AuthenticationKey)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'AuthenticationKey':
        v, buffer = bcs.deserialize(input, AuthenticationKey)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


@dataclass(frozen=True)
class BlockMetadata:
    parent_hash: "HashValue"
    timestamp: st.uint64
    author: "AccountAddress"
    author_auth_key: typing.Optional["AuthenticationKey"]
    uncles: st.uint64
    number: st.uint64
    chain_id: "ChainId"
    parent_gas_used: st.uint64

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, BlockMetadata)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'BlockMetadata':
        v, buffer = bcs.deserialize(input, BlockMetadata)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


@dataclass(frozen=True)
class ChainId:
    id: st.uint8

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, ChainId)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'ChainId':
        v, buffer = bcs.deserialize(input, ChainId)
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


class DataType:
    VARIANTS = []  # type: typing.Sequence[typing.Type[DataType]]

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, DataType)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'DataType':
        v, buffer = bcs.deserialize(input, DataType)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


@dataclass(frozen=True)
class DataType__CODE(DataType):
    INDEX = 0  # type: int
    pass


@dataclass(frozen=True)
class DataType__RESOURCE(DataType):
    INDEX = 1  # type: int
    pass


DataType.VARIANTS = [
    DataType__CODE,
    DataType__RESOURCE,
]


@dataclass(frozen=True)
class Ed25519PrivateKey:
    value: bytes

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, Ed25519PrivateKey)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'Ed25519PrivateKey':
        v, buffer = bcs.deserialize(input, Ed25519PrivateKey)
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
class MultiEd25519PrivateKey:
    value: bytes

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, MultiEd25519PrivateKey)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'MultiEd25519PrivateKey':
        v, buffer = bcs.deserialize(input, MultiEd25519PrivateKey)
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
class Package:
    package_address: "AccountAddress"
    modules: typing.Sequence["Module"]
    init_script: typing.Optional["ScriptFunction"]

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, Package)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'Package':
        v, buffer = bcs.deserialize(input, Package)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


@dataclass(frozen=True)
class RawUserTransaction:
    sender: "AccountAddress"
    sequence_number: st.uint64
    payload: "TransactionPayload"
    max_gas_amount: st.uint64
    gas_unit_price: st.uint64
    gas_token_code: str
    expiration_timestamp_secs: st.uint64
    chain_id: "ChainId"

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, RawUserTransaction)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'RawUserTransaction':
        v, buffer = bcs.deserialize(input, RawUserTransaction)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


@dataclass(frozen=True)
class Script:
    code: bytes
    ty_args: typing.Sequence["TypeTag"]
    args: typing.Sequence[bytes]

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, Script)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'Script':
        v, buffer = bcs.deserialize(input, Script)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


class ScriptABI:
    VARIANTS = []  # type: typing.Sequence[typing.Type[ScriptABI]]

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, ScriptABI)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'ScriptABI':
        v, buffer = bcs.deserialize(input, ScriptABI)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


@dataclass(frozen=True)
class ScriptABI__TransactionScript(ScriptABI):
    INDEX = 0  # type: int
    value: "TransactionScriptABI"


@dataclass(frozen=True)
class ScriptABI__ScriptFunction(ScriptABI):
    INDEX = 1  # type: int
    value: "ScriptFunctionABI"


ScriptABI.VARIANTS = [
    ScriptABI__TransactionScript,
    ScriptABI__ScriptFunction,
]


@dataclass(frozen=True)
class ScriptFunction:
    module: "ModuleId"
    function: "Identifier"
    ty_args: typing.Sequence["TypeTag"]
    args: typing.Sequence[bytes]

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, ScriptFunction)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'ScriptFunction':
        v, buffer = bcs.deserialize(input, ScriptFunction)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


@dataclass(frozen=True)
class ScriptFunctionABI:
    name: str
    module_name: "ModuleId"
    doc: str
    ty_args: typing.Sequence["TypeArgumentABI"]
    args: typing.Sequence["ArgumentABI"]

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, ScriptFunctionABI)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'ScriptFunctionABI':
        v, buffer = bcs.deserialize(input, ScriptFunctionABI)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


@dataclass(frozen=True)
class SignedMessage:
    account: "AccountAddress"
    message: "SigningMessage"
    authenticator: "TransactionAuthenticator"
    chain_id: "ChainId"

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, SignedMessage)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'SignedMessage':
        v, buffer = bcs.deserialize(input, SignedMessage)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


@dataclass(frozen=True)
class SignedUserTransaction:
    raw_txn: "RawUserTransaction"
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
class SigningMessage:
    value: typing.Sequence[st.uint8]

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, SigningMessage)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'SigningMessage':
        v, buffer = bcs.deserialize(input, SigningMessage)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


@dataclass(frozen=True)
class StructTag:
    address: "AccountAddress"
    module: "Identifier"
    name: "Identifier"
    type_args: typing.Sequence["TypeTag"]

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, StructTag)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'StructTag':
        v, buffer = bcs.deserialize(input, StructTag)
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


@dataclass(frozen=True)
class TransactionScriptABI:
    name: str
    doc: str
    code: bytes
    ty_args: typing.Sequence["TypeArgumentABI"]
    args: typing.Sequence["ArgumentABI"]

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, TransactionScriptABI)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'TransactionScriptABI':
        v, buffer = bcs.deserialize(input, TransactionScriptABI)
        if buffer:
            raise st.DeserializationError("Some input bytes were not read")
        return v


@dataclass(frozen=True)
class TypeArgumentABI:
    name: str

    def bcs_serialize(self) -> bytes:
        return bcs.serialize(self, TypeArgumentABI)

    @staticmethod
    def bcs_deserialize(input: bytes) -> 'TypeArgumentABI':
        v, buffer = bcs.deserialize(input, TypeArgumentABI)
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
class TypeTag__bool(TypeTag):
    INDEX = 0  # type: int
    pass


@dataclass(frozen=True)
class TypeTag__u8(TypeTag):
    INDEX = 1  # type: int
    pass


@dataclass(frozen=True)
class TypeTag__u64(TypeTag):
    INDEX = 2  # type: int
    pass


@dataclass(frozen=True)
class TypeTag__u128(TypeTag):
    INDEX = 3  # type: int
    pass


@dataclass(frozen=True)
class TypeTag__address(TypeTag):
    INDEX = 4  # type: int
    pass


@dataclass(frozen=True)
class TypeTag__signer(TypeTag):
    INDEX = 5  # type: int
    pass


@dataclass(frozen=True)
class TypeTag__vector(TypeTag):
    INDEX = 6  # type: int
    value: "TypeTag"


@dataclass(frozen=True)
class TypeTag__struct(TypeTag):
    INDEX = 7  # type: int
    value: "StructTag"


TypeTag.VARIANTS = [
    TypeTag__bool,
    TypeTag__u8,
    TypeTag__u64,
    TypeTag__u128,
    TypeTag__address,
    TypeTag__signer,
    TypeTag__vector,
    TypeTag__struct,
]


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

# pyre-strict
from starcoin import bcs
from starcoin.starcoin_types import (Script, ScriptFunction, TransactionPayload, TransactionPayload__ScriptFunction, Identifier, ModuleId, TypeTag, AccountAddress, TransactionArgument,
                                     TransactionArgument__Bool, TransactionArgument__U8, TransactionArgument__U64, TransactionArgument__U128, TransactionArgument__Address, TransactionArgument__U8Vector)
from dataclasses import dataclass
import typing
from starcoin import serde_types as st
from starcoin import starcoin_types


class ScriptCall:
    """Structured representation of a call into a known Move script.
    """
    pass


class ScriptFunctionCall:
    """Structured representation of a call into a known Move script function.
    """
    pass


@dataclass(frozen=True)
class ScriptFunctionCall__AcceptToken(ScriptFunctionCall):
    """.
    """
    token_type: starcoin_types.TypeTag


@dataclass(frozen=True)
class ScriptFunctionCall__CancelUpgradePlan(ScriptFunctionCall):
    """.
    """
    pass


@dataclass(frozen=True)
class ScriptFunctionCall__CastVote(ScriptFunctionCall):
    """.
    """
    token: starcoin_types.TypeTag
    action_t: starcoin_types.TypeTag
    proposer_address: starcoin_types.AccountAddress
    proposal_id: st.uint64
    agree: bool
    votes: st.uint128


@dataclass(frozen=True)
class ScriptFunctionCall__ConvertTwoPhaseUpgradeToTwoPhaseUpgradeV2(ScriptFunctionCall):
    """.
    """
    package_address: starcoin_types.AccountAddress


@dataclass(frozen=True)
class ScriptFunctionCall__CreateAccountWithInitialAmount(ScriptFunctionCall):
    """.
    """
    token_type: starcoin_types.TypeTag
    fresh_address: starcoin_types.AccountAddress
    auth_key: bytes
    initial_amount: st.uint128


@dataclass(frozen=True)
class ScriptFunctionCall__DestroyTerminatedProposal(ScriptFunctionCall):
    """remove terminated proposal from proposer.
    """
    token_t: starcoin_types.TypeTag
    action_t: starcoin_types.TypeTag
    proposer_address: starcoin_types.AccountAddress
    proposal_id: st.uint64


@dataclass(frozen=True)
class ScriptFunctionCall__EmptyScript(ScriptFunctionCall):
    """.
    """
    pass


@dataclass(frozen=True)
class ScriptFunctionCall__Execute(ScriptFunctionCall):
    """Once the proposal is agreed, anyone can call the method to make the proposal happen.
    """
    token_t: starcoin_types.TypeTag
    proposer_address: starcoin_types.AccountAddress
    proposal_id: st.uint64


@dataclass(frozen=True)
class ScriptFunctionCall__ExecuteOnChainConfigProposal(ScriptFunctionCall):
    """.
    """
    config_t: starcoin_types.TypeTag
    proposal_id: st.uint64


@dataclass(frozen=True)
class ScriptFunctionCall__Initialize(ScriptFunctionCall):
    """.
    """
    stdlib_version: st.uint64
    reward_delay: st.uint64
    pre_mine_amount: st.uint128
    time_mint_amount: st.uint128
    time_mint_period: st.uint64
    parent_hash: bytes
    association_auth_key: bytes
    genesis_auth_key: bytes
    chain_id: st.uint8
    genesis_timestamp: st.uint64
    uncle_rate_target: st.uint64
    epoch_block_count: st.uint64
    base_block_time_target: st.uint64
    base_block_difficulty_window: st.uint64
    base_reward_per_block: st.uint128
    base_reward_per_uncle_percent: st.uint64
    min_block_time_target: st.uint64
    max_block_time_target: st.uint64
    base_max_uncles_per_block: st.uint64
    base_block_gas_limit: st.uint64
    strategy: st.uint8
    script_allowed: bool
    module_publishing_allowed: bool
    instruction_schedule: bytes
    native_schedule: bytes
    global_memory_per_byte_cost: st.uint64
    global_memory_per_byte_write_cost: st.uint64
    min_transaction_gas_units: st.uint64
    large_transaction_cutoff: st.uint64
    instrinsic_gas_per_byte: st.uint64
    maximum_number_of_gas_units: st.uint64
    min_price_per_gas_unit: st.uint64
    max_price_per_gas_unit: st.uint64
    max_transaction_size_in_bytes: st.uint64
    gas_unit_scaling_factor: st.uint64
    default_account_size: st.uint64
    voting_delay: st.uint64
    voting_period: st.uint64
    voting_quorum_rate: st.uint8
    min_action_delay: st.uint64
    transaction_timeout: st.uint64


@dataclass(frozen=True)
class ScriptFunctionCall__MintAndSplitByLinearKey(ScriptFunctionCall):
    """.
    """
    token: starcoin_types.TypeTag
    for_address: starcoin_types.AccountAddress
    amount: st.uint128
    lock_period: st.uint64


@dataclass(frozen=True)
class ScriptFunctionCall__MintTokenByFixedKey(ScriptFunctionCall):
    """.
    """
    token: starcoin_types.TypeTag


@dataclass(frozen=True)
class ScriptFunctionCall__MintTokenByLinearKey(ScriptFunctionCall):
    """.
    """
    token: starcoin_types.TypeTag


@dataclass(frozen=True)
class ScriptFunctionCall__PeerToPeer(ScriptFunctionCall):
    """.
    """
    token_type: starcoin_types.TypeTag
    payee: starcoin_types.AccountAddress
    payee_auth_key: bytes
    amount: st.uint128


@dataclass(frozen=True)
class ScriptFunctionCall__PeerToPeerBatch(ScriptFunctionCall):
    """.
    """
    token_type: starcoin_types.TypeTag
    payeees: bytes
    payee_auth_keys: bytes
    amount: st.uint128


@dataclass(frozen=True)
class ScriptFunctionCall__PeerToPeerWithMetadata(ScriptFunctionCall):
    """.
    """
    token_type: starcoin_types.TypeTag
    payee: starcoin_types.AccountAddress
    payee_auth_key: bytes
    amount: st.uint128
    metadata: bytes


@dataclass(frozen=True)
class ScriptFunctionCall__Propose(ScriptFunctionCall):
    """Entrypoint for the proposal.
    """
    token_t: starcoin_types.TypeTag
    voting_delay: st.uint64
    voting_period: st.uint64
    voting_quorum_rate: st.uint8
    min_action_delay: st.uint64
    exec_delay: st.uint64


@dataclass(frozen=True)
class ScriptFunctionCall__ProposeModuleUpgrade(ScriptFunctionCall):
    """.
    """
    token: starcoin_types.TypeTag
    _module_address: starcoin_types.AccountAddress
    _package_hash: bytes
    _version: st.uint64
    _exec_delay: st.uint64


@dataclass(frozen=True)
class ScriptFunctionCall__ProposeModuleUpgradeV2(ScriptFunctionCall):
    """.
    """
    token: starcoin_types.TypeTag
    module_address: starcoin_types.AccountAddress
    package_hash: bytes
    version: st.uint64
    exec_delay: st.uint64
    enforced: bool


@dataclass(frozen=True)
class ScriptFunctionCall__ProposeUpdateConsensusConfig(ScriptFunctionCall):
    """.
    """
    uncle_rate_target: st.uint64
    base_block_time_target: st.uint64
    base_reward_per_block: st.uint128
    base_reward_per_uncle_percent: st.uint64
    epoch_block_count: st.uint64
    base_block_difficulty_window: st.uint64
    min_block_time_target: st.uint64
    max_block_time_target: st.uint64
    base_max_uncles_per_block: st.uint64
    base_block_gas_limit: st.uint64
    strategy: st.uint8
    exec_delay: st.uint64


@dataclass(frozen=True)
class ScriptFunctionCall__ProposeUpdateRewardConfig(ScriptFunctionCall):
    """.
    """
    reward_delay: st.uint64
    exec_delay: st.uint64


@dataclass(frozen=True)
class ScriptFunctionCall__ProposeUpdateTxnPublishOption(ScriptFunctionCall):
    """.
    """
    script_allowed: bool
    module_publishing_allowed: bool
    exec_delay: st.uint64


@dataclass(frozen=True)
class ScriptFunctionCall__ProposeUpdateTxnTimeoutConfig(ScriptFunctionCall):
    """.
    """
    duration_seconds: st.uint64
    exec_delay: st.uint64


@dataclass(frozen=True)
class ScriptFunctionCall__ProposeUpdateVmConfig(ScriptFunctionCall):
    """.
    """
    instruction_schedule: bytes
    native_schedule: bytes
    global_memory_per_byte_cost: st.uint64
    global_memory_per_byte_write_cost: st.uint64
    min_transaction_gas_units: st.uint64
    large_transaction_cutoff: st.uint64
    instrinsic_gas_per_byte: st.uint64
    maximum_number_of_gas_units: st.uint64
    min_price_per_gas_unit: st.uint64
    max_price_per_gas_unit: st.uint64
    max_transaction_size_in_bytes: st.uint64
    gas_unit_scaling_factor: st.uint64
    default_account_size: st.uint64
    exec_delay: st.uint64


@dataclass(frozen=True)
class ScriptFunctionCall__QueueProposalAction(ScriptFunctionCall):
    """queue agreed proposal to execute.
    """
    token_t: starcoin_types.TypeTag
    action_t: starcoin_types.TypeTag
    proposer_address: starcoin_types.AccountAddress
    proposal_id: st.uint64


@dataclass(frozen=True)
class ScriptFunctionCall__RevokeVote(ScriptFunctionCall):
    """.
    """
    token: starcoin_types.TypeTag
    action: starcoin_types.TypeTag
    proposer_address: starcoin_types.AccountAddress
    proposal_id: st.uint64


@dataclass(frozen=True)
class ScriptFunctionCall__RotateAuthenticationKey(ScriptFunctionCall):
    """.
    """
    new_key: bytes


@dataclass(frozen=True)
class ScriptFunctionCall__SplitFixedKey(ScriptFunctionCall):
    """.
    """
    token: starcoin_types.TypeTag
    for_address: starcoin_types.AccountAddress
    amount: st.uint128
    lock_period: st.uint64


@dataclass(frozen=True)
class ScriptFunctionCall__SubmitModuleUpgradePlan(ScriptFunctionCall):
    """.
    """
    token: starcoin_types.TypeTag
    proposer_address: starcoin_types.AccountAddress
    proposal_id: st.uint64


@dataclass(frozen=True)
class ScriptFunctionCall__TakeOffer(ScriptFunctionCall):
    """.
    """
    offered: starcoin_types.TypeTag
    offer_address: starcoin_types.AccountAddress


@dataclass(frozen=True)
class ScriptFunctionCall__UnstakeVote(ScriptFunctionCall):
    """.
    """
    token: starcoin_types.TypeTag
    action: starcoin_types.TypeTag
    proposer_address: starcoin_types.AccountAddress
    proposal_id: st.uint64


@dataclass(frozen=True)
class ScriptFunctionCall__UpdateModuleUpgradeStrategy(ScriptFunctionCall):
    """.
    """
    strategy: st.uint8


def encode_script(call: ScriptCall) -> Script:
    """Build a Diem `Script` from a structured object `ScriptCall`.
    """
    helper = TRANSACTION_SCRIPT_ENCODER_MAP[call.__class__]
    return helper(call)


def encode_script_function(call: ScriptFunctionCall) -> TransactionPayload:
    """Build a Diem `ScriptFunction` `TransactionPayload` from a structured object `ScriptFunctionCall`.
    """
    helper = SCRIPT_FUNCTION_ENCODER_MAP[call.__class__]
    return helper(call)


def decode_script(script: Script) -> ScriptCall:
    """Try to recognize a Diem `Script` and convert it into a structured object `ScriptCall`.
    """
    helper = TRANSACTION_SCRIPT_DECODER_MAP.get(script.code)
    if helper is None:
        raise ValueError("Unknown script bytecode")
    return helper(script)


def decode_script_function_payload(payload: TransactionPayload) -> ScriptFunctionCall:
    """Try to recognize a Diem `TransactionPayload` and convert it into a structured object `ScriptFunctionCall`.
    """
    if not isinstance(payload, TransactionPayload__ScriptFunction):
        raise ValueError("Unexpected transaction payload")
    script = payload.value
    helper = SCRIPT_FUNCTION_DECODER_MAP.get(
        script.module.name.value + script.function.value)
    if helper is None:
        raise ValueError("Unknown script bytecode")
    return helper(script)


def encode_accept_token_script_function(token_type: TypeTag) -> TransactionPayload:
    """.
    """
    return TransactionPayload__ScriptFunction(
        value=ScriptFunction(
            module=ModuleId(address=AccountAddress.from_hex(
                "00000000000000000000000000000001"), name=Identifier("Account")),
            function=Identifier("accept_token"),
            ty_args=[token_type],
            args=[],
        )
    )


def encode_cancel_upgrade_plan_script_function() -> TransactionPayload:
    """.
    """
    return TransactionPayload__ScriptFunction(
        value=ScriptFunction(
            module=ModuleId(address=AccountAddress.from_hex(
                "00000000000000000000000000000001"), name=Identifier("ModuleUpgradeScripts")),
            function=Identifier("cancel_upgrade_plan"),
            ty_args=[],
            args=[],
        )
    )


def encode_cast_vote_script_function(token: TypeTag, action_t: TypeTag, proposer_address: AccountAddress, proposal_id: st.uint64, agree: bool, votes: st.uint128) -> TransactionPayload:
    """.
    """
    return TransactionPayload__ScriptFunction(
        value=ScriptFunction(
            module=ModuleId(address=AccountAddress.from_hex(
                "00000000000000000000000000000001"), name=Identifier("DaoVoteScripts")),
            function=Identifier("cast_vote"),
            ty_args=[token, action_t],
            args=[bcs.serialize(proposer_address, starcoin_types.AccountAddress), bcs.serialize(
                proposal_id, st.uint64), bcs.serialize(agree, st.bool), bcs.serialize(votes, st.uint128)],
        )
    )


def encode_convert_TwoPhaseUpgrade_to_TwoPhaseUpgradeV2_script_function(package_address: AccountAddress) -> TransactionPayload:
    """.
    """
    return TransactionPayload__ScriptFunction(
        value=ScriptFunction(
            module=ModuleId(address=AccountAddress.from_hex(
                "00000000000000000000000000000001"), name=Identifier("PackageTxnManager")),
            function=Identifier(
                "convert_TwoPhaseUpgrade_to_TwoPhaseUpgradeV2"),
            ty_args=[],
            args=[bcs.serialize(
                package_address, starcoin_types.AccountAddress)],
        )
    )


def encode_create_account_with_initial_amount_script_function(token_type: TypeTag, fresh_address: AccountAddress, auth_key: bytes, initial_amount: st.uint128) -> TransactionPayload:
    """.
    """
    return TransactionPayload__ScriptFunction(
        value=ScriptFunction(
            module=ModuleId(address=AccountAddress.from_hex(
                "00000000000000000000000000000001"), name=Identifier("Account")),
            function=Identifier("create_account_with_initial_amount"),
            ty_args=[token_type],
            args=[bcs.serialize(fresh_address, starcoin_types.AccountAddress), bcs.serialize(
                auth_key, bytes), bcs.serialize(initial_amount, st.uint128)],
        )
    )


def encode_destroy_terminated_proposal_script_function(token_t: TypeTag, action_t: TypeTag, proposer_address: AccountAddress, proposal_id: st.uint64) -> TransactionPayload:
    """remove terminated proposal from proposer.
    """
    return TransactionPayload__ScriptFunction(
        value=ScriptFunction(
            module=ModuleId(address=AccountAddress.from_hex(
                "00000000000000000000000000000001"), name=Identifier("Dao")),
            function=Identifier("destroy_terminated_proposal"),
            ty_args=[token_t, action_t],
            args=[bcs.serialize(proposer_address, starcoin_types.AccountAddress), bcs.serialize(
                proposal_id, st.uint64)],
        )
    )


def encode_empty_script_script_function() -> TransactionPayload:
    """.
    """
    return TransactionPayload__ScriptFunction(
        value=ScriptFunction(
            module=ModuleId(address=AccountAddress.from_hex(
                "00000000000000000000000000000001"), name=Identifier("EmptyScripts")),
            function=Identifier("empty_script"),
            ty_args=[],
            args=[],
        )
    )


def encode_execute_script_function(token_t: TypeTag, proposer_address: AccountAddress, proposal_id: st.uint64) -> TransactionPayload:
    """Once the proposal is agreed, anyone can call the method to make the proposal happen.
    """
    return TransactionPayload__ScriptFunction(
        value=ScriptFunction(
            module=ModuleId(address=AccountAddress.from_hex(
                "00000000000000000000000000000001"), name=Identifier("ModifyDaoConfigProposal")),
            function=Identifier("execute"),
            ty_args=[token_t],
            args=[bcs.serialize(proposer_address, starcoin_types.AccountAddress), bcs.serialize(
                proposal_id, st.uint64)],
        )
    )


def encode_execute_on_chain_config_proposal_script_function(config_t: TypeTag, proposal_id: st.uint64) -> TransactionPayload:
    """.
    """
    return TransactionPayload__ScriptFunction(
        value=ScriptFunction(
            module=ModuleId(address=AccountAddress.from_hex(
                "00000000000000000000000000000001"), name=Identifier("OnChainConfigScripts")),
            function=Identifier("execute_on_chain_config_proposal"),
            ty_args=[config_t],
            args=[bcs.serialize(proposal_id, st.uint64)],
        )
    )


def encode_initialize_script_function(stdlib_version: st.uint64, reward_delay: st.uint64, pre_mine_amount: st.uint128, time_mint_amount: st.uint128, time_mint_period: st.uint64, parent_hash: bytes, association_auth_key: bytes, genesis_auth_key: bytes, chain_id: st.uint8, genesis_timestamp: st.uint64, uncle_rate_target: st.uint64, epoch_block_count: st.uint64, base_block_time_target: st.uint64, base_block_difficulty_window: st.uint64, base_reward_per_block: st.uint128, base_reward_per_uncle_percent: st.uint64, min_block_time_target: st.uint64, max_block_time_target: st.uint64, base_max_uncles_per_block: st.uint64, base_block_gas_limit: st.uint64, strategy: st.uint8, script_allowed: bool, module_publishing_allowed: bool, instruction_schedule: bytes, native_schedule: bytes, global_memory_per_byte_cost: st.uint64, global_memory_per_byte_write_cost: st.uint64, min_transaction_gas_units: st.uint64, large_transaction_cutoff: st.uint64, instrinsic_gas_per_byte: st.uint64, maximum_number_of_gas_units: st.uint64, min_price_per_gas_unit: st.uint64, max_price_per_gas_unit: st.uint64, max_transaction_size_in_bytes: st.uint64, gas_unit_scaling_factor: st.uint64, default_account_size: st.uint64, voting_delay: st.uint64, voting_period: st.uint64, voting_quorum_rate: st.uint8, min_action_delay: st.uint64, transaction_timeout: st.uint64) -> TransactionPayload:
    """.
    """
    return TransactionPayload__ScriptFunction(
        value=ScriptFunction(
            module=ModuleId(address=AccountAddress.from_hex(
                "00000000000000000000000000000001"), name=Identifier("Genesis")),
            function=Identifier("initialize"),
            ty_args=[],
            args=[bcs.serialize(stdlib_version, st.uint64), bcs.serialize(reward_delay, st.uint64), bcs.serialize(pre_mine_amount, st.uint128), bcs.serialize(time_mint_amount, st.uint128), bcs.serialize(time_mint_period, st.uint64), bcs.serialize(parent_hash, bytes), bcs.serialize(association_auth_key, bytes), bcs.serialize(genesis_auth_key, bytes), bcs.serialize(chain_id, st.uint8), bcs.serialize(genesis_timestamp, st.uint64), bcs.serialize(uncle_rate_target, st.uint64), bcs.serialize(epoch_block_count, st.uint64), bcs.serialize(base_block_time_target, st.uint64), bcs.serialize(base_block_difficulty_window, st.uint64), bcs.serialize(base_reward_per_block, st.uint128), bcs.serialize(base_reward_per_uncle_percent, st.uint64), bcs.serialize(min_block_time_target, st.uint64), bcs.serialize(max_block_time_target, st.uint64), bcs.serialize(base_max_uncles_per_block, st.uint64), bcs.serialize(base_block_gas_limit, st.uint64), bcs.serialize(strategy, st.uint8), bcs.serialize(
                script_allowed, st.bool), bcs.serialize(module_publishing_allowed, st.bool), bcs.serialize(instruction_schedule, bytes), bcs.serialize(native_schedule, bytes), bcs.serialize(global_memory_per_byte_cost, st.uint64), bcs.serialize(global_memory_per_byte_write_cost, st.uint64), bcs.serialize(min_transaction_gas_units, st.uint64), bcs.serialize(large_transaction_cutoff, st.uint64), bcs.serialize(instrinsic_gas_per_byte, st.uint64), bcs.serialize(maximum_number_of_gas_units, st.uint64), bcs.serialize(min_price_per_gas_unit, st.uint64), bcs.serialize(max_price_per_gas_unit, st.uint64), bcs.serialize(max_transaction_size_in_bytes, st.uint64), bcs.serialize(gas_unit_scaling_factor, st.uint64), bcs.serialize(default_account_size, st.uint64), bcs.serialize(voting_delay, st.uint64), bcs.serialize(voting_period, st.uint64), bcs.serialize(voting_quorum_rate, st.uint8), bcs.serialize(min_action_delay, st.uint64), bcs.serialize(transaction_timeout, st.uint64)],
        )
    )


def encode_mint_and_split_by_linear_key_script_function(token: TypeTag, for_address: AccountAddress, amount: st.uint128, lock_period: st.uint64) -> TransactionPayload:
    """.
    """
    return TransactionPayload__ScriptFunction(
        value=ScriptFunction(
            module=ModuleId(address=AccountAddress.from_hex(
                "00000000000000000000000000000001"), name=Identifier("MintScripts")),
            function=Identifier("mint_and_split_by_linear_key"),
            ty_args=[token],
            args=[bcs.serialize(for_address, starcoin_types.AccountAddress), bcs.serialize(
                amount, st.uint128), bcs.serialize(lock_period, st.uint64)],
        )
    )


def encode_mint_token_by_fixed_key_script_function(token: TypeTag) -> TransactionPayload:
    """.
    """
    return TransactionPayload__ScriptFunction(
        value=ScriptFunction(
            module=ModuleId(address=AccountAddress.from_hex(
                "00000000000000000000000000000001"), name=Identifier("MintScripts")),
            function=Identifier("mint_token_by_fixed_key"),
            ty_args=[token],
            args=[],
        )
    )


def encode_mint_token_by_linear_key_script_function(token: TypeTag) -> TransactionPayload:
    """.
    """
    return TransactionPayload__ScriptFunction(
        value=ScriptFunction(
            module=ModuleId(address=AccountAddress.from_hex(
                "00000000000000000000000000000001"), name=Identifier("MintScripts")),
            function=Identifier("mint_token_by_linear_key"),
            ty_args=[token],
            args=[],
        )
    )


def encode_peer_to_peer_script_function(token_type: TypeTag, payee: AccountAddress, payee_auth_key: bytes, amount: st.uint128) -> TransactionPayload:
    """.
    """
    return TransactionPayload__ScriptFunction(
        value=ScriptFunction(
            module=ModuleId(address=AccountAddress.from_hex(
                "00000000000000000000000000000001"), name=Identifier("TransferScripts")),
            function=Identifier("peer_to_peer"),
            ty_args=[token_type],
            args=[bcs.serialize(payee, starcoin_types.AccountAddress), bcs.serialize(
                payee_auth_key, bytes), bcs.serialize(amount, st.uint128)],
        )
    )


def encode_peer_to_peer_batch_script_function(token_type: TypeTag, payeees: bytes, payee_auth_keys: bytes, amount: st.uint128) -> TransactionPayload:
    """.
    """
    return TransactionPayload__ScriptFunction(
        value=ScriptFunction(
            module=ModuleId(address=AccountAddress.from_hex(
                "00000000000000000000000000000001"), name=Identifier("TransferScripts")),
            function=Identifier("peer_to_peer_batch"),
            ty_args=[token_type],
            args=[bcs.serialize(payeees, bytes), bcs.serialize(
                payee_auth_keys, bytes), bcs.serialize(amount, st.uint128)],
        )
    )


def encode_peer_to_peer_with_metadata_script_function(token_type: TypeTag, payee: AccountAddress, payee_auth_key: bytes, amount: st.uint128, metadata: bytes) -> TransactionPayload:
    """.
    """
    return TransactionPayload__ScriptFunction(
        value=ScriptFunction(
            module=ModuleId(address=AccountAddress.from_hex(
                "00000000000000000000000000000001"), name=Identifier("TransferScripts")),
            function=Identifier("peer_to_peer_with_metadata"),
            ty_args=[token_type],
            args=[bcs.serialize(payee, starcoin_types.AccountAddress), bcs.serialize(
                payee_auth_key, bytes), bcs.serialize(amount, st.uint128), bcs.serialize(metadata, bytes)],
        )
    )


def encode_propose_script_function(token_t: TypeTag, voting_delay: st.uint64, voting_period: st.uint64, voting_quorum_rate: st.uint8, min_action_delay: st.uint64, exec_delay: st.uint64) -> TransactionPayload:
    """Entrypoint for the proposal.
    """
    return TransactionPayload__ScriptFunction(
        value=ScriptFunction(
            module=ModuleId(address=AccountAddress.from_hex(
                "00000000000000000000000000000001"), name=Identifier("ModifyDaoConfigProposal")),
            function=Identifier("propose"),
            ty_args=[token_t],
            args=[bcs.serialize(voting_delay, st.uint64), bcs.serialize(voting_period, st.uint64), bcs.serialize(
                voting_quorum_rate, st.uint8), bcs.serialize(min_action_delay, st.uint64), bcs.serialize(exec_delay, st.uint64)],
        )
    )


def encode_propose_module_upgrade_script_function(token: TypeTag, _module_address: AccountAddress, _package_hash: bytes, _version: st.uint64, _exec_delay: st.uint64) -> TransactionPayload:
    """.
    """
    return TransactionPayload__ScriptFunction(
        value=ScriptFunction(
            module=ModuleId(address=AccountAddress.from_hex(
                "00000000000000000000000000000001"), name=Identifier("ModuleUpgradeScripts")),
            function=Identifier("propose_module_upgrade"),
            ty_args=[token],
            args=[bcs.serialize(_module_address, starcoin_types.AccountAddress), bcs.serialize(
                _package_hash, bytes), bcs.serialize(_version, st.uint64), bcs.serialize(_exec_delay, st.uint64)],
        )
    )


def encode_propose_module_upgrade_v2_script_function(token: TypeTag, module_address: AccountAddress, package_hash: bytes, version: st.uint64, exec_delay: st.uint64, enforced: bool) -> TransactionPayload:
    """.
    """
    return TransactionPayload__ScriptFunction(
        value=ScriptFunction(
            module=ModuleId(address=AccountAddress.from_hex(
                "00000000000000000000000000000001"), name=Identifier("ModuleUpgradeScripts")),
            function=Identifier("propose_module_upgrade_v2"),
            ty_args=[token],
            args=[bcs.serialize(module_address, starcoin_types.AccountAddress), bcs.serialize(package_hash, bytes), bcs.serialize(
                version, st.uint64), bcs.serialize(exec_delay, st.uint64), bcs.serialize(enforced, st.bool)],
        )
    )


def encode_propose_update_consensus_config_script_function(uncle_rate_target: st.uint64, base_block_time_target: st.uint64, base_reward_per_block: st.uint128, base_reward_per_uncle_percent: st.uint64, epoch_block_count: st.uint64, base_block_difficulty_window: st.uint64, min_block_time_target: st.uint64, max_block_time_target: st.uint64, base_max_uncles_per_block: st.uint64, base_block_gas_limit: st.uint64, strategy: st.uint8, exec_delay: st.uint64) -> TransactionPayload:
    """.
    """
    return TransactionPayload__ScriptFunction(
        value=ScriptFunction(
            module=ModuleId(address=AccountAddress.from_hex(
                "00000000000000000000000000000001"), name=Identifier("OnChainConfigScripts")),
            function=Identifier("propose_update_consensus_config"),
            ty_args=[],
            args=[bcs.serialize(uncle_rate_target, st.uint64), bcs.serialize(base_block_time_target, st.uint64), bcs.serialize(base_reward_per_block, st.uint128), bcs.serialize(base_reward_per_uncle_percent, st.uint64), bcs.serialize(epoch_block_count, st.uint64), bcs.serialize(
                base_block_difficulty_window, st.uint64), bcs.serialize(min_block_time_target, st.uint64), bcs.serialize(max_block_time_target, st.uint64), bcs.serialize(base_max_uncles_per_block, st.uint64), bcs.serialize(base_block_gas_limit, st.uint64), bcs.serialize(strategy, st.uint8), bcs.serialize(exec_delay, st.uint64)],
        )
    )


def encode_propose_update_reward_config_script_function(reward_delay: st.uint64, exec_delay: st.uint64) -> TransactionPayload:
    """.
    """
    return TransactionPayload__ScriptFunction(
        value=ScriptFunction(
            module=ModuleId(address=AccountAddress.from_hex(
                "00000000000000000000000000000001"), name=Identifier("OnChainConfigScripts")),
            function=Identifier("propose_update_reward_config"),
            ty_args=[],
            args=[bcs.serialize(reward_delay, st.uint64),
                  bcs.serialize(exec_delay, st.uint64)],
        )
    )


def encode_propose_update_txn_publish_option_script_function(script_allowed: bool, module_publishing_allowed: bool, exec_delay: st.uint64) -> TransactionPayload:
    """.
    """
    return TransactionPayload__ScriptFunction(
        value=ScriptFunction(
            module=ModuleId(address=AccountAddress.from_hex(
                "00000000000000000000000000000001"), name=Identifier("OnChainConfigScripts")),
            function=Identifier("propose_update_txn_publish_option"),
            ty_args=[],
            args=[bcs.serialize(script_allowed, st.bool), bcs.serialize(
                module_publishing_allowed, st.bool), bcs.serialize(exec_delay, st.uint64)],
        )
    )


def encode_propose_update_txn_timeout_config_script_function(duration_seconds: st.uint64, exec_delay: st.uint64) -> TransactionPayload:
    """.
    """
    return TransactionPayload__ScriptFunction(
        value=ScriptFunction(
            module=ModuleId(address=AccountAddress.from_hex(
                "00000000000000000000000000000001"), name=Identifier("OnChainConfigScripts")),
            function=Identifier("propose_update_txn_timeout_config"),
            ty_args=[],
            args=[bcs.serialize(duration_seconds, st.uint64),
                  bcs.serialize(exec_delay, st.uint64)],
        )
    )


def encode_propose_update_vm_config_script_function(instruction_schedule: bytes, native_schedule: bytes, global_memory_per_byte_cost: st.uint64, global_memory_per_byte_write_cost: st.uint64, min_transaction_gas_units: st.uint64, large_transaction_cutoff: st.uint64, instrinsic_gas_per_byte: st.uint64, maximum_number_of_gas_units: st.uint64, min_price_per_gas_unit: st.uint64, max_price_per_gas_unit: st.uint64, max_transaction_size_in_bytes: st.uint64, gas_unit_scaling_factor: st.uint64, default_account_size: st.uint64, exec_delay: st.uint64) -> TransactionPayload:
    """.
    """
    return TransactionPayload__ScriptFunction(
        value=ScriptFunction(
            module=ModuleId(address=AccountAddress.from_hex(
                "00000000000000000000000000000001"), name=Identifier("OnChainConfigScripts")),
            function=Identifier("propose_update_vm_config"),
            ty_args=[],
            args=[bcs.serialize(instruction_schedule, bytes), bcs.serialize(native_schedule, bytes), bcs.serialize(global_memory_per_byte_cost, st.uint64), bcs.serialize(global_memory_per_byte_write_cost, st.uint64), bcs.serialize(min_transaction_gas_units, st.uint64), bcs.serialize(large_transaction_cutoff, st.uint64), bcs.serialize(instrinsic_gas_per_byte, st.uint64), bcs.serialize(
                maximum_number_of_gas_units, st.uint64), bcs.serialize(min_price_per_gas_unit, st.uint64), bcs.serialize(max_price_per_gas_unit, st.uint64), bcs.serialize(max_transaction_size_in_bytes, st.uint64), bcs.serialize(gas_unit_scaling_factor, st.uint64), bcs.serialize(default_account_size, st.uint64), bcs.serialize(exec_delay, st.uint64)],
        )
    )


def encode_queue_proposal_action_script_function(token_t: TypeTag, action_t: TypeTag, proposer_address: AccountAddress, proposal_id: st.uint64) -> TransactionPayload:
    """queue agreed proposal to execute.
    """
    return TransactionPayload__ScriptFunction(
        value=ScriptFunction(
            module=ModuleId(address=AccountAddress.from_hex(
                "00000000000000000000000000000001"), name=Identifier("Dao")),
            function=Identifier("queue_proposal_action"),
            ty_args=[token_t, action_t],
            args=[bcs.serialize(proposer_address, starcoin_types.AccountAddress), bcs.serialize(
                proposal_id, st.uint64)],
        )
    )


def encode_revoke_vote_script_function(token: TypeTag, action: TypeTag, proposer_address: AccountAddress, proposal_id: st.uint64) -> TransactionPayload:
    """.
    """
    return TransactionPayload__ScriptFunction(
        value=ScriptFunction(
            module=ModuleId(address=AccountAddress.from_hex(
                "00000000000000000000000000000001"), name=Identifier("DaoVoteScripts")),
            function=Identifier("revoke_vote"),
            ty_args=[token, action],
            args=[bcs.serialize(proposer_address, starcoin_types.AccountAddress), bcs.serialize(
                proposal_id, st.uint64)],
        )
    )


def encode_rotate_authentication_key_script_function(new_key: bytes) -> TransactionPayload:
    """.
    """
    return TransactionPayload__ScriptFunction(
        value=ScriptFunction(
            module=ModuleId(address=AccountAddress.from_hex(
                "00000000000000000000000000000001"), name=Identifier("Account")),
            function=Identifier("rotate_authentication_key"),
            ty_args=[],
            args=[bcs.serialize(new_key, bytes)],
        )
    )


def encode_split_fixed_key_script_function(token: TypeTag, for_address: AccountAddress, amount: st.uint128, lock_period: st.uint64) -> TransactionPayload:
    """.
    """
    return TransactionPayload__ScriptFunction(
        value=ScriptFunction(
            module=ModuleId(address=AccountAddress.from_hex(
                "00000000000000000000000000000001"), name=Identifier("MintScripts")),
            function=Identifier("split_fixed_key"),
            ty_args=[token],
            args=[bcs.serialize(for_address, starcoin_types.AccountAddress), bcs.serialize(
                amount, st.uint128), bcs.serialize(lock_period, st.uint64)],
        )
    )


def encode_submit_module_upgrade_plan_script_function(token: TypeTag, proposer_address: AccountAddress, proposal_id: st.uint64) -> TransactionPayload:
    """.
    """
    return TransactionPayload__ScriptFunction(
        value=ScriptFunction(
            module=ModuleId(address=AccountAddress.from_hex(
                "00000000000000000000000000000001"), name=Identifier("ModuleUpgradeScripts")),
            function=Identifier("submit_module_upgrade_plan"),
            ty_args=[token],
            args=[bcs.serialize(proposer_address, starcoin_types.AccountAddress), bcs.serialize(
                proposal_id, st.uint64)],
        )
    )


def encode_take_offer_script_function(offered: TypeTag, offer_address: AccountAddress) -> TransactionPayload:
    """.
    """
    return TransactionPayload__ScriptFunction(
        value=ScriptFunction(
            module=ModuleId(address=AccountAddress.from_hex(
                "00000000000000000000000000000001"), name=Identifier("Offer")),
            function=Identifier("take_offer"),
            ty_args=[offered],
            args=[bcs.serialize(offer_address, starcoin_types.AccountAddress)],
        )
    )


def encode_unstake_vote_script_function(token: TypeTag, action: TypeTag, proposer_address: AccountAddress, proposal_id: st.uint64) -> TransactionPayload:
    """.
    """
    return TransactionPayload__ScriptFunction(
        value=ScriptFunction(
            module=ModuleId(address=AccountAddress.from_hex(
                "00000000000000000000000000000001"), name=Identifier("DaoVoteScripts")),
            function=Identifier("unstake_vote"),
            ty_args=[token, action],
            args=[bcs.serialize(proposer_address, starcoin_types.AccountAddress), bcs.serialize(
                proposal_id, st.uint64)],
        )
    )


def encode_update_module_upgrade_strategy_script_function(strategy: st.uint8) -> TransactionPayload:
    """.
    """
    return TransactionPayload__ScriptFunction(
        value=ScriptFunction(
            module=ModuleId(address=AccountAddress.from_hex(
                "00000000000000000000000000000001"), name=Identifier("ModuleUpgradeScripts")),
            function=Identifier("update_module_upgrade_strategy"),
            ty_args=[],
            args=[bcs.serialize(strategy, st.uint8)],
        )
    )


def decode_accept_token_script_function(script: TransactionPayload) -> ScriptFunctionCall:
    if not isinstance(script, ScriptFunction):
        raise ValueError("Unexpected transaction payload")
    return ScriptFunctionCall__AcceptToken(
        token_type=script.ty_args[0],
    )


def decode_cancel_upgrade_plan_script_function(script: TransactionPayload) -> ScriptFunctionCall:
    if not isinstance(script, ScriptFunction):
        raise ValueError("Unexpected transaction payload")
    return ScriptFunctionCall__CancelUpgradePlan(
    )


def decode_cast_vote_script_function(script: TransactionPayload) -> ScriptFunctionCall:
    if not isinstance(script, ScriptFunction):
        raise ValueError("Unexpected transaction payload")
    return ScriptFunctionCall__CastVote(
        token=script.ty_args[0],
        action_t=script.ty_args[1],
        proposer_address=bcs.deserialize(
            script.args[0], starcoin_types.AccountAddress),
        proposal_id=bcs.deserialize(script.args[1], st.uint64),
        agree=bcs.deserialize(script.args[2], bool),
        votes=bcs.deserialize(script.args[3], st.uint128),
    )


def decode_convert_TwoPhaseUpgrade_to_TwoPhaseUpgradeV2_script_function(script: TransactionPayload) -> ScriptFunctionCall:
    if not isinstance(script, ScriptFunction):
        raise ValueError("Unexpected transaction payload")
    return ScriptFunctionCall__ConvertTwoPhaseUpgradeToTwoPhaseUpgradeV2(
        package_address=bcs.deserialize(
            script.args[0], starcoin_types.AccountAddress),
    )


def decode_create_account_with_initial_amount_script_function(script: TransactionPayload) -> ScriptFunctionCall:
    if not isinstance(script, ScriptFunction):
        raise ValueError("Unexpected transaction payload")
    return ScriptFunctionCall__CreateAccountWithInitialAmount(
        token_type=script.ty_args[0],
        fresh_address=bcs.deserialize(
            script.args[0], starcoin_types.AccountAddress),
        auth_key=bcs.deserialize(script.args[1], bytes),
        initial_amount=bcs.deserialize(script.args[2], st.uint128),
    )


def decode_destroy_terminated_proposal_script_function(script: TransactionPayload) -> ScriptFunctionCall:
    if not isinstance(script, ScriptFunction):
        raise ValueError("Unexpected transaction payload")
    return ScriptFunctionCall__DestroyTerminatedProposal(
        token_t=script.ty_args[0],
        action_t=script.ty_args[1],
        proposer_address=bcs.deserialize(
            script.args[0], starcoin_types.AccountAddress),
        proposal_id=bcs.deserialize(script.args[1], st.uint64),
    )


def decode_empty_script_script_function(script: TransactionPayload) -> ScriptFunctionCall:
    if not isinstance(script, ScriptFunction):
        raise ValueError("Unexpected transaction payload")
    return ScriptFunctionCall__EmptyScript(
    )


def decode_execute_script_function(script: TransactionPayload) -> ScriptFunctionCall:
    if not isinstance(script, ScriptFunction):
        raise ValueError("Unexpected transaction payload")
    return ScriptFunctionCall__Execute(
        token_t=script.ty_args[0],
        proposer_address=bcs.deserialize(
            script.args[0], starcoin_types.AccountAddress),
        proposal_id=bcs.deserialize(script.args[1], st.uint64),
    )


def decode_execute_on_chain_config_proposal_script_function(script: TransactionPayload) -> ScriptFunctionCall:
    if not isinstance(script, ScriptFunction):
        raise ValueError("Unexpected transaction payload")
    return ScriptFunctionCall__ExecuteOnChainConfigProposal(
        config_t=script.ty_args[0],
        proposal_id=bcs.deserialize(script.args[0], st.uint64),
    )


def decode_initialize_script_function(script: TransactionPayload) -> ScriptFunctionCall:
    if not isinstance(script, ScriptFunction):
        raise ValueError("Unexpected transaction payload")
    return ScriptFunctionCall__Initialize(
        stdlib_version=bcs.deserialize(script.args[0], st.uint64),
        reward_delay=bcs.deserialize(script.args[1], st.uint64),
        pre_mine_amount=bcs.deserialize(script.args[2], st.uint128),
        time_mint_amount=bcs.deserialize(script.args[3], st.uint128),
        time_mint_period=bcs.deserialize(script.args[4], st.uint64),
        parent_hash=bcs.deserialize(script.args[5], bytes),
        association_auth_key=bcs.deserialize(script.args[6], bytes),
        genesis_auth_key=bcs.deserialize(script.args[7], bytes),
        chain_id=bcs.deserialize(script.args[8], st.uint8),
        genesis_timestamp=bcs.deserialize(script.args[9], st.uint64),
        uncle_rate_target=bcs.deserialize(script.args[10], st.uint64),
        epoch_block_count=bcs.deserialize(script.args[11], st.uint64),
        base_block_time_target=bcs.deserialize(script.args[12], st.uint64),
        base_block_difficulty_window=bcs.deserialize(
            script.args[13], st.uint64),
        base_reward_per_block=bcs.deserialize(script.args[14], st.uint128),
        base_reward_per_uncle_percent=bcs.deserialize(
            script.args[15], st.uint64),
        min_block_time_target=bcs.deserialize(script.args[16], st.uint64),
        max_block_time_target=bcs.deserialize(script.args[17], st.uint64),
        base_max_uncles_per_block=bcs.deserialize(script.args[18], st.uint64),
        base_block_gas_limit=bcs.deserialize(script.args[19], st.uint64),
        strategy=bcs.deserialize(script.args[20], st.uint8),
        script_allowed=bcs.deserialize(script.args[21], bool),
        module_publishing_allowed=bcs.deserialize(script.args[22], bool),
        instruction_schedule=bcs.deserialize(script.args[23], bytes),
        native_schedule=bcs.deserialize(script.args[24], bytes),
        global_memory_per_byte_cost=bcs.deserialize(
            script.args[25], st.uint64),
        global_memory_per_byte_write_cost=bcs.deserialize(
            script.args[26], st.uint64),
        min_transaction_gas_units=bcs.deserialize(script.args[27], st.uint64),
        large_transaction_cutoff=bcs.deserialize(script.args[28], st.uint64),
        instrinsic_gas_per_byte=bcs.deserialize(script.args[29], st.uint64),
        maximum_number_of_gas_units=bcs.deserialize(
            script.args[30], st.uint64),
        min_price_per_gas_unit=bcs.deserialize(script.args[31], st.uint64),
        max_price_per_gas_unit=bcs.deserialize(script.args[32], st.uint64),
        max_transaction_size_in_bytes=bcs.deserialize(
            script.args[33], st.uint64),
        gas_unit_scaling_factor=bcs.deserialize(script.args[34], st.uint64),
        default_account_size=bcs.deserialize(script.args[35], st.uint64),
        voting_delay=bcs.deserialize(script.args[36], st.uint64),
        voting_period=bcs.deserialize(script.args[37], st.uint64),
        voting_quorum_rate=bcs.deserialize(script.args[38], st.uint8),
        min_action_delay=bcs.deserialize(script.args[39], st.uint64),
        transaction_timeout=bcs.deserialize(script.args[40], st.uint64),
    )


def decode_mint_and_split_by_linear_key_script_function(script: TransactionPayload) -> ScriptFunctionCall:
    if not isinstance(script, ScriptFunction):
        raise ValueError("Unexpected transaction payload")
    return ScriptFunctionCall__MintAndSplitByLinearKey(
        token=script.ty_args[0],
        for_address=bcs.deserialize(
            script.args[0], starcoin_types.AccountAddress),
        amount=bcs.deserialize(script.args[1], st.uint128),
        lock_period=bcs.deserialize(script.args[2], st.uint64),
    )


def decode_mint_token_by_fixed_key_script_function(script: TransactionPayload) -> ScriptFunctionCall:
    if not isinstance(script, ScriptFunction):
        raise ValueError("Unexpected transaction payload")
    return ScriptFunctionCall__MintTokenByFixedKey(
        token=script.ty_args[0],
    )


def decode_mint_token_by_linear_key_script_function(script: TransactionPayload) -> ScriptFunctionCall:
    if not isinstance(script, ScriptFunction):
        raise ValueError("Unexpected transaction payload")
    return ScriptFunctionCall__MintTokenByLinearKey(
        token=script.ty_args[0],
    )


def decode_peer_to_peer_script_function(script: TransactionPayload) -> ScriptFunctionCall:
    if not isinstance(script, ScriptFunction):
        raise ValueError("Unexpected transaction payload")
    return ScriptFunctionCall__PeerToPeer(
        token_type=script.ty_args[0],
        payee=bcs.deserialize(script.args[0], starcoin_types.AccountAddress),
        payee_auth_key=bcs.deserialize(script.args[1], bytes),
        amount=bcs.deserialize(script.args[2], st.uint128),
    )


def decode_peer_to_peer_batch_script_function(script: TransactionPayload) -> ScriptFunctionCall:
    if not isinstance(script, ScriptFunction):
        raise ValueError("Unexpected transaction payload")
    return ScriptFunctionCall__PeerToPeerBatch(
        token_type=script.ty_args[0],
        payeees=bcs.deserialize(script.args[0], bytes),
        payee_auth_keys=bcs.deserialize(script.args[1], bytes),
        amount=bcs.deserialize(script.args[2], st.uint128),
    )


def decode_peer_to_peer_with_metadata_script_function(script: TransactionPayload) -> ScriptFunctionCall:
    if not isinstance(script, ScriptFunction):
        raise ValueError("Unexpected transaction payload")
    return ScriptFunctionCall__PeerToPeerWithMetadata(
        token_type=script.ty_args[0],
        payee=bcs.deserialize(script.args[0], starcoin_types.AccountAddress),
        payee_auth_key=bcs.deserialize(script.args[1], bytes),
        amount=bcs.deserialize(script.args[2], st.uint128),
        metadata=bcs.deserialize(script.args[3], bytes),
    )


def decode_propose_script_function(script: TransactionPayload) -> ScriptFunctionCall:
    if not isinstance(script, ScriptFunction):
        raise ValueError("Unexpected transaction payload")
    return ScriptFunctionCall__Propose(
        token_t=script.ty_args[0],
        voting_delay=bcs.deserialize(script.args[0], st.uint64),
        voting_period=bcs.deserialize(script.args[1], st.uint64),
        voting_quorum_rate=bcs.deserialize(script.args[2], st.uint8),
        min_action_delay=bcs.deserialize(script.args[3], st.uint64),
        exec_delay=bcs.deserialize(script.args[4], st.uint64),
    )


def decode_propose_module_upgrade_script_function(script: TransactionPayload) -> ScriptFunctionCall:
    if not isinstance(script, ScriptFunction):
        raise ValueError("Unexpected transaction payload")
    return ScriptFunctionCall__ProposeModuleUpgrade(
        token=script.ty_args[0],
        _module_address=bcs.deserialize(
            script.args[0], starcoin_types.AccountAddress),
        _package_hash=bcs.deserialize(script.args[1], bytes),
        _version=bcs.deserialize(script.args[2], st.uint64),
        _exec_delay=bcs.deserialize(script.args[3], st.uint64),
    )


def decode_propose_module_upgrade_v2_script_function(script: TransactionPayload) -> ScriptFunctionCall:
    if not isinstance(script, ScriptFunction):
        raise ValueError("Unexpected transaction payload")
    return ScriptFunctionCall__ProposeModuleUpgradeV2(
        token=script.ty_args[0],
        module_address=bcs.deserialize(
            script.args[0], starcoin_types.AccountAddress),
        package_hash=bcs.deserialize(script.args[1], bytes),
        version=bcs.deserialize(script.args[2], st.uint64),
        exec_delay=bcs.deserialize(script.args[3], st.uint64),
        enforced=bcs.deserialize(script.args[4], bool),
    )


def decode_propose_update_consensus_config_script_function(script: TransactionPayload) -> ScriptFunctionCall:
    if not isinstance(script, ScriptFunction):
        raise ValueError("Unexpected transaction payload")
    return ScriptFunctionCall__ProposeUpdateConsensusConfig(
        uncle_rate_target=bcs.deserialize(script.args[0], st.uint64),
        base_block_time_target=bcs.deserialize(script.args[1], st.uint64),
        base_reward_per_block=bcs.deserialize(script.args[2], st.uint128),
        base_reward_per_uncle_percent=bcs.deserialize(
            script.args[3], st.uint64),
        epoch_block_count=bcs.deserialize(script.args[4], st.uint64),
        base_block_difficulty_window=bcs.deserialize(
            script.args[5], st.uint64),
        min_block_time_target=bcs.deserialize(script.args[6], st.uint64),
        max_block_time_target=bcs.deserialize(script.args[7], st.uint64),
        base_max_uncles_per_block=bcs.deserialize(script.args[8], st.uint64),
        base_block_gas_limit=bcs.deserialize(script.args[9], st.uint64),
        strategy=bcs.deserialize(script.args[10], st.uint8),
        exec_delay=bcs.deserialize(script.args[11], st.uint64),
    )


def decode_propose_update_reward_config_script_function(script: TransactionPayload) -> ScriptFunctionCall:
    if not isinstance(script, ScriptFunction):
        raise ValueError("Unexpected transaction payload")
    return ScriptFunctionCall__ProposeUpdateRewardConfig(
        reward_delay=bcs.deserialize(script.args[0], st.uint64),
        exec_delay=bcs.deserialize(script.args[1], st.uint64),
    )


def decode_propose_update_txn_publish_option_script_function(script: TransactionPayload) -> ScriptFunctionCall:
    if not isinstance(script, ScriptFunction):
        raise ValueError("Unexpected transaction payload")
    return ScriptFunctionCall__ProposeUpdateTxnPublishOption(
        script_allowed=bcs.deserialize(script.args[0], bool),
        module_publishing_allowed=bcs.deserialize(script.args[1], bool),
        exec_delay=bcs.deserialize(script.args[2], st.uint64),
    )


def decode_propose_update_txn_timeout_config_script_function(script: TransactionPayload) -> ScriptFunctionCall:
    if not isinstance(script, ScriptFunction):
        raise ValueError("Unexpected transaction payload")
    return ScriptFunctionCall__ProposeUpdateTxnTimeoutConfig(
        duration_seconds=bcs.deserialize(script.args[0], st.uint64),
        exec_delay=bcs.deserialize(script.args[1], st.uint64),
    )


def decode_propose_update_vm_config_script_function(script: TransactionPayload) -> ScriptFunctionCall:
    if not isinstance(script, ScriptFunction):
        raise ValueError("Unexpected transaction payload")
    return ScriptFunctionCall__ProposeUpdateVmConfig(
        instruction_schedule=bcs.deserialize(script.args[0], bytes),
        native_schedule=bcs.deserialize(script.args[1], bytes),
        global_memory_per_byte_cost=bcs.deserialize(script.args[2], st.uint64),
        global_memory_per_byte_write_cost=bcs.deserialize(
            script.args[3], st.uint64),
        min_transaction_gas_units=bcs.deserialize(script.args[4], st.uint64),
        large_transaction_cutoff=bcs.deserialize(script.args[5], st.uint64),
        instrinsic_gas_per_byte=bcs.deserialize(script.args[6], st.uint64),
        maximum_number_of_gas_units=bcs.deserialize(script.args[7], st.uint64),
        min_price_per_gas_unit=bcs.deserialize(script.args[8], st.uint64),
        max_price_per_gas_unit=bcs.deserialize(script.args[9], st.uint64),
        max_transaction_size_in_bytes=bcs.deserialize(
            script.args[10], st.uint64),
        gas_unit_scaling_factor=bcs.deserialize(script.args[11], st.uint64),
        default_account_size=bcs.deserialize(script.args[12], st.uint64),
        exec_delay=bcs.deserialize(script.args[13], st.uint64),
    )


def decode_queue_proposal_action_script_function(script: TransactionPayload) -> ScriptFunctionCall:
    if not isinstance(script, ScriptFunction):
        raise ValueError("Unexpected transaction payload")
    return ScriptFunctionCall__QueueProposalAction(
        token_t=script.ty_args[0],
        action_t=script.ty_args[1],
        proposer_address=bcs.deserialize(
            script.args[0], starcoin_types.AccountAddress),
        proposal_id=bcs.deserialize(script.args[1], st.uint64),
    )


def decode_revoke_vote_script_function(script: TransactionPayload) -> ScriptFunctionCall:
    if not isinstance(script, ScriptFunction):
        raise ValueError("Unexpected transaction payload")
    return ScriptFunctionCall__RevokeVote(
        token=script.ty_args[0],
        action=script.ty_args[1],
        proposer_address=bcs.deserialize(
            script.args[0], starcoin_types.AccountAddress),
        proposal_id=bcs.deserialize(script.args[1], st.uint64),
    )


def decode_rotate_authentication_key_script_function(script: TransactionPayload) -> ScriptFunctionCall:
    if not isinstance(script, ScriptFunction):
        raise ValueError("Unexpected transaction payload")
    return ScriptFunctionCall__RotateAuthenticationKey(
        new_key=bcs.deserialize(script.args[0], bytes),
    )


def decode_split_fixed_key_script_function(script: TransactionPayload) -> ScriptFunctionCall:
    if not isinstance(script, ScriptFunction):
        raise ValueError("Unexpected transaction payload")
    return ScriptFunctionCall__SplitFixedKey(
        token=script.ty_args[0],
        for_address=bcs.deserialize(
            script.args[0], starcoin_types.AccountAddress),
        amount=bcs.deserialize(script.args[1], st.uint128),
        lock_period=bcs.deserialize(script.args[2], st.uint64),
    )


def decode_submit_module_upgrade_plan_script_function(script: TransactionPayload) -> ScriptFunctionCall:
    if not isinstance(script, ScriptFunction):
        raise ValueError("Unexpected transaction payload")
    return ScriptFunctionCall__SubmitModuleUpgradePlan(
        token=script.ty_args[0],
        proposer_address=bcs.deserialize(
            script.args[0], starcoin_types.AccountAddress),
        proposal_id=bcs.deserialize(script.args[1], st.uint64),
    )


def decode_take_offer_script_function(script: TransactionPayload) -> ScriptFunctionCall:
    if not isinstance(script, ScriptFunction):
        raise ValueError("Unexpected transaction payload")
    return ScriptFunctionCall__TakeOffer(
        offered=script.ty_args[0],
        offer_address=bcs.deserialize(
            script.args[0], starcoin_types.AccountAddress),
    )


def decode_unstake_vote_script_function(script: TransactionPayload) -> ScriptFunctionCall:
    if not isinstance(script, ScriptFunction):
        raise ValueError("Unexpected transaction payload")
    return ScriptFunctionCall__UnstakeVote(
        token=script.ty_args[0],
        action=script.ty_args[1],
        proposer_address=bcs.deserialize(
            script.args[0], starcoin_types.AccountAddress),
        proposal_id=bcs.deserialize(script.args[1], st.uint64),
    )


def decode_update_module_upgrade_strategy_script_function(script: TransactionPayload) -> ScriptFunctionCall:
    if not isinstance(script, ScriptFunction):
        raise ValueError("Unexpected transaction payload")
    return ScriptFunctionCall__UpdateModuleUpgradeStrategy(
        strategy=bcs.deserialize(script.args[0], st.uint8),
    )


# pyre-ignore
TRANSACTION_SCRIPT_ENCODER_MAP: typing.Dict[typing.Type[ScriptCall], typing.Callable[[ScriptCall], Script]] = {
}


# pyre-ignore
SCRIPT_FUNCTION_ENCODER_MAP: typing.Dict[typing.Type[ScriptFunctionCall], typing.Callable[[ScriptFunctionCall], TransactionPayload]] = {
    ScriptFunctionCall__AcceptToken: encode_accept_token_script_function,
    ScriptFunctionCall__CancelUpgradePlan: encode_cancel_upgrade_plan_script_function,
    ScriptFunctionCall__CastVote: encode_cast_vote_script_function,
    ScriptFunctionCall__ConvertTwoPhaseUpgradeToTwoPhaseUpgradeV2: encode_convert_TwoPhaseUpgrade_to_TwoPhaseUpgradeV2_script_function,
    ScriptFunctionCall__CreateAccountWithInitialAmount: encode_create_account_with_initial_amount_script_function,
    ScriptFunctionCall__DestroyTerminatedProposal: encode_destroy_terminated_proposal_script_function,
    ScriptFunctionCall__EmptyScript: encode_empty_script_script_function,
    ScriptFunctionCall__Execute: encode_execute_script_function,
    ScriptFunctionCall__ExecuteOnChainConfigProposal: encode_execute_on_chain_config_proposal_script_function,
    ScriptFunctionCall__Initialize: encode_initialize_script_function,
    ScriptFunctionCall__MintAndSplitByLinearKey: encode_mint_and_split_by_linear_key_script_function,
    ScriptFunctionCall__MintTokenByFixedKey: encode_mint_token_by_fixed_key_script_function,
    ScriptFunctionCall__MintTokenByLinearKey: encode_mint_token_by_linear_key_script_function,
    ScriptFunctionCall__PeerToPeer: encode_peer_to_peer_script_function,
    ScriptFunctionCall__PeerToPeerBatch: encode_peer_to_peer_batch_script_function,
    ScriptFunctionCall__PeerToPeerWithMetadata: encode_peer_to_peer_with_metadata_script_function,
    ScriptFunctionCall__Propose: encode_propose_script_function,
    ScriptFunctionCall__ProposeModuleUpgrade: encode_propose_module_upgrade_script_function,
    ScriptFunctionCall__ProposeModuleUpgradeV2: encode_propose_module_upgrade_v2_script_function,
    ScriptFunctionCall__ProposeUpdateConsensusConfig: encode_propose_update_consensus_config_script_function,
    ScriptFunctionCall__ProposeUpdateRewardConfig: encode_propose_update_reward_config_script_function,
    ScriptFunctionCall__ProposeUpdateTxnPublishOption: encode_propose_update_txn_publish_option_script_function,
    ScriptFunctionCall__ProposeUpdateTxnTimeoutConfig: encode_propose_update_txn_timeout_config_script_function,
    ScriptFunctionCall__ProposeUpdateVmConfig: encode_propose_update_vm_config_script_function,
    ScriptFunctionCall__QueueProposalAction: encode_queue_proposal_action_script_function,
    ScriptFunctionCall__RevokeVote: encode_revoke_vote_script_function,
    ScriptFunctionCall__RotateAuthenticationKey: encode_rotate_authentication_key_script_function,
    ScriptFunctionCall__SplitFixedKey: encode_split_fixed_key_script_function,
    ScriptFunctionCall__SubmitModuleUpgradePlan: encode_submit_module_upgrade_plan_script_function,
    ScriptFunctionCall__TakeOffer: encode_take_offer_script_function,
    ScriptFunctionCall__UnstakeVote: encode_unstake_vote_script_function,
    ScriptFunctionCall__UpdateModuleUpgradeStrategy: encode_update_module_upgrade_strategy_script_function,
}


TRANSACTION_SCRIPT_DECODER_MAP: typing.Dict[bytes, typing.Callable[[Script], ScriptCall]] = {
}


SCRIPT_FUNCTION_DECODER_MAP: typing.Dict[str, typing.Callable[[TransactionPayload], ScriptFunctionCall]] = {
    "Accountaccept_token": decode_accept_token_script_function,
    "ModuleUpgradeScriptscancel_upgrade_plan": decode_cancel_upgrade_plan_script_function,
    "DaoVoteScriptscast_vote": decode_cast_vote_script_function,
    "PackageTxnManagerconvert_TwoPhaseUpgrade_to_TwoPhaseUpgradeV2": decode_convert_TwoPhaseUpgrade_to_TwoPhaseUpgradeV2_script_function,
    "Accountcreate_account_with_initial_amount": decode_create_account_with_initial_amount_script_function,
    "Daodestroy_terminated_proposal": decode_destroy_terminated_proposal_script_function,
    "EmptyScriptsempty_script": decode_empty_script_script_function,
    "ModifyDaoConfigProposalexecute": decode_execute_script_function,
    "OnChainConfigScriptsexecute_on_chain_config_proposal": decode_execute_on_chain_config_proposal_script_function,
    "Genesisinitialize": decode_initialize_script_function,
    "MintScriptsmint_and_split_by_linear_key": decode_mint_and_split_by_linear_key_script_function,
    "MintScriptsmint_token_by_fixed_key": decode_mint_token_by_fixed_key_script_function,
    "MintScriptsmint_token_by_linear_key": decode_mint_token_by_linear_key_script_function,
    "TransferScriptspeer_to_peer": decode_peer_to_peer_script_function,
    "TransferScriptspeer_to_peer_batch": decode_peer_to_peer_batch_script_function,
    "TransferScriptspeer_to_peer_with_metadata": decode_peer_to_peer_with_metadata_script_function,
    "ModifyDaoConfigProposalpropose": decode_propose_script_function,
    "ModuleUpgradeScriptspropose_module_upgrade": decode_propose_module_upgrade_script_function,
    "ModuleUpgradeScriptspropose_module_upgrade_v2": decode_propose_module_upgrade_v2_script_function,
    "OnChainConfigScriptspropose_update_consensus_config": decode_propose_update_consensus_config_script_function,
    "OnChainConfigScriptspropose_update_reward_config": decode_propose_update_reward_config_script_function,
    "OnChainConfigScriptspropose_update_txn_publish_option": decode_propose_update_txn_publish_option_script_function,
    "OnChainConfigScriptspropose_update_txn_timeout_config": decode_propose_update_txn_timeout_config_script_function,
    "OnChainConfigScriptspropose_update_vm_config": decode_propose_update_vm_config_script_function,
    "Daoqueue_proposal_action": decode_queue_proposal_action_script_function,
    "DaoVoteScriptsrevoke_vote": decode_revoke_vote_script_function,
    "Accountrotate_authentication_key": decode_rotate_authentication_key_script_function,
    "MintScriptssplit_fixed_key": decode_split_fixed_key_script_function,
    "ModuleUpgradeScriptssubmit_module_upgrade_plan": decode_submit_module_upgrade_plan_script_function,
    "Offertake_offer": decode_take_offer_script_function,
    "DaoVoteScriptsunstake_vote": decode_unstake_vote_script_function,
    "ModuleUpgradeScriptsupdate_module_upgrade_strategy": decode_update_module_upgrade_strategy_script_function,
}

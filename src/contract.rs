/// This contract implements SNIP-20 standard:
/// https://github.com/SecretFoundation/SNIPs/blob/master/SNIP-20.md
use cosmwasm_std::{
    log, to_binary, Api, Binary, CanonicalAddr, CosmosMsg, Env, Extern, HandleResponse, HumanAddr,
    InitResponse, Querier, QueryResult, ReadonlyStorage, StdError, StdResult, Storage, Uint128,
};

use crate::batch;
use crate::msg::{
    space_pad, ContractStatusLevel, HandleAnswer, HandleMsg, InitMsg, QueryAnswer, QueryMsg,
    ResponseStatus::Success,
};
use crate::rand::sha_256;
use crate::receiver::Snip20ReceiveMsg;
use crate::state::{
    get_receiver_hash, read_allowance, read_viewing_key, set_receiver_hash, write_allowance,
    write_viewing_key, Balances, Config, Constants, ReadonlyBalances, ReadonlyConfig,
};
use crate::transaction_history::{get_transfers, get_txs, store_burn, store_mint, store_transfer};
use crate::viewing_key::{ViewingKey, VIEWING_KEY_SIZE};

/// We make sure that responses from `handle` are padded to a multiple of this size.
pub const RESPONSE_BLOCK_SIZE: usize = 256;

pub fn init<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: InitMsg,
) -> StdResult<InitResponse> {
    // Check name, symbol, decimals
    if !is_valid_name(&msg.name) {
        return Err(StdError::generic_err(
            "Name is not in the expected format (3-30 UTF-8 bytes)",
        ));
    }
    if !is_valid_symbol(&msg.symbol) {
        return Err(StdError::generic_err(
            "Ticker symbol is not in expected format [A-Z]{3,6}",
        ));
    }
    if msg.decimals > 18 {
        return Err(StdError::generic_err("Decimals must not exceed 18"));
    }

    let init_config = msg.config();
    let contract_initializer = env.message.sender;
    let prng_seed_hashed = sha_256(&msg.prng_seed.0);
    let mut config = Config::from_storage(&mut deps.storage);
    config.set_constants(&Constants {
        name: msg.name,
        symbol: msg.symbol,
        decimals: msg.decimals,
        prng_seed: prng_seed_hashed.to_vec(),
        total_supply_is_public: init_config.public_total_supply(),
        deposit_is_enabled: init_config.deposit_enabled(),
        redeem_is_enabled: init_config.redeem_enabled(),
        mint_is_enabled: init_config.mint_enabled(),
        burn_is_enabled: init_config.burn_enabled(),
    })?;
    config.set_total_supply(0);
    let minters = if init_config.mint_enabled() {
        Vec::from([contract_initializer])
    } else {
        Vec::new()
    };
    config.set_minters(minters)?;

    Ok(InitResponse::default())
}

fn pad_response(response: StdResult<HandleResponse>) -> StdResult<HandleResponse> {
    response.map(|mut response| {
        response.data = response.data.map(|mut data| {
            space_pad(RESPONSE_BLOCK_SIZE, &mut data.0);
            data
        });
        response
    })
}

pub fn handle<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: HandleMsg,
) -> StdResult<HandleResponse> {
    let response = match msg {
        // Base
        HandleMsg::Transfer {
            recipient,
            amount,
            memo,
            ..
        } => try_transfer(deps, env, recipient, amount, memo),
        HandleMsg::Send {
            recipient,
            amount,
            msg,
            memo,
            ..
        } => try_send(deps, env, recipient, amount, memo, msg),
        HandleMsg::BatchTransfer { actions, .. } => try_batch_transfer(deps, env, actions),
        HandleMsg::BatchSend { actions, .. } => try_batch_send(deps, env, actions),
        HandleMsg::Burn { amount, memo, .. } => try_burn(deps, env, amount, memo),
        HandleMsg::RegisterReceive { code_hash, .. } => try_register_receive(deps, env, code_hash),
        HandleMsg::CreateViewingKey { entropy, .. } => try_create_key(deps, env, entropy),
        HandleMsg::SetViewingKey { key, .. } => try_set_key(deps, env, key),

        // Allowance
        HandleMsg::IncreaseAllowance {
            spender,
            amount,
            expiration,
            ..
        } => try_increase_allowance(deps, env, spender, amount, expiration),
        HandleMsg::DecreaseAllowance {
            spender,
            amount,
            expiration,
            ..
        } => try_decrease_allowance(deps, env, spender, amount, expiration),
        HandleMsg::TransferFrom {
            owner,
            recipient,
            amount,
            memo,
            ..
        } => try_transfer_from(deps, &env, &owner, &recipient, amount, memo),
        HandleMsg::SendFrom {
            owner,
            recipient,
            amount,
            msg,
            memo,
            ..
        } => try_send_from(deps, env, owner, recipient, amount, memo, msg),
        HandleMsg::BatchTransferFrom { actions, .. } => {
            try_batch_transfer_from(deps, &env, actions)
        }
        HandleMsg::BatchSendFrom { actions, .. } => try_batch_send_from(deps, env, actions),
        HandleMsg::BurnFrom {
            owner,
            amount,
            memo,
            ..
        } => try_burn_from(deps, &env, &owner, amount, memo),
        HandleMsg::BatchBurnFrom { actions, .. } => try_batch_burn_from(deps, &env, actions),

        // Mint
        HandleMsg::Mint {
            recipient,
            amount,
            memo,
            ..
        } => try_mint(deps, env, recipient, amount, memo),
        HandleMsg::BatchMint { actions, .. } => try_batch_mint(deps, env, actions),
    };

    pad_response(response)
}

pub fn query<S: Storage, A: Api, Q: Querier>(deps: &Extern<S, A, Q>, msg: QueryMsg) -> QueryResult {
    match msg {
        QueryMsg::TokenInfo {} => query_token_info(&deps.storage),
        QueryMsg::TokenConfig {} => query_token_config(&deps.storage),
        QueryMsg::ContractStatus {} => query_contract_status(),
        QueryMsg::ExchangeRate {} => query_exchange_rate(),
        QueryMsg::Minters { .. } => query_minters(deps),
        _ => authenticated_queries(deps, msg),
    }
}

pub fn authenticated_queries<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    msg: QueryMsg,
) -> QueryResult {
    let (addresses, key) = msg.get_validation_params();

    for address in addresses {
        let canonical_addr = deps.api.canonical_address(address)?;

        let expected_key = read_viewing_key(&deps.storage, &canonical_addr);

        if expected_key.is_none() {
            // Checking the key will take significant time. We don't want to exit immediately if it isn't set
            // in a way which will allow to time the command and determine if a viewing key doesn't exist
            key.check_viewing_key(&[0u8; VIEWING_KEY_SIZE]);
        } else if key.check_viewing_key(expected_key.unwrap().as_slice()) {
            return match msg {
                // Base
                QueryMsg::Balance { address, .. } => query_balance(&deps, &address),
                QueryMsg::TransferHistory {
                    address,
                    page,
                    page_size,
                    ..
                } => query_transfers(&deps, &address, page.unwrap_or(0), page_size),
                QueryMsg::TransactionHistory {
                    address,
                    page,
                    page_size,
                    ..
                } => query_transactions(&deps, &address, page.unwrap_or(0), page_size),
                QueryMsg::Allowance { owner, spender, .. } => query_allowance(deps, owner, spender),
                _ => panic!("This query type does not require authentication"),
            };
        }
    }

    Ok(to_binary(&QueryAnswer::ViewingKeyError {
        msg: "Wrong viewing key for this address or viewing key not set".to_string(),
    })?)
}

fn query_exchange_rate() -> QueryResult {
    to_binary(&QueryAnswer::ExchangeRate {
        rate: Uint128(0),
        denom: String::new(),
    })
}

fn query_token_info<S: ReadonlyStorage>(storage: &S) -> QueryResult {
    let config = ReadonlyConfig::from_storage(storage);
    let constants = config.constants()?;

    let total_supply = if constants.total_supply_is_public {
        Some(Uint128(config.total_supply()))
    } else {
        None
    };

    to_binary(&QueryAnswer::TokenInfo {
        name: constants.name,
        symbol: constants.symbol,
        decimals: constants.decimals,
        total_supply,
    })
}

fn query_token_config<S: ReadonlyStorage>(storage: &S) -> QueryResult {
    let config = ReadonlyConfig::from_storage(storage);
    let constants = config.constants()?;

    to_binary(&QueryAnswer::TokenConfig {
        public_total_supply: constants.total_supply_is_public,
        deposit_enabled: constants.deposit_is_enabled,
        redeem_enabled: constants.redeem_is_enabled,
        mint_enabled: constants.mint_is_enabled,
        burn_enabled: constants.burn_is_enabled,
    })
}

fn query_contract_status() -> QueryResult {
    to_binary(&QueryAnswer::ContractStatus {
        status: ContractStatusLevel::NormalRun,
    })
}

pub fn query_transfers<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    account: &HumanAddr,
    page: u32,
    page_size: u32,
) -> StdResult<Binary> {
    let address = deps.api.canonical_address(account)?;
    let (txs, total) = get_transfers(&deps.api, &deps.storage, &address, page, page_size)?;

    let result = QueryAnswer::TransferHistory {
        txs,
        total: Some(total),
    };
    to_binary(&result)
}

pub fn query_transactions<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    account: &HumanAddr,
    page: u32,
    page_size: u32,
) -> StdResult<Binary> {
    let address = deps.api.canonical_address(account)?;
    let (txs, total) = get_txs(&deps.api, &deps.storage, &address, page, page_size)?;

    let result = QueryAnswer::TransactionHistory {
        txs,
        total: Some(total),
    };
    to_binary(&result)
}

pub fn query_balance<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    account: &HumanAddr,
) -> StdResult<Binary> {
    let address = deps.api.canonical_address(account)?;

    let amount = Uint128(ReadonlyBalances::from_storage(&deps.storage).account_amount(&address));
    let response = QueryAnswer::Balance { amount };
    to_binary(&response)
}

fn query_minters<S: Storage, A: Api, Q: Querier>(deps: &Extern<S, A, Q>) -> StdResult<Binary> {
    let minters = ReadonlyConfig::from_storage(&deps.storage).minters();

    let response = QueryAnswer::Minters { minters };
    to_binary(&response)
}

fn try_mint_impl<S: Storage>(
    storage: &mut S,
    minter: &CanonicalAddr,
    recipient: &CanonicalAddr,
    amount: Uint128,
    denom: String,
    memo: Option<String>,
    block: &cosmwasm_std::BlockInfo,
) -> StdResult<()> {
    let raw_amount = amount.u128();

    let mut balances = Balances::from_storage(storage);

    let mut account_balance = balances.balance(recipient);

    if let Some(new_balance) = account_balance.checked_add(raw_amount) {
        account_balance = new_balance;
    } else {
        // This error literally can not happen, since the account's funds are a subset
        // of the total supply, both are stored as u128, and we check for overflow of
        // the total supply just a couple lines before.
        // Still, writing this to cover all overflows.
        return Err(StdError::generic_err(
            "This mint attempt would increase the account's balance above the supported maximum",
        ));
    }

    balances.set_account_balance(recipient, account_balance);

    store_mint(storage, minter, recipient, amount, denom, memo, block)?;

    Ok(())
}

fn try_mint<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    recipient: HumanAddr,
    amount: Uint128,
    memo: Option<String>,
) -> StdResult<HandleResponse> {
    let mut config = Config::from_storage(&mut deps.storage);
    let constants = config.constants()?;
    if !constants.mint_is_enabled {
        return Err(StdError::generic_err(
            "Mint functionality is not enabled for this token.",
        ));
    }

    let minters = config.minters();
    if !minters.contains(&env.message.sender) {
        return Err(StdError::generic_err(
            "Minting is allowed to minter accounts only",
        ));
    }

    let mut total_supply = config.total_supply();
    if let Some(new_total_supply) = total_supply.checked_add(amount.u128()) {
        total_supply = new_total_supply;
    } else {
        return Err(StdError::generic_err(
            "This mint attempt would increase the total supply above the supported maximum",
        ));
    }
    config.set_total_supply(total_supply);

    let minter = &deps.api.canonical_address(&env.message.sender)?;
    let recipient = &deps.api.canonical_address(&recipient)?;
    try_mint_impl(
        &mut deps.storage,
        &minter,
        &recipient,
        amount,
        constants.symbol,
        memo,
        &env.block,
    )?;

    let res = HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::Mint { status: Success })?),
    };

    Ok(res)
}

fn try_batch_mint<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    actions: Vec<batch::MintAction>,
) -> StdResult<HandleResponse> {
    let mut config = Config::from_storage(&mut deps.storage);
    let constants = config.constants()?;
    if !constants.mint_is_enabled {
        return Err(StdError::generic_err(
            "Mint functionality is not enabled for this token.",
        ));
    }

    let minters = config.minters();
    if !minters.contains(&env.message.sender) {
        return Err(StdError::generic_err(
            "Minting is allowed to minter accounts only",
        ));
    }

    let mut total_supply = config.total_supply();

    // Quick loop to check that the total of amounts is valid
    for action in &actions {
        if let Some(new_total_supply) = total_supply.checked_add(action.amount.u128()) {
            total_supply = new_total_supply;
        } else {
            return Err(StdError::generic_err(
                format!("This mint attempt would increase the total supply above the supported maximum: {:?}", action),
            ));
        }
    }
    config.set_total_supply(total_supply);

    let minter = &deps.api.canonical_address(&env.message.sender)?;
    for action in actions {
        let recipient = &deps.api.canonical_address(&action.recipient)?;
        try_mint_impl(
            &mut deps.storage,
            &minter,
            &recipient,
            action.amount,
            constants.symbol.clone(),
            action.memo,
            &env.block,
        )?;
    }

    let res = HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::BatchMint { status: Success })?),
    };

    Ok(res)
}

pub fn try_set_key<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    key: String,
) -> StdResult<HandleResponse> {
    let vk = ViewingKey(key);

    let message_sender = deps.api.canonical_address(&env.message.sender)?;
    write_viewing_key(&mut deps.storage, &message_sender, &vk);

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::SetViewingKey { status: Success })?),
    })
}

pub fn try_create_key<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    entropy: String,
) -> StdResult<HandleResponse> {
    let constants = ReadonlyConfig::from_storage(&deps.storage).constants()?;
    let prng_seed = constants.prng_seed;

    let key = ViewingKey::new(&env, &prng_seed, (&entropy).as_ref());

    let message_sender = deps.api.canonical_address(&env.message.sender)?;
    write_viewing_key(&mut deps.storage, &message_sender, &key);

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::CreateViewingKey { key })?),
    })
}

pub fn query_allowance<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    owner: HumanAddr,
    spender: HumanAddr,
) -> StdResult<Binary> {
    let owner_address = deps.api.canonical_address(&owner)?;
    let spender_address = deps.api.canonical_address(&spender)?;

    let allowance = read_allowance(&deps.storage, &owner_address, &spender_address)?;

    let response = QueryAnswer::Allowance {
        owner,
        spender,
        allowance: Uint128(allowance.amount),
        expiration: allowance.expiration,
    };
    to_binary(&response)
}

fn try_transfer_impl<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    sender: &CanonicalAddr,
    recipient: &CanonicalAddr,
    amount: Uint128,
    memo: Option<String>,
    block: &cosmwasm_std::BlockInfo,
) -> StdResult<()> {
    perform_transfer(&mut deps.storage, &sender, &recipient, amount.u128())?;

    let symbol = Config::from_storage(&mut deps.storage).constants()?.symbol;

    store_transfer(
        &mut deps.storage,
        &sender,
        &sender,
        &recipient,
        amount,
        symbol,
        memo,
        block,
    )?;

    Ok(())
}

fn try_transfer<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    recipient: HumanAddr,
    amount: Uint128,
    memo: Option<String>,
) -> StdResult<HandleResponse> {
    let sender = deps.api.canonical_address(&env.message.sender)?;
    let recipient = deps.api.canonical_address(&recipient)?;
    try_transfer_impl(deps, &sender, &recipient, amount, memo, &env.block)?;

    let res = HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::Transfer { status: Success })?),
    };
    Ok(res)
}

fn try_batch_transfer<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    actions: Vec<batch::TransferAction>,
) -> StdResult<HandleResponse> {
    let sender = deps.api.canonical_address(&env.message.sender)?;
    for action in actions {
        let recipient = deps.api.canonical_address(&action.recipient)?;
        try_transfer_impl(
            deps,
            &sender,
            &recipient,
            action.amount,
            action.memo,
            &env.block,
        )?;
    }

    let res = HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::BatchTransfer { status: Success })?),
    };
    Ok(res)
}

#[allow(clippy::too_many_arguments)]
fn try_add_receiver_api_callback<S: ReadonlyStorage>(
    storage: &S,
    messages: &mut Vec<CosmosMsg>,
    recipient: HumanAddr,
    msg: Option<Binary>,
    sender: HumanAddr,
    from: HumanAddr,
    amount: Uint128,
    memo: Option<String>,
) -> StdResult<()> {
    let receiver_hash = get_receiver_hash(storage, &recipient);
    if let Some(receiver_hash) = receiver_hash {
        let receiver_hash = receiver_hash?;
        let receiver_msg = Snip20ReceiveMsg::new(sender, from, amount, memo, msg);
        let callback_msg = receiver_msg.into_cosmos_msg(receiver_hash, recipient)?;

        messages.push(callback_msg);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn try_send_impl<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    messages: &mut Vec<CosmosMsg>,
    sender: HumanAddr,
    sender_canon: &CanonicalAddr, // redundant but more efficient
    recipient: HumanAddr,
    amount: Uint128,
    memo: Option<String>,
    msg: Option<Binary>,
    block: &cosmwasm_std::BlockInfo,
) -> StdResult<()> {
    let recipient_canon = deps.api.canonical_address(&recipient)?;
    try_transfer_impl(
        deps,
        &sender_canon,
        &recipient_canon,
        amount,
        memo.clone(),
        block,
    )?;

    try_add_receiver_api_callback(
        &deps.storage,
        messages,
        recipient,
        msg,
        sender.clone(),
        sender,
        amount,
        memo,
    )?;

    Ok(())
}

fn try_send<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    recipient: HumanAddr,
    amount: Uint128,
    memo: Option<String>,
    msg: Option<Binary>,
) -> StdResult<HandleResponse> {
    let mut messages = vec![];
    let sender = env.message.sender;
    let sender_canon = deps.api.canonical_address(&sender)?;
    try_send_impl(
        deps,
        &mut messages,
        sender,
        &sender_canon,
        recipient,
        amount,
        memo,
        msg,
        &env.block,
    )?;

    let res = HandleResponse {
        messages,
        log: vec![],
        data: Some(to_binary(&HandleAnswer::Send { status: Success })?),
    };
    Ok(res)
}

fn try_batch_send<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    actions: Vec<batch::SendAction>,
) -> StdResult<HandleResponse> {
    let mut messages = vec![];
    let sender = env.message.sender;
    let sender_canon = deps.api.canonical_address(&sender)?;
    for action in actions {
        try_send_impl(
            deps,
            &mut messages,
            sender.clone(),
            &sender_canon,
            action.recipient,
            action.amount,
            action.memo,
            action.msg,
            &env.block,
        )?;
    }

    let res = HandleResponse {
        messages,
        log: vec![],
        data: Some(to_binary(&HandleAnswer::BatchSend { status: Success })?),
    };
    Ok(res)
}

fn try_register_receive<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    code_hash: String,
) -> StdResult<HandleResponse> {
    set_receiver_hash(&mut deps.storage, &env.message.sender, code_hash);
    let res = HandleResponse {
        messages: vec![],
        log: vec![log("register_status", "success")],
        data: Some(to_binary(&HandleAnswer::RegisterReceive {
            status: Success,
        })?),
    };
    Ok(res)
}

fn insufficient_allowance(allowance: u128, required: u128) -> StdError {
    StdError::generic_err(format!(
        "insufficient allowance: allowance={}, required={}",
        allowance, required
    ))
}

fn use_allowance<S: Storage>(
    storage: &mut S,
    env: &Env,
    owner: &CanonicalAddr,
    spender: &CanonicalAddr,
    amount: u128,
) -> StdResult<()> {
    let mut allowance = read_allowance(storage, owner, spender)?;

    if allowance.is_expired_at(&env.block) {
        return Err(insufficient_allowance(0, amount));
    }
    if let Some(new_allowance) = allowance.amount.checked_sub(amount) {
        allowance.amount = new_allowance;
    } else {
        return Err(insufficient_allowance(allowance.amount, amount));
    }

    write_allowance(storage, owner, spender, allowance)?;

    Ok(())
}

fn try_transfer_from_impl<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: &Env,
    spender: &CanonicalAddr,
    owner: &CanonicalAddr,
    recipient: &CanonicalAddr,
    amount: Uint128,
    memo: Option<String>,
) -> StdResult<()> {
    let raw_amount = amount.u128();

    use_allowance(&mut deps.storage, env, owner, spender, raw_amount)?;

    perform_transfer(&mut deps.storage, owner, recipient, raw_amount)?;

    let symbol = Config::from_storage(&mut deps.storage).constants()?.symbol;

    store_transfer(
        &mut deps.storage,
        owner,
        spender,
        recipient,
        amount,
        symbol,
        memo,
        &env.block,
    )?;

    Ok(())
}

fn try_transfer_from<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: &Env,
    owner: &HumanAddr,
    recipient: &HumanAddr,
    amount: Uint128,
    memo: Option<String>,
) -> StdResult<HandleResponse> {
    let spender = deps.api.canonical_address(&env.message.sender)?;
    let owner = deps.api.canonical_address(owner)?;
    let recipient = deps.api.canonical_address(recipient)?;
    try_transfer_from_impl(deps, env, &spender, &owner, &recipient, amount, memo)?;

    let res = HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::TransferFrom { status: Success })?),
    };
    Ok(res)
}

fn try_batch_transfer_from<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: &Env,
    actions: Vec<batch::TransferFromAction>,
) -> StdResult<HandleResponse> {
    let spender = deps.api.canonical_address(&env.message.sender)?;
    for action in actions {
        let owner = deps.api.canonical_address(&action.owner)?;
        let recipient = deps.api.canonical_address(&action.recipient)?;
        try_transfer_from_impl(
            deps,
            env,
            &spender,
            &owner,
            &recipient,
            action.amount,
            action.memo,
        )?;
    }

    let res = HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::BatchTransferFrom {
            status: Success,
        })?),
    };
    Ok(res)
}

#[allow(clippy::too_many_arguments)]
fn try_send_from_impl<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    messages: &mut Vec<CosmosMsg>,
    spender_canon: &CanonicalAddr, // redundant but more efficient
    owner: HumanAddr,
    recipient: HumanAddr,
    amount: Uint128,
    memo: Option<String>,
    msg: Option<Binary>,
) -> StdResult<()> {
    let owner_canon = deps.api.canonical_address(&owner)?;
    let recipient_canon = deps.api.canonical_address(&recipient)?;
    try_transfer_from_impl(
        deps,
        &env,
        &spender_canon,
        &owner_canon,
        &recipient_canon,
        amount,
        memo.clone(),
    )?;

    try_add_receiver_api_callback(
        &deps.storage,
        messages,
        recipient,
        msg,
        env.message.sender,
        owner,
        amount,
        memo,
    )?;

    Ok(())
}

fn try_send_from<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    owner: HumanAddr,
    recipient: HumanAddr,
    amount: Uint128,
    memo: Option<String>,
    msg: Option<Binary>,
) -> StdResult<HandleResponse> {
    let spender = &env.message.sender;
    let spender_canon = deps.api.canonical_address(spender)?;

    let mut messages = vec![];
    try_send_from_impl(
        deps,
        env,
        &mut messages,
        &spender_canon,
        owner,
        recipient,
        amount,
        memo,
        msg,
    )?;

    let res = HandleResponse {
        messages,
        log: vec![],
        data: Some(to_binary(&HandleAnswer::SendFrom { status: Success })?),
    };
    Ok(res)
}

fn try_batch_send_from<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    actions: Vec<batch::SendFromAction>,
) -> StdResult<HandleResponse> {
    let spender = &env.message.sender;
    let spender_canon = deps.api.canonical_address(spender)?;
    let mut messages = vec![];

    for action in actions {
        try_send_from_impl(
            deps,
            env.clone(),
            &mut messages,
            &spender_canon,
            action.owner,
            action.recipient,
            action.amount,
            action.memo,
            action.msg,
        )?;
    }

    let res = HandleResponse {
        messages,
        log: vec![],
        data: Some(to_binary(&HandleAnswer::BatchSendFrom { status: Success })?),
    };
    Ok(res)
}

fn try_burn_from<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: &Env,
    owner: &HumanAddr,
    amount: Uint128,
    memo: Option<String>,
) -> StdResult<HandleResponse> {
    let config = ReadonlyConfig::from_storage(&deps.storage);
    let constants = config.constants()?;
    if !constants.burn_is_enabled {
        return Err(StdError::generic_err(
            "Burn functionality is not enabled for this token.",
        ));
    }

    let spender = deps.api.canonical_address(&env.message.sender)?;
    let owner = deps.api.canonical_address(owner)?;
    let raw_amount = amount.u128();
    use_allowance(&mut deps.storage, env, &owner, &spender, raw_amount)?;

    // subtract from owner account
    let mut balances = Balances::from_storage(&mut deps.storage);
    let mut account_balance = balances.balance(&owner);

    if let Some(new_balance) = account_balance.checked_sub(raw_amount) {
        account_balance = new_balance;
    } else {
        return Err(StdError::generic_err(format!(
            "insufficient funds to burn: balance={}, required={}",
            account_balance, raw_amount
        )));
    }
    balances.set_account_balance(&owner, account_balance);

    // remove from supply
    let mut config = Config::from_storage(&mut deps.storage);
    let mut total_supply = config.total_supply();
    if let Some(new_total_supply) = total_supply.checked_sub(raw_amount) {
        total_supply = new_total_supply;
    } else {
        return Err(StdError::generic_err(
            "You're trying to burn more than is available in the total supply",
        ));
    }
    config.set_total_supply(total_supply);

    store_burn(
        &mut deps.storage,
        &owner,
        &spender,
        amount,
        constants.symbol,
        memo,
        &env.block,
    )?;

    let res = HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::BurnFrom { status: Success })?),
    };

    Ok(res)
}

fn try_batch_burn_from<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: &Env,
    actions: Vec<batch::BurnFromAction>,
) -> StdResult<HandleResponse> {
    let config = ReadonlyConfig::from_storage(&deps.storage);
    let constants = config.constants()?;
    if !constants.burn_is_enabled {
        return Err(StdError::generic_err(
            "Burn functionality is not enabled for this token.",
        ));
    }

    let spender = deps.api.canonical_address(&env.message.sender)?;

    let mut total_supply = config.total_supply();

    for action in actions {
        let owner = deps.api.canonical_address(&action.owner)?;
        let amount = action.amount.u128();
        use_allowance(&mut deps.storage, env, &owner, &spender, amount)?;

        // subtract from owner account
        let mut balances = Balances::from_storage(&mut deps.storage);
        let mut account_balance = balances.balance(&owner);

        if let Some(new_balance) = account_balance.checked_sub(amount) {
            account_balance = new_balance;
        } else {
            return Err(StdError::generic_err(format!(
                "insufficient funds to burn: balance={}, required={}",
                account_balance, amount
            )));
        }
        balances.set_account_balance(&owner, account_balance);

        // remove from supply
        if let Some(new_total_supply) = total_supply.checked_sub(amount) {
            total_supply = new_total_supply;
        } else {
            return Err(StdError::generic_err(format!(
                "You're trying to burn more than is available in the total supply: {:?}",
                action
            )));
        }

        store_burn(
            &mut deps.storage,
            &owner,
            &spender,
            action.amount,
            constants.symbol.clone(),
            action.memo,
            &env.block,
        )?;
    }

    let mut config = Config::from_storage(&mut deps.storage);
    config.set_total_supply(total_supply);

    let res = HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::BatchBurnFrom { status: Success })?),
    };

    Ok(res)
}

fn try_increase_allowance<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    spender: HumanAddr,
    amount: Uint128,
    expiration: Option<u64>,
) -> StdResult<HandleResponse> {
    let owner_address = deps.api.canonical_address(&env.message.sender)?;
    let spender_address = deps.api.canonical_address(&spender)?;

    let mut allowance = read_allowance(&deps.storage, &owner_address, &spender_address)?;

    // If the previous allowance has expired, reset the allowance.
    // Without this users can take advantage of an expired allowance given to
    // them long ago.
    if allowance.is_expired_at(&env.block) {
        allowance.amount = amount.u128();
        allowance.expiration = None;
    } else {
        allowance.amount = allowance.amount.saturating_add(amount.u128());
    }

    if expiration.is_some() {
        allowance.expiration = expiration;
    }
    let new_amount = allowance.amount;
    write_allowance(
        &mut deps.storage,
        &owner_address,
        &spender_address,
        allowance,
    )?;

    let res = HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::IncreaseAllowance {
            owner: env.message.sender,
            spender,
            allowance: Uint128(new_amount),
        })?),
    };
    Ok(res)
}

fn try_decrease_allowance<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    spender: HumanAddr,
    amount: Uint128,
    expiration: Option<u64>,
) -> StdResult<HandleResponse> {
    let owner_address = deps.api.canonical_address(&env.message.sender)?;
    let spender_address = deps.api.canonical_address(&spender)?;

    let mut allowance = read_allowance(&deps.storage, &owner_address, &spender_address)?;

    // If the previous allowance has expired, reset the allowance.
    // Without this users can take advantage of an expired allowance given to
    // them long ago.
    if allowance.is_expired_at(&env.block) {
        allowance.amount = 0;
        allowance.expiration = None;
    } else {
        allowance.amount = allowance.amount.saturating_sub(amount.u128());
    }

    if expiration.is_some() {
        allowance.expiration = expiration;
    }
    let new_amount = allowance.amount;
    write_allowance(
        &mut deps.storage,
        &owner_address,
        &spender_address,
        allowance,
    )?;

    let res = HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::DecreaseAllowance {
            owner: env.message.sender,
            spender,
            allowance: Uint128(new_amount),
        })?),
    };
    Ok(res)
}

/// Burn tokens
///
/// Remove `amount` tokens from the system irreversibly, from signer account
///
/// @param amount the amount of money to burn
fn try_burn<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    amount: Uint128,
    memo: Option<String>,
) -> StdResult<HandleResponse> {
    let config = ReadonlyConfig::from_storage(&deps.storage);
    let constants = config.constants()?;
    if !constants.burn_is_enabled {
        return Err(StdError::generic_err(
            "Burn functionality is not enabled for this token.",
        ));
    }

    let sender_address = deps.api.canonical_address(&env.message.sender)?;
    let raw_amount = amount.u128();

    let mut balances = Balances::from_storage(&mut deps.storage);
    let mut account_balance = balances.balance(&sender_address);

    if let Some(new_account_balance) = account_balance.checked_sub(raw_amount) {
        account_balance = new_account_balance;
    } else {
        return Err(StdError::generic_err(format!(
            "insufficient funds to burn: balance={}, required={}",
            account_balance, raw_amount
        )));
    }

    balances.set_account_balance(&sender_address, account_balance);

    let mut config = Config::from_storage(&mut deps.storage);
    let mut total_supply = config.total_supply();
    if let Some(new_total_supply) = total_supply.checked_sub(raw_amount) {
        total_supply = new_total_supply;
    } else {
        return Err(StdError::generic_err(
            "You're trying to burn more than is available in the total supply",
        ));
    }
    config.set_total_supply(total_supply);

    store_burn(
        &mut deps.storage,
        &sender_address,
        &sender_address,
        amount,
        constants.symbol,
        memo,
        &env.block,
    )?;

    let res = HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::Burn { status: Success })?),
    };

    Ok(res)
}

fn perform_transfer<T: Storage>(
    store: &mut T,
    from: &CanonicalAddr,
    to: &CanonicalAddr,
    amount: u128,
) -> StdResult<()> {
    let mut balances = Balances::from_storage(store);

    let mut from_balance = balances.balance(from);
    if let Some(new_from_balance) = from_balance.checked_sub(amount) {
        from_balance = new_from_balance;
    } else {
        return Err(StdError::generic_err(format!(
            "insufficient funds: balance={}, required={}",
            from_balance, amount
        )));
    }
    balances.set_account_balance(from, from_balance);

    let mut to_balance = balances.balance(to);
    to_balance = to_balance.checked_add(amount).ok_or_else(|| {
        StdError::generic_err("This tx will literally make them too rich. Try transferring less")
    })?;
    balances.set_account_balance(to, to_balance);

    Ok(())
}

fn is_valid_name(name: &str) -> bool {
    let len = name.len();
    (3..=30).contains(&len)
}

fn is_valid_symbol(symbol: &str) -> bool {
    let len = symbol.len();
    let len_is_valid = (3..=6).contains(&len);

    len_is_valid && symbol.bytes().all(|byte| (b'A'..=b'Z').contains(&byte))
}

// pub fn migrate<S: Storage, A: Api, Q: Querier>(
//     _deps: &mut Extern<S, A, Q>,
//     _env: Env,
//     _msg: MigrateMsg,
// ) -> StdResult<MigrateResponse> {
//     Ok(MigrateResponse::default())
// }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msg::InitConfig;
    use crate::msg::ResponseStatus;
    use cosmwasm_std::testing::*;
    use cosmwasm_std::{
        from_binary, BlockInfo, Coin, ContractInfo, MessageInfo, QueryResponse, WasmMsg,
    };
    use std::any::Any;

    // Helper functions

    fn init_helper() -> (
        StdResult<InitResponse>,
        Extern<MockStorage, MockApi, MockQuerier>,
    ) {
        let mut deps = mock_dependencies(20, &[]);
        let env = mock_env("contract_initializer", &[]);

        let init_msg = InitMsg {
            name: "sec-sec".to_string(),
            symbol: "SECSEC".to_string(),
            decimals: 8,
            prng_seed: Binary::from("lolz fun yay".as_bytes()),
            config: None,
        };

        (init(&mut deps, env, init_msg), deps)
    }

    fn init_helper_with_config(
        enable_deposit: bool,
        enable_redeem: bool,
        enable_mint: bool,
        enable_burn: bool,
        contract_bal: u128,
    ) -> (
        StdResult<InitResponse>,
        Extern<MockStorage, MockApi, MockQuerier>,
    ) {
        let mut deps = mock_dependencies(
            20,
            &[Coin {
                denom: "uscrt".to_string(),
                amount: Uint128(contract_bal),
            }],
        );

        let env = mock_env("contract_initializer", &[]);
        let init_config: InitConfig = from_binary(&Binary::from(
            format!(
                "{{\"public_total_supply\":false,
            \"enable_deposit\":{},
            \"enable_redeem\":{},
            \"enable_mint\":{},
            \"enable_burn\":{}}}",
                enable_deposit, enable_redeem, enable_mint, enable_burn
            )
            .as_bytes(),
        ))
        .unwrap();
        let init_msg = InitMsg {
            name: "sec-sec".to_string(),
            symbol: "SECSEC".to_string(),
            decimals: 8,
            prng_seed: Binary::from("lolz fun yay".as_bytes()),
            config: Some(init_config),
        };

        (init(&mut deps, env, init_msg), deps)
    }

    fn extract_error_msg<T: Any>(error: StdResult<T>) -> String {
        match error {
            Ok(response) => {
                let bin_err = (&response as &dyn Any)
                    .downcast_ref::<QueryResponse>()
                    .expect("An error was expected, but no error could be extracted");
                match from_binary(bin_err).unwrap() {
                    QueryAnswer::ViewingKeyError { msg } => msg,
                    _ => panic!("Unexpected query answer"),
                }
            }
            Err(err) => match err {
                StdError::GenericErr { msg, .. } => msg,
                _ => panic!("Unexpected result from init"),
            },
        }
    }

    fn ensure_success(handle_result: HandleResponse) -> bool {
        let handle_result: HandleAnswer = from_binary(&handle_result.data.unwrap()).unwrap();

        match handle_result {
            HandleAnswer::Transfer { status }
            | HandleAnswer::Send { status }
            | HandleAnswer::Burn { status }
            | HandleAnswer::RegisterReceive { status }
            | HandleAnswer::SetViewingKey { status }
            | HandleAnswer::TransferFrom { status }
            | HandleAnswer::SendFrom { status }
            | HandleAnswer::BurnFrom { status }
            | HandleAnswer::Mint { status } => {
                matches!(status, ResponseStatus::Success { .. })
            }
            _ => panic!(
                "HandleAnswer not supported for success extraction: {:?}",
                handle_result
            ),
        }
    }

    // Init tests

    #[test]
    fn test_init_sanity() {
        let (init_result, mut deps) = init_helper_with_config(true, true, true, true, 0);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // Mint
        let handle_msg = HandleMsg::Mint {
            recipient: HumanAddr("lebron".to_string()),
            amount: Uint128(5000),
            memo: None,
            padding: None,
        };
        handle(&mut deps, mock_env("contract_initializer", &[]), handle_msg).unwrap();

        let config = ReadonlyConfig::from_storage(&deps.storage);
        let constants = config.constants().unwrap();
        assert_eq!(config.total_supply(), 5000);
        assert_eq!(constants.name, "sec-sec".to_string());
        assert_eq!(constants.symbol, "SECSEC".to_string());
        assert_eq!(constants.decimals, 8);
        assert_eq!(
            constants.prng_seed,
            sha_256("lolz fun yay".to_owned().as_bytes())
        );
        assert_eq!(constants.total_supply_is_public, false);
    }

    #[test]
    fn test_init_with_config_sanity() {
        let (init_result, mut deps) = init_helper_with_config(true, true, true, true, 0);
        assert_eq!(init_result.unwrap(), InitResponse::default());

        // Mint
        let handle_msg = HandleMsg::Mint {
            recipient: HumanAddr("lebron".to_string()),
            amount: Uint128(5000),
            memo: None,
            padding: None,
        };
        handle(&mut deps, mock_env("contract_initializer", &[]), handle_msg).unwrap();

        let config = ReadonlyConfig::from_storage(&deps.storage);
        let constants = config.constants().unwrap();
        assert_eq!(config.total_supply(), 5000);
        assert_eq!(constants.name, "sec-sec".to_string());
        assert_eq!(constants.symbol, "SECSEC".to_string());
        assert_eq!(constants.decimals, 8);
        assert_eq!(
            constants.prng_seed,
            sha_256("lolz fun yay".to_owned().as_bytes())
        );
        assert_eq!(constants.total_supply_is_public, false);
        assert_eq!(constants.deposit_is_enabled, true);
        assert_eq!(constants.redeem_is_enabled, true);
        assert_eq!(constants.mint_is_enabled, true);
        assert_eq!(constants.burn_is_enabled, true);
    }

    // Handle tests

    #[test]
    fn test_handle_transfer() {
        let (init_result, mut deps) = init_helper_with_config(true, true, true, true, 0);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // Mint
        let handle_msg = HandleMsg::Mint {
            recipient: HumanAddr("bob".to_string()),
            amount: Uint128(5000),
            memo: None,
            padding: None,
        };
        handle(&mut deps, mock_env("contract_initializer", &[]), handle_msg).unwrap();

        let handle_msg = HandleMsg::Transfer {
            recipient: HumanAddr("alice".to_string()),
            amount: Uint128(1000),
            memo: None,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        let result = handle_result.unwrap();
        assert!(ensure_success(result));
        let bob_canonical = deps
            .api
            .canonical_address(&HumanAddr("bob".to_string()))
            .unwrap();
        let alice_canonical = deps
            .api
            .canonical_address(&HumanAddr("alice".to_string()))
            .unwrap();
        let balances = ReadonlyBalances::from_storage(&deps.storage);
        assert_eq!(5000 - 1000, balances.account_amount(&bob_canonical));
        assert_eq!(1000, balances.account_amount(&alice_canonical));

        let handle_msg = HandleMsg::Transfer {
            recipient: HumanAddr("alice".to_string()),
            amount: Uint128(10000),
            memo: None,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("insufficient funds"));
    }

    #[test]
    fn test_handle_send() {
        let (init_result, mut deps) = init_helper_with_config(true, true, true, true, 0);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // Mint
        let handle_msg = HandleMsg::Mint {
            recipient: HumanAddr("bob".to_string()),
            amount: Uint128(5000),
            memo: None,
            padding: None,
        };
        handle(&mut deps, mock_env("contract_initializer", &[]), handle_msg).unwrap();

        let handle_msg = HandleMsg::RegisterReceive {
            code_hash: "this_is_a_hash_of_a_code".to_string(),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("contract", &[]), handle_msg);
        let result = handle_result.unwrap();
        assert!(ensure_success(result));

        let handle_msg = HandleMsg::Send {
            recipient: HumanAddr("contract".to_string()),
            amount: Uint128(100),
            memo: Some("my memo".to_string()),
            padding: None,
            msg: Some(to_binary("hey hey you you").unwrap()),
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        let result = handle_result.unwrap();
        assert!(ensure_success(result.clone()));
        assert!(result.messages.contains(&CosmosMsg::Wasm(WasmMsg::Execute {
            contract_addr: HumanAddr("contract".to_string()),
            callback_code_hash: "this_is_a_hash_of_a_code".to_string(),
            msg: Snip20ReceiveMsg::new(
                HumanAddr("bob".to_string()),
                HumanAddr("bob".to_string()),
                Uint128(100),
                Some("my memo".to_string()),
                Some(to_binary("hey hey you you").unwrap())
            )
            .into_binary()
            .unwrap(),
            send: vec![]
        })));
    }

    #[test]
    fn test_handle_register_receive() {
        let (init_result, mut deps) = init_helper();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = HandleMsg::RegisterReceive {
            code_hash: "this_is_a_hash_of_a_code".to_string(),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("contract", &[]), handle_msg);
        let result = handle_result.unwrap();
        assert!(ensure_success(result));

        let hash = get_receiver_hash(&deps.storage, &HumanAddr("contract".to_string()))
            .unwrap()
            .unwrap();
        assert_eq!(hash, "this_is_a_hash_of_a_code".to_string());
    }

    #[test]
    fn test_handle_create_viewing_key() {
        let (init_result, mut deps) = init_helper();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = HandleMsg::CreateViewingKey {
            entropy: "".to_string(),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );
        let answer: HandleAnswer = from_binary(&handle_result.unwrap().data.unwrap()).unwrap();

        let key = match answer {
            HandleAnswer::CreateViewingKey { key } => key,
            _ => panic!("NOPE"),
        };
        let bob_canonical = deps
            .api
            .canonical_address(&HumanAddr("bob".to_string()))
            .unwrap();
        let saved_vk = read_viewing_key(&deps.storage, &bob_canonical).unwrap();
        assert!(key.check_viewing_key(saved_vk.as_slice()));
    }

    #[test]
    fn test_handle_set_viewing_key() {
        let (init_result, mut deps) = init_helper();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // Set VK
        let handle_msg = HandleMsg::SetViewingKey {
            key: "hi lol".to_string(),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        let unwrapped_result: HandleAnswer =
            from_binary(&handle_result.unwrap().data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&unwrapped_result).unwrap(),
            to_binary(&HandleAnswer::SetViewingKey {
                status: ResponseStatus::Success
            })
            .unwrap(),
        );

        // Set valid VK
        let actual_vk = ViewingKey("x".to_string().repeat(VIEWING_KEY_SIZE));
        let handle_msg = HandleMsg::SetViewingKey {
            key: actual_vk.0.clone(),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        let unwrapped_result: HandleAnswer =
            from_binary(&handle_result.unwrap().data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&unwrapped_result).unwrap(),
            to_binary(&HandleAnswer::SetViewingKey { status: Success }).unwrap(),
        );
        let bob_canonical = deps
            .api
            .canonical_address(&HumanAddr("bob".to_string()))
            .unwrap();
        let saved_vk = read_viewing_key(&deps.storage, &bob_canonical).unwrap();
        assert!(actual_vk.check_viewing_key(&saved_vk));
    }

    #[test]
    fn test_handle_transfer_from() {
        let (init_result, mut deps) = init_helper_with_config(true, true, true, true, 0);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // Mint
        let handle_msg = HandleMsg::Mint {
            recipient: HumanAddr("bob".to_string()),
            amount: Uint128(5000),
            memo: None,
            padding: None,
        };
        handle(&mut deps, mock_env("contract_initializer", &[]), handle_msg).unwrap();

        // Transfer before allowance
        let handle_msg = HandleMsg::TransferFrom {
            owner: HumanAddr("bob".to_string()),
            recipient: HumanAddr("alice".to_string()),
            amount: Uint128(2500),
            memo: None,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("insufficient allowance"));

        // Transfer more than allowance
        let handle_msg = HandleMsg::IncreaseAllowance {
            spender: HumanAddr("alice".to_string()),
            amount: Uint128(2000),
            padding: None,
            expiration: Some(1_571_797_420),
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );
        let handle_msg = HandleMsg::TransferFrom {
            owner: HumanAddr("bob".to_string()),
            recipient: HumanAddr("alice".to_string()),
            amount: Uint128(2500),
            memo: None,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("insufficient allowance"));

        // Transfer after allowance expired
        let handle_msg = HandleMsg::TransferFrom {
            owner: HumanAddr("bob".to_string()),
            recipient: HumanAddr("alice".to_string()),
            amount: Uint128(2000),
            memo: None,
            padding: None,
        };
        let handle_result = handle(
            &mut deps,
            Env {
                block: BlockInfo {
                    height: 12_345,
                    time: 1_571_797_420,
                    chain_id: "cosmos-testnet-14002".to_string(),
                },
                message: MessageInfo {
                    sender: HumanAddr("bob".to_string()),
                    sent_funds: vec![],
                },
                contract: ContractInfo {
                    address: HumanAddr::from(MOCK_CONTRACT_ADDR),
                },
                contract_key: Some("".to_string()),
                contract_code_hash: "".to_string(),
            },
            handle_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("insufficient allowance"));

        // Sanity check
        let handle_msg = HandleMsg::TransferFrom {
            owner: HumanAddr("bob".to_string()),
            recipient: HumanAddr("alice".to_string()),
            amount: Uint128(2000),
            memo: None,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );
        let bob_canonical = deps
            .api
            .canonical_address(&HumanAddr("bob".to_string()))
            .unwrap();
        let alice_canonical = deps
            .api
            .canonical_address(&HumanAddr("alice".to_string()))
            .unwrap();
        let bob_balance = crate::state::ReadonlyBalances::from_storage(&deps.storage)
            .account_amount(&bob_canonical);
        let alice_balance = crate::state::ReadonlyBalances::from_storage(&deps.storage)
            .account_amount(&alice_canonical);
        assert_eq!(bob_balance, 5000 - 2000);
        assert_eq!(alice_balance, 2000);
        let total_supply = ReadonlyConfig::from_storage(&deps.storage).total_supply();
        assert_eq!(total_supply, 5000);

        // Second send more than allowance
        let handle_msg = HandleMsg::TransferFrom {
            owner: HumanAddr("bob".to_string()),
            recipient: HumanAddr("alice".to_string()),
            amount: Uint128(1),
            memo: None,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("insufficient allowance"));
    }

    #[test]
    fn test_handle_send_from() {
        let (init_result, mut deps) = init_helper_with_config(true, true, true, true, 0);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // Mint
        let handle_msg = HandleMsg::Mint {
            recipient: HumanAddr("bob".to_string()),
            amount: Uint128(5000),
            memo: None,
            padding: None,
        };
        handle(&mut deps, mock_env("contract_initializer", &[]), handle_msg).unwrap();

        // Send before allowance
        let handle_msg = HandleMsg::SendFrom {
            owner: HumanAddr("bob".to_string()),
            recipient: HumanAddr("alice".to_string()),
            amount: Uint128(2500),
            memo: None,
            msg: None,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("insufficient allowance"));

        // Send more than allowance
        let handle_msg = HandleMsg::IncreaseAllowance {
            spender: HumanAddr("alice".to_string()),
            amount: Uint128(2000),
            padding: None,
            expiration: None,
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );
        let handle_msg = HandleMsg::SendFrom {
            owner: HumanAddr("bob".to_string()),
            recipient: HumanAddr("alice".to_string()),
            amount: Uint128(2500),
            memo: None,
            msg: None,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("insufficient allowance"));

        // Sanity check
        let handle_msg = HandleMsg::RegisterReceive {
            code_hash: "lolz".to_string(),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("contract", &[]), handle_msg);
        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );
        let send_msg = Binary::from(r#"{ "some_msg": { "some_key": "some_val" } }"#.as_bytes());
        let snip20_msg = Snip20ReceiveMsg::new(
            HumanAddr("alice".to_string()),
            HumanAddr("bob".to_string()),
            Uint128(2000),
            Some("my memo".to_string()),
            Some(send_msg.clone()),
        );
        let handle_msg = HandleMsg::SendFrom {
            owner: HumanAddr("bob".to_string()),
            recipient: HumanAddr("contract".to_string()),
            amount: Uint128(2000),
            memo: Some("my memo".to_string()),
            msg: Some(send_msg),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );
        assert!(handle_result.unwrap().messages.contains(
            &snip20_msg
                .into_cosmos_msg("lolz".to_string(), HumanAddr("contract".to_string()))
                .unwrap()
        ));
        let bob_canonical = deps
            .api
            .canonical_address(&HumanAddr("bob".to_string()))
            .unwrap();
        let contract_canonical = deps
            .api
            .canonical_address(&HumanAddr("contract".to_string()))
            .unwrap();
        let bob_balance = crate::state::ReadonlyBalances::from_storage(&deps.storage)
            .account_amount(&bob_canonical);
        let contract_balance = crate::state::ReadonlyBalances::from_storage(&deps.storage)
            .account_amount(&contract_canonical);
        assert_eq!(bob_balance, 5000 - 2000);
        assert_eq!(contract_balance, 2000);
        let total_supply = ReadonlyConfig::from_storage(&deps.storage).total_supply();
        assert_eq!(total_supply, 5000);

        // Second send more than allowance
        let handle_msg = HandleMsg::SendFrom {
            owner: HumanAddr("bob".to_string()),
            recipient: HumanAddr("alice".to_string()),
            amount: Uint128(1),
            memo: None,
            msg: None,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("insufficient allowance"));
    }

    #[test]
    fn test_handle_burn_from() {
        let (init_result, mut deps) = init_helper_with_config(true, true, true, true, 0);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // Mint
        let handle_msg = HandleMsg::Mint {
            recipient: HumanAddr("bob".to_string()),
            amount: Uint128(10000),
            memo: None,
            padding: None,
        };
        handle(&mut deps, mock_env("contract_initializer", &[]), handle_msg).unwrap();

        let (init_result_for_failure, mut deps_for_failure) = init_helper();
        assert!(
            init_result_for_failure.is_ok(),
            "Init failed: {}",
            init_result_for_failure.err().unwrap()
        );
        // test when burn disabled
        let handle_msg = HandleMsg::BurnFrom {
            owner: HumanAddr("bob".to_string()),
            amount: Uint128(2500),
            memo: None,
            padding: None,
        };
        let handle_result = handle(&mut deps_for_failure, mock_env("alice", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Burn functionality is not enabled for this token."));

        // Burn before allowance
        let handle_msg = HandleMsg::BurnFrom {
            owner: HumanAddr("bob".to_string()),
            amount: Uint128(2500),
            memo: None,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("insufficient allowance"));

        // Burn more than allowance
        let handle_msg = HandleMsg::IncreaseAllowance {
            spender: HumanAddr("alice".to_string()),
            amount: Uint128(2000),
            padding: None,
            expiration: None,
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );
        let handle_msg = HandleMsg::BurnFrom {
            owner: HumanAddr("bob".to_string()),
            amount: Uint128(2500),
            memo: None,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("insufficient allowance"));

        // Sanity check
        let handle_msg = HandleMsg::BurnFrom {
            owner: HumanAddr("bob".to_string()),
            amount: Uint128(2000),
            memo: None,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );
        let bob_canonical = deps
            .api
            .canonical_address(&HumanAddr("bob".to_string()))
            .unwrap();
        let bob_balance = crate::state::ReadonlyBalances::from_storage(&deps.storage)
            .account_amount(&bob_canonical);
        assert_eq!(bob_balance, 10000 - 2000);
        let total_supply = ReadonlyConfig::from_storage(&deps.storage).total_supply();
        assert_eq!(total_supply, 10000 - 2000);

        // Second burn more than allowance
        let handle_msg = HandleMsg::BurnFrom {
            owner: HumanAddr("bob".to_string()),
            amount: Uint128(1),
            memo: None,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("insufficient allowance"));
    }

    #[test]
    fn test_handle_batch_burn_from() {
        let (init_result, mut deps) = init_helper_with_config(true, true, true, true, 0);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // Mint
        let handle_msg = HandleMsg::BatchMint {
            actions: vec![
                batch::MintAction {
                    recipient: HumanAddr("bob".to_string()),
                    amount: Uint128(10000),
                    memo: None,
                },
                batch::MintAction {
                    recipient: HumanAddr("jerry".to_string()),
                    amount: Uint128(10000),
                    memo: None,
                },
                batch::MintAction {
                    recipient: HumanAddr("mike".to_string()),
                    amount: Uint128(10000),
                    memo: None,
                },
            ],
            padding: None,
        };
        handle(&mut deps, mock_env("contract_initializer", &[]), handle_msg).unwrap();

        let (init_result_for_failure, mut deps_for_failure) = init_helper();
        assert!(
            init_result_for_failure.is_ok(),
            "Init failed: {}",
            init_result_for_failure.err().unwrap()
        );
        // test when burn disabled
        let actions: Vec<_> = ["bob", "jerry", "mike"]
            .iter()
            .map(|name| batch::BurnFromAction {
                owner: HumanAddr(name.to_string()),
                amount: Uint128(2500),
                memo: None,
            })
            .collect();
        let handle_msg = HandleMsg::BatchBurnFrom {
            actions,
            padding: None,
        };
        let handle_result = handle(
            &mut deps_for_failure,
            mock_env("alice", &[]),
            handle_msg.clone(),
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Burn functionality is not enabled for this token."));

        // Burn before allowance
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("insufficient allowance"));

        // Burn more than allowance
        let allowance_size = 2000;
        for name in &["bob", "jerry", "mike"] {
            let handle_msg = HandleMsg::IncreaseAllowance {
                spender: HumanAddr("alice".to_string()),
                amount: Uint128(allowance_size),
                padding: None,
                expiration: None,
            };
            let handle_result = handle(&mut deps, mock_env(*name, &[]), handle_msg);
            assert!(
                handle_result.is_ok(),
                "handle() failed: {}",
                handle_result.err().unwrap()
            );
            let handle_msg = HandleMsg::BurnFrom {
                owner: HumanAddr(name.to_string()),
                amount: Uint128(2500),
                memo: None,
                padding: None,
            };
            let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
            let error = extract_error_msg(handle_result);
            assert!(error.contains("insufficient allowance"));
        }

        // Burn some of the allowance
        let actions: Vec<_> = [("bob", 200_u128), ("jerry", 300), ("mike", 400)]
            .iter()
            .map(|(name, amount)| batch::BurnFromAction {
                owner: HumanAddr(name.to_string()),
                amount: Uint128(*amount),
                memo: None,
            })
            .collect();

        let handle_msg = HandleMsg::BatchBurnFrom {
            actions,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );
        for (name, amount) in &[("bob", 200_u128), ("jerry", 300), ("mike", 400)] {
            let name_canon = deps
                .api
                .canonical_address(&HumanAddr(name.to_string()))
                .unwrap();
            let balance = crate::state::ReadonlyBalances::from_storage(&deps.storage)
                .account_amount(&name_canon);
            assert_eq!(balance, 10000 - amount);
        }
        let total_supply = ReadonlyConfig::from_storage(&deps.storage).total_supply();
        assert_eq!(total_supply, 10000 * 3 - (200 + 300 + 400));

        // Burn the rest of the allowance
        let actions: Vec<_> = [("bob", 200_u128), ("jerry", 300), ("mike", 400)]
            .iter()
            .map(|(name, amount)| batch::BurnFromAction {
                owner: HumanAddr(name.to_string()),
                amount: Uint128(allowance_size - *amount),
                memo: None,
            })
            .collect();

        let handle_msg = HandleMsg::BatchBurnFrom {
            actions,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );
        for name in &["bob", "jerry", "mike"] {
            let name_canon = deps
                .api
                .canonical_address(&HumanAddr(name.to_string()))
                .unwrap();
            let balance = crate::state::ReadonlyBalances::from_storage(&deps.storage)
                .account_amount(&name_canon);
            assert_eq!(balance, 10000 - allowance_size);
        }
        let total_supply = ReadonlyConfig::from_storage(&deps.storage).total_supply();
        assert_eq!(total_supply, 3 * (10000 - allowance_size));

        // Second burn more than allowance
        let actions: Vec<_> = ["bob", "jerry", "mike"]
            .iter()
            .map(|name| batch::BurnFromAction {
                owner: HumanAddr(name.to_string()),
                amount: Uint128(1),
                memo: None,
            })
            .collect();
        let handle_msg = HandleMsg::BatchBurnFrom {
            actions,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("insufficient allowance"));
    }

    #[test]
    fn test_handle_decrease_allowance() {
        let (init_result, mut deps) = init_helper();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = HandleMsg::DecreaseAllowance {
            spender: HumanAddr("alice".to_string()),
            amount: Uint128(2000),
            padding: None,
            expiration: None,
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );

        let bob_canonical = deps
            .api
            .canonical_address(&HumanAddr("bob".to_string()))
            .unwrap();
        let alice_canonical = deps
            .api
            .canonical_address(&HumanAddr("alice".to_string()))
            .unwrap();

        let allowance = read_allowance(&deps.storage, &bob_canonical, &alice_canonical).unwrap();
        assert_eq!(
            allowance,
            crate::state::Allowance {
                amount: 0,
                expiration: None
            }
        );

        let handle_msg = HandleMsg::IncreaseAllowance {
            spender: HumanAddr("alice".to_string()),
            amount: Uint128(2000),
            padding: None,
            expiration: None,
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );

        let handle_msg = HandleMsg::DecreaseAllowance {
            spender: HumanAddr("alice".to_string()),
            amount: Uint128(50),
            padding: None,
            expiration: None,
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );

        let allowance = read_allowance(&deps.storage, &bob_canonical, &alice_canonical).unwrap();
        assert_eq!(
            allowance,
            crate::state::Allowance {
                amount: 1950,
                expiration: None
            }
        );
    }

    #[test]
    fn test_handle_increase_allowance() {
        let (init_result, mut deps) = init_helper();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = HandleMsg::IncreaseAllowance {
            spender: HumanAddr("alice".to_string()),
            amount: Uint128(2000),
            padding: None,
            expiration: None,
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );

        let bob_canonical = deps
            .api
            .canonical_address(&HumanAddr("bob".to_string()))
            .unwrap();
        let alice_canonical = deps
            .api
            .canonical_address(&HumanAddr("alice".to_string()))
            .unwrap();

        let allowance = read_allowance(&deps.storage, &bob_canonical, &alice_canonical).unwrap();
        assert_eq!(
            allowance,
            crate::state::Allowance {
                amount: 2000,
                expiration: None
            }
        );

        let handle_msg = HandleMsg::IncreaseAllowance {
            spender: HumanAddr("alice".to_string()),
            amount: Uint128(2000),
            padding: None,
            expiration: None,
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );

        let allowance = read_allowance(&deps.storage, &bob_canonical, &alice_canonical).unwrap();
        assert_eq!(
            allowance,
            crate::state::Allowance {
                amount: 4000,
                expiration: None
            }
        );
    }

    #[test]
    fn test_handle_burn() {
        let (init_result, mut deps) = init_helper_with_config(true, true, true, true, 0);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // Mint
        let handle_msg = HandleMsg::Mint {
            recipient: HumanAddr("lebron".to_string()),
            amount: Uint128(10000),
            memo: None,
            padding: None,
        };
        handle(&mut deps, mock_env("contract_initializer", &[]), handle_msg).unwrap();

        let (init_result_for_failure, mut deps_for_failure) = init_helper();
        assert!(
            init_result_for_failure.is_ok(),
            "Init failed: {}",
            init_result_for_failure.err().unwrap()
        );
        // test when burn disabled
        let handle_msg = HandleMsg::Burn {
            amount: Uint128(100),
            memo: None,
            padding: None,
        };
        let handle_result = handle(&mut deps_for_failure, mock_env("lebron", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Burn functionality is not enabled for this token."));

        let supply = ReadonlyConfig::from_storage(&deps.storage).total_supply();
        let burn_amount: u128 = 100;
        let handle_msg = HandleMsg::Burn {
            amount: Uint128(burn_amount),
            memo: None,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("lebron", &[]), handle_msg);
        assert!(
            handle_result.is_ok(),
            "Pause handle failed: {}",
            handle_result.err().unwrap()
        );

        let new_supply = ReadonlyConfig::from_storage(&deps.storage).total_supply();
        assert_eq!(new_supply, supply - burn_amount);
    }

    #[test]
    fn test_handle_mint() {
        let (init_result, mut deps) = init_helper_with_config(false, false, true, false, 0);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let (init_result_for_failure, mut deps_for_failure) = init_helper();
        assert!(
            init_result_for_failure.is_ok(),
            "Init failed: {}",
            init_result_for_failure.err().unwrap()
        );
        // try to mint when mint is disabled
        let mint_amount: u128 = 100;
        let handle_msg = HandleMsg::Mint {
            recipient: HumanAddr("lebron".to_string()),
            amount: Uint128(mint_amount),
            memo: None,
            padding: None,
        };
        let handle_result = handle(
            &mut deps_for_failure,
            mock_env("contract_initializer", &[]),
            handle_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Mint functionality is not enabled for this token"));

        let supply = ReadonlyConfig::from_storage(&deps.storage).total_supply();
        let mint_amount: u128 = 100;
        let handle_msg = HandleMsg::Mint {
            recipient: HumanAddr("lebron".to_string()),
            amount: Uint128(mint_amount),
            memo: None,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("contract_initializer", &[]), handle_msg);
        assert!(
            handle_result.is_ok(),
            "Pause handle failed: {}",
            handle_result.err().unwrap()
        );

        let new_supply = ReadonlyConfig::from_storage(&deps.storage).total_supply();
        assert_eq!(new_supply, supply + mint_amount);
    }

    // Query tests

    #[test]
    fn test_authenticated_queries() {
        let (init_result, mut deps) = init_helper_with_config(true, true, true, true, 0);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // Mint
        let handle_msg = HandleMsg::Mint {
            recipient: HumanAddr("giannis".to_string()),
            amount: Uint128(5000),
            memo: None,
            padding: None,
        };
        handle(&mut deps, mock_env("contract_initializer", &[]), handle_msg).unwrap();

        let no_vk_yet_query_msg = QueryMsg::Balance {
            address: HumanAddr("giannis".to_string()),
            key: "no_vk_yet".to_string(),
        };
        let query_result = query(&deps, no_vk_yet_query_msg);
        let error = extract_error_msg(query_result);
        assert_eq!(
            error,
            "Wrong viewing key for this address or viewing key not set".to_string()
        );

        let create_vk_msg = HandleMsg::CreateViewingKey {
            entropy: "34".to_string(),
            padding: None,
        };
        let handle_response = handle(&mut deps, mock_env("giannis", &[]), create_vk_msg).unwrap();
        let vk = match from_binary(&handle_response.data.unwrap()).unwrap() {
            HandleAnswer::CreateViewingKey { key } => key,
            _ => panic!("Unexpected result from handle"),
        };

        let query_balance_msg = QueryMsg::Balance {
            address: HumanAddr("giannis".to_string()),
            key: vk.0,
        };

        let query_response = query(&deps, query_balance_msg).unwrap();
        let balance = match from_binary(&query_response).unwrap() {
            QueryAnswer::Balance { amount } => amount,
            _ => panic!("Unexpected result from query"),
        };
        assert_eq!(balance, Uint128(5000));

        let wrong_vk_query_msg = QueryMsg::Balance {
            address: HumanAddr("giannis".to_string()),
            key: "wrong_vk".to_string(),
        };
        let query_result = query(&deps, wrong_vk_query_msg);
        let error = extract_error_msg(query_result);
        assert_eq!(
            error,
            "Wrong viewing key for this address or viewing key not set".to_string()
        );
    }

    #[test]
    fn test_query_contract_status() {
        let (init_result, deps) = init_helper();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let query_msg = QueryMsg::ContractStatus {};
        let query_result = query(&deps, query_msg);
        assert!(
            query_result.is_ok(),
            "Init failed: {}",
            query_result.err().unwrap()
        );
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::ContractStatus { status } => {
                assert_eq!(status, ContractStatusLevel::NormalRun);
            }
            _ => panic!("unexpected"),
        }
    }

    #[test]
    fn test_query_token_info() {
        let init_name = "sec-sec".to_string();
        let init_symbol = "SECSEC".to_string();
        let init_decimals = 8;
        let init_config: InitConfig = from_binary(&Binary::from(
            r#"{ "public_total_supply": true }"#.as_bytes(),
        ))
        .unwrap();
        let mut deps = mock_dependencies(20, &[]);
        let env = mock_env("instantiator", &[]);
        let init_msg = InitMsg {
            name: init_name.clone(),
            symbol: init_symbol.clone(),
            decimals: init_decimals.clone(),
            prng_seed: Binary::from("lolz fun yay".as_bytes()),
            config: Some(init_config),
        };
        let init_result = init(&mut deps, env, init_msg);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let query_msg = QueryMsg::TokenInfo {};
        let query_result = query(&deps, query_msg);
        assert!(
            query_result.is_ok(),
            "Init failed: {}",
            query_result.err().unwrap()
        );
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::TokenInfo {
                name,
                symbol,
                decimals,
                total_supply,
            } => {
                assert_eq!(name, init_name);
                assert_eq!(symbol, init_symbol);
                assert_eq!(decimals, init_decimals);
                assert_eq!(total_supply, Some(Uint128(0)));
            }
            _ => panic!("unexpected"),
        }
    }

    #[test]
    fn test_query_token_config() {
        let init_name = "sec-sec".to_string();
        let init_symbol = "SECSEC".to_string();
        let init_decimals = 8;
        let init_config: InitConfig = from_binary(&Binary::from(
            format!(
                "{{\"public_total_supply\":{},
            \"enable_deposit\":{},
            \"enable_redeem\":{},
            \"enable_mint\":{},
            \"enable_burn\":{}}}",
                true, false, false, true, false
            )
            .as_bytes(),
        ))
        .unwrap();
        let mut deps = mock_dependencies(20, &[]);
        let env = mock_env("instantiator", &[]);
        let init_msg = InitMsg {
            name: init_name.clone(),
            symbol: init_symbol.clone(),
            decimals: init_decimals.clone(),
            prng_seed: Binary::from("lolz fun yay".as_bytes()),
            config: Some(init_config),
        };
        let init_result = init(&mut deps, env, init_msg);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let query_msg = QueryMsg::TokenConfig {};
        let query_result = query(&deps, query_msg);
        assert!(
            query_result.is_ok(),
            "Init failed: {}",
            query_result.err().unwrap()
        );
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::TokenConfig {
                public_total_supply,
                deposit_enabled,
                redeem_enabled,
                mint_enabled,
                burn_enabled,
            } => {
                assert_eq!(public_total_supply, true);
                assert_eq!(deposit_enabled, false);
                assert_eq!(redeem_enabled, false);
                assert_eq!(mint_enabled, true);
                assert_eq!(burn_enabled, false);
            }
            _ => panic!("unexpected"),
        }
    }

    #[test]
    fn test_query_allowance() {
        let (init_result, mut deps) = init_helper();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = HandleMsg::IncreaseAllowance {
            spender: HumanAddr("lebron".to_string()),
            amount: Uint128(2000),
            padding: None,
            expiration: None,
        };
        let handle_result = handle(&mut deps, mock_env("giannis", &[]), handle_msg);
        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );

        let vk1 = ViewingKey("key1".to_string());
        let vk2 = ViewingKey("key2".to_string());

        let query_msg = QueryMsg::Allowance {
            owner: HumanAddr("giannis".to_string()),
            spender: HumanAddr("lebron".to_string()),
            key: vk1.0.clone(),
        };
        let query_result = query(&deps, query_msg);
        assert!(
            query_result.is_ok(),
            "Query failed: {}",
            query_result.err().unwrap()
        );
        let error = extract_error_msg(query_result);
        assert!(error.contains("Wrong viewing key"));

        let handle_msg = HandleMsg::SetViewingKey {
            key: vk1.0.clone(),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("lebron", &[]), handle_msg);
        let unwrapped_result: HandleAnswer =
            from_binary(&handle_result.unwrap().data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&unwrapped_result).unwrap(),
            to_binary(&HandleAnswer::SetViewingKey {
                status: ResponseStatus::Success
            })
            .unwrap(),
        );

        let handle_msg = HandleMsg::SetViewingKey {
            key: vk2.0.clone(),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("giannis", &[]), handle_msg);
        let unwrapped_result: HandleAnswer =
            from_binary(&handle_result.unwrap().data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&unwrapped_result).unwrap(),
            to_binary(&HandleAnswer::SetViewingKey {
                status: ResponseStatus::Success
            })
            .unwrap(),
        );

        let query_msg = QueryMsg::Allowance {
            owner: HumanAddr("giannis".to_string()),
            spender: HumanAddr("lebron".to_string()),
            key: vk1.0.clone(),
        };
        let query_result = query(&deps, query_msg);
        let allowance = match from_binary(&query_result.unwrap()).unwrap() {
            QueryAnswer::Allowance { allowance, .. } => allowance,
            _ => panic!("Unexpected"),
        };
        assert_eq!(allowance, Uint128(2000));

        let query_msg = QueryMsg::Allowance {
            owner: HumanAddr("giannis".to_string()),
            spender: HumanAddr("lebron".to_string()),
            key: vk2.0.clone(),
        };
        let query_result = query(&deps, query_msg);
        let allowance = match from_binary(&query_result.unwrap()).unwrap() {
            QueryAnswer::Allowance { allowance, .. } => allowance,
            _ => panic!("Unexpected"),
        };
        assert_eq!(allowance, Uint128(2000));

        let query_msg = QueryMsg::Allowance {
            owner: HumanAddr("lebron".to_string()),
            spender: HumanAddr("giannis".to_string()),
            key: vk2.0.clone(),
        };
        let query_result = query(&deps, query_msg);
        let allowance = match from_binary(&query_result.unwrap()).unwrap() {
            QueryAnswer::Allowance { allowance, .. } => allowance,
            _ => panic!("Unexpected"),
        };
        assert_eq!(allowance, Uint128(0));
    }

    #[test]
    fn test_query_balance() {
        let (init_result, mut deps) = init_helper_with_config(true, true, true, true, 0);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // Mint
        let handle_msg = HandleMsg::Mint {
            recipient: HumanAddr("bob".to_string()),
            amount: Uint128(5000),
            memo: None,
            padding: None,
        };
        handle(&mut deps, mock_env("contract_initializer", &[]), handle_msg).unwrap();

        let handle_msg = HandleMsg::SetViewingKey {
            key: "key".to_string(),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        let unwrapped_result: HandleAnswer =
            from_binary(&handle_result.unwrap().data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&unwrapped_result).unwrap(),
            to_binary(&HandleAnswer::SetViewingKey {
                status: ResponseStatus::Success
            })
            .unwrap(),
        );

        let query_msg = QueryMsg::Balance {
            address: HumanAddr("bob".to_string()),
            key: "wrong_key".to_string(),
        };
        let query_result = query(&deps, query_msg);
        let error = extract_error_msg(query_result);
        assert!(error.contains("Wrong viewing key"));

        let query_msg = QueryMsg::Balance {
            address: HumanAddr("bob".to_string()),
            key: "key".to_string(),
        };
        let query_result = query(&deps, query_msg);
        let balance = match from_binary(&query_result.unwrap()).unwrap() {
            QueryAnswer::Balance { amount } => amount,
            _ => panic!("Unexpected"),
        };
        assert_eq!(balance, Uint128(5000));
    }

    #[test]
    fn test_query_exchange_rate() {
        let (init_result, deps) = init_helper();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let query_msg = QueryMsg::ExchangeRate {};
        let query_result = query(&deps, query_msg);
        assert!(
            query_result.is_ok(),
            "Init failed: {}",
            query_result.err().unwrap()
        );
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::ExchangeRate { rate, denom } => {
                assert_eq!(rate, Uint128(0));
                assert_eq!(denom, "");
            }
            _ => panic!("unexpected"),
        }
    }

    #[test]
    fn test_query_transfer_history() {
        let (init_result, mut deps) = init_helper_with_config(true, true, true, true, 0);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // Mint
        let handle_msg = HandleMsg::Mint {
            recipient: HumanAddr("bob".to_string()),
            amount: Uint128(5000),
            memo: None,
            padding: None,
        };
        handle(&mut deps, mock_env("contract_initializer", &[]), handle_msg).unwrap();

        let handle_msg = HandleMsg::SetViewingKey {
            key: "key".to_string(),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        assert!(ensure_success(handle_result.unwrap()));

        let handle_msg = HandleMsg::Transfer {
            recipient: HumanAddr("alice".to_string()),
            amount: Uint128(1000),
            memo: None,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        let result = handle_result.unwrap();
        assert!(ensure_success(result));
        let handle_msg = HandleMsg::Transfer {
            recipient: HumanAddr("banana".to_string()),
            amount: Uint128(500),
            memo: None,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        let result = handle_result.unwrap();
        assert!(ensure_success(result));
        let handle_msg = HandleMsg::Transfer {
            recipient: HumanAddr("mango".to_string()),
            amount: Uint128(2500),
            memo: None,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        let result = handle_result.unwrap();
        assert!(ensure_success(result));

        let query_msg = QueryMsg::TransferHistory {
            address: HumanAddr("bob".to_string()),
            key: "key".to_string(),
            page: None,
            page_size: 0,
        };
        let query_result = query(&deps, query_msg);
        // let a: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        // println!("{:?}", a);
        let transfers = match from_binary(&query_result.unwrap()).unwrap() {
            QueryAnswer::TransferHistory { txs, .. } => txs,
            _ => panic!("Unexpected"),
        };
        assert!(transfers.is_empty());

        let query_msg = QueryMsg::TransferHistory {
            address: HumanAddr("bob".to_string()),
            key: "key".to_string(),
            page: None,
            page_size: 10,
        };
        let query_result = query(&deps, query_msg);
        let transfers = match from_binary(&query_result.unwrap()).unwrap() {
            QueryAnswer::TransferHistory { txs, .. } => txs,
            _ => panic!("Unexpected"),
        };
        assert_eq!(transfers.len(), 3);

        let query_msg = QueryMsg::TransferHistory {
            address: HumanAddr("bob".to_string()),
            key: "key".to_string(),
            page: None,
            page_size: 2,
        };
        let query_result = query(&deps, query_msg);
        let transfers = match from_binary(&query_result.unwrap()).unwrap() {
            QueryAnswer::TransferHistory { txs, .. } => txs,
            _ => panic!("Unexpected"),
        };
        assert_eq!(transfers.len(), 2);

        let query_msg = QueryMsg::TransferHistory {
            address: HumanAddr("bob".to_string()),
            key: "key".to_string(),
            page: Some(1),
            page_size: 2,
        };
        let query_result = query(&deps, query_msg);
        let transfers = match from_binary(&query_result.unwrap()).unwrap() {
            QueryAnswer::TransferHistory { txs, .. } => txs,
            _ => panic!("Unexpected"),
        };
        assert_eq!(transfers.len(), 1);
    }

    #[test]
    fn test_query_transaction_history() {
        let (init_result, mut deps) = init_helper_with_config(true, true, true, true, 1000);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        // Mint
        let handle_msg = HandleMsg::Mint {
            recipient: HumanAddr("bob".to_string()),
            amount: Uint128(10000),
            memo: None,
            padding: None,
        };
        handle(&mut deps, mock_env("contract_initializer", &[]), handle_msg).unwrap();

        let handle_msg = HandleMsg::SetViewingKey {
            key: "key".to_string(),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        assert!(ensure_success(handle_result.unwrap()));

        let handle_msg = HandleMsg::Burn {
            amount: Uint128(1),
            memo: Some("my burn message".to_string()),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        assert!(
            handle_result.is_ok(),
            "Pause handle failed: {}",
            handle_result.err().unwrap()
        );

        let handle_msg = HandleMsg::Mint {
            recipient: HumanAddr("bob".to_string()),
            amount: Uint128(100),
            memo: Some("my mint message".to_string()),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("contract_initializer", &[]), handle_msg);
        assert!(ensure_success(handle_result.unwrap()));

        let handle_msg = HandleMsg::Transfer {
            recipient: HumanAddr("alice".to_string()),
            amount: Uint128(1000),
            memo: Some("my transfer message #1".to_string()),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        let result = handle_result.unwrap();
        assert!(ensure_success(result));

        let handle_msg = HandleMsg::Transfer {
            recipient: HumanAddr("banana".to_string()),
            amount: Uint128(500),
            memo: Some("my transfer message #2".to_string()),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        let result = handle_result.unwrap();
        assert!(ensure_success(result));

        let handle_msg = HandleMsg::Transfer {
            recipient: HumanAddr("mango".to_string()),
            amount: Uint128(2500),
            memo: Some("my transfer message #3".to_string()),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        let result = handle_result.unwrap();
        assert!(ensure_success(result));

        let query_msg = QueryMsg::TransferHistory {
            address: HumanAddr("bob".to_string()),
            key: "key".to_string(),
            page: None,
            page_size: 10,
        };
        let query_result = query(&deps, query_msg);
        let transfers = match from_binary(&query_result.unwrap()).unwrap() {
            QueryAnswer::TransferHistory { txs, .. } => txs,
            _ => panic!("Unexpected"),
        };
        assert_eq!(transfers.len(), 3);

        let query_msg = QueryMsg::TransactionHistory {
            address: HumanAddr("bob".to_string()),
            key: "key".to_string(),
            page: None,
            page_size: 10,
        };
        let query_result = query(&deps, query_msg);
        let transfers = match from_binary(&query_result.unwrap()).unwrap() {
            QueryAnswer::TransactionHistory { txs, .. } => txs,
            other => panic!("Unexpected: {:?}", other),
        };

        use crate::transaction_history::{RichTx, TxAction};
        let expected_transfers = [
            RichTx {
                id: 6,
                action: TxAction::Transfer {
                    from: HumanAddr("bob".to_string()),
                    sender: HumanAddr("bob".to_string()),
                    recipient: HumanAddr("mango".to_string()),
                },
                coins: Coin {
                    denom: "SECSEC".to_string(),
                    amount: Uint128(2500),
                },
                memo: Some("my transfer message #3".to_string()),
                block_time: 1571797419,
                block_height: 12345,
            },
            RichTx {
                id: 5,
                action: TxAction::Transfer {
                    from: HumanAddr("bob".to_string()),
                    sender: HumanAddr("bob".to_string()),
                    recipient: HumanAddr("banana".to_string()),
                },
                coins: Coin {
                    denom: "SECSEC".to_string(),
                    amount: Uint128(500),
                },
                memo: Some("my transfer message #2".to_string()),
                block_time: 1571797419,
                block_height: 12345,
            },
            RichTx {
                id: 4,
                action: TxAction::Transfer {
                    from: HumanAddr("bob".to_string()),
                    sender: HumanAddr("bob".to_string()),
                    recipient: HumanAddr("alice".to_string()),
                },
                coins: Coin {
                    denom: "SECSEC".to_string(),
                    amount: Uint128(1000),
                },
                memo: Some("my transfer message #1".to_string()),
                block_time: 1571797419,
                block_height: 12345,
            },
            RichTx {
                id: 3,
                action: TxAction::Mint {
                    minter: HumanAddr("contract_initializer".to_string()),
                    recipient: HumanAddr("bob".to_string()),
                },
                coins: Coin {
                    denom: "SECSEC".to_string(),
                    amount: Uint128(100),
                },
                memo: Some("my mint message".to_string()),
                block_time: 1571797419,
                block_height: 12345,
            },
            RichTx {
                id: 2,
                action: TxAction::Burn {
                    burner: HumanAddr("bob".to_string()),
                    owner: HumanAddr("bob".to_string()),
                },
                coins: Coin {
                    denom: "SECSEC".to_string(),
                    amount: Uint128(1),
                },
                memo: Some("my burn message".to_string()),
                block_time: 1571797419,
                block_height: 12345,
            },
            RichTx {
                id: 1,
                action: TxAction::Mint {
                    minter: HumanAddr("contract_initializer".to_string()),
                    recipient: HumanAddr("bob".to_string()),
                },
                coins: Coin {
                    denom: "SECSEC".to_string(),
                    amount: Uint128(10000),
                },

                memo: None,
                block_time: 1571797419,
                block_height: 12345,
            },
        ];

        assert_eq!(transfers, expected_transfers);
    }
}

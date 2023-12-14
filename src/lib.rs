//! SPDX-License-Identifier: MIT
//! 
//! EUROe Contract Using Concordium Token Standard CIS2.
//! Copyright (c) 2023 Membrane Finance Oy
//! 
//! Permission is hereby granted, free of charge, to any person obtaining a copy
//! of this software and associated documentation files (the "Software"), to deal
//! in the Software without restriction, including without limitation the rights
//! to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//! copies of the Software, and to permit persons to whom the Software is
//! furnished to do so, subject to the following conditions:
//! 
//! The above copyright notice and this permission notice shall be included in all
//! copies or substantial portions of the Software.
//! 
//! THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//! IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//! FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//! AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//! LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//! OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//! SOFTWARE.
//! 
//! 
//! CIS-2 smart contract for the EUROe Stablecoin.
//! This contract implements the EUROe stablecoin along with its core functionality, such as minting and burning, for the Concordium blockchain as an augmented CIS-2 token. For more information, please see https://dev.euroe.com.

#![cfg_attr(not(feature = "std"), no_std)]

use concordium_cis2::*;
use concordium_std::{collections::BTreeMap, EntrypointName,*};

/// The ID of the EUROe token in this contract
const TOKEN_ID_EUROE: ContractTokenId = TokenIdUnit();

/// The base URL for the token metadata
const TOKEN_METADATA_BASE_URL: &str = "https://euroeccdmetadataprod.blob.core.windows.net/euroeccdmetadataprod/euroe-concordium-offchain-data.json";

/// The standard identifier for CIS-3
pub const CIS3_STANDARD_IDENTIFIER: StandardIdentifier<'static> =
    StandardIdentifier::new_unchecked("CIS-3");

/// List of standards supported by this contract address
const SUPPORTS_STANDARDS: [StandardIdentifier<'static>; 3] =
    [CIS0_STANDARD_IDENTIFIER, CIS2_STANDARD_IDENTIFIER, CIS3_STANDARD_IDENTIFIER];

/// List of entrypoints supported by the `permit` function (CIS3)
const SUPPORTS_PERMIT_ENTRYPOINTS: [EntrypointName; 2] =
    [EntrypointName::new_unchecked("updateOperator"), EntrypointName::new_unchecked("transfer")];

/// Tag for the CIS3 Nonce event
pub const NONCE_EVENT_TAG: u8 = u8::MAX - 5;

// Event definitions
impl schema::SchemaType for Event {
    fn get_type() -> schema::Type {
        let mut event_map = BTreeMap::new();
        event_map.insert(
            NONCE_EVENT_TAG,
            (
                "Nonce".to_string(),
                schema::Fields::Named(vec![
                    (String::from("account"), AccountAddress::get_type()),
                    (String::from("nonce"), u64::get_type()),
                ]),
            ),
        );
        event_map.insert(
            TRANSFER_EVENT_TAG,
            (
                "Transfer".to_string(),
                schema::Fields::Named(vec![
                    (String::from("token_id"), ContractTokenId::get_type()),
                    (String::from("amount"), ContractTokenAmount::get_type()),
                    (String::from("from"), Address::get_type()),
                    (String::from("to"), Address::get_type()),
                ]),
            ),
        );
        event_map.insert(
            MINT_EVENT_TAG,
            (
                "Mint".to_string(),
                schema::Fields::Named(vec![
                    (String::from("token_id"), ContractTokenId::get_type()),
                    (String::from("amount"), ContractTokenAmount::get_type()),
                    (String::from("owner"), Address::get_type()),
                ]),
            ),
        );
        event_map.insert(
            BURN_EVENT_TAG,
            (
                "Burn".to_string(),
                schema::Fields::Named(vec![
                    (String::from("token_id"), ContractTokenId::get_type()),
                    (String::from("amount"), ContractTokenAmount::get_type()),
                    (String::from("owner"), Address::get_type()),
                ]),
            ),
        );
        event_map.insert(
            UPDATE_OPERATOR_EVENT_TAG,
            (
                "UpdateOperator".to_string(),
                schema::Fields::Named(vec![
                    (String::from("update"), OperatorUpdate::get_type()),
                    (String::from("owner"), Address::get_type()),
                    (String::from("operator"), Address::get_type()),
                ]),
            ),
        );
        event_map.insert(
            TOKEN_METADATA_EVENT_TAG,
            (
                "TokenMetadata".to_string(),
                schema::Fields::Named(vec![
                    (String::from("token_id"), ContractTokenId::get_type()),
                    (String::from("metadata_url"), MetadataUrl::get_type()),
                ]),
            ),
        );
        schema::Type::TaggedEnum(event_map)
    }
}

// Types

/// Contract token ID type
pub type ContractTokenId = TokenIdUnit;

/// Contract token amount type
pub type ContractTokenAmount = TokenAmountU64;

/// The state for each address
#[derive(Serial, DeserialWithState, Deletable)]
#[concordium(state_parameter = "S")]
struct AddressState<S> {
    /// The amount of tokens owned by this address
    balances: StateMap<ContractTokenId, ContractTokenAmount, S>,
    /// The address which are currently enabled as operators for this address
    operators: StateSet<Address, S>,
}

impl<S: HasStateApi> AddressState<S> {
    fn empty(state_builder: &mut StateBuilder<S>) -> Self {
        AddressState {
            balances: state_builder.new_map(),
            operators: state_builder.new_set(),
        }
    }
}

/// The contract state
///
/// Note: The specification does not specify how to structure the contract state
/// and this could be structured in a more space efficient way.
#[derive(Serial, DeserialWithState)]
#[concordium(state_parameter = "S")]
struct State<S> {
    /// The state of addresses.
    state: StateMap<Address, AddressState<S>, S>,
    /// Map specifying the total supply of each token.
    token_balance: StateMap<ContractTokenId, ContractTokenAmount, S>,
    /// Map with contract addresses providing implementations of additional standards.
    implementors: StateMap<StandardIdentifierOwned, Vec<ContractAddress>, S>,
    // Paused state for stopping relevant contract operations.
    paused: bool,
    // State of the roles.
    roles: StateMap<Address, AddressRoleState<S>, S>,
    // State of blocklisted addresses.
    blocklist: StateSet<Address, S>,
    /// A registry to link an account to its next nonce. The nonce is used to
    /// prevent replay attacks of the signed message. The nonce is increased
    /// sequentially every time a signed message (corresponding to the
    /// account) is successfully executed in the `permit` function. This
    /// mapping keeps track of the next nonce that needs to be used by the
    /// account to generate a signature.
    nonces_registry:  StateMap<AccountAddress, u64, S>,

}

/// The errors the contract can produce.
#[derive(Serialize, Debug, PartialEq, Eq, Reject, SchemaType)]
pub enum CustomContractError {
    /// Failed parsing the parameter.
    #[from(ParseError)]
    ParseParams,
    /// Failed logging: Log is full.
    LogFull,
    /// Failed logging: Log is malformed.
    LogMalformed,
    /// Invalid contract name.
    InvalidContractName,
    /// Only a smart contract can call this function.
    ContractOnly,
    /// Failed to invoke a contract.
    InvokeContractError,
    /// Minted token unique ID.
    TokenAlreadyMinted,
    // Max supply reached.
    MaxSupplyReached,
    // Not enough balance to burn.
    NoBalanceToBurn,
    // Contract is paused.
    ContractPaused,
    // Address is blocklisted.
    AddressBlocklisted,
    /// Upgrade failed because the new module does not exist.
    FailedUpgradeMissingModule,
    /// Upgrade failed because the new module does not contain a contract with a
    /// matching name.
    FailedUpgradeMissingContract,
    /// Upgrade failed because the smart contract version of the module is not
    /// supported.
    FailedUpgradeUnsupportedModuleVersion,
    /// Failed to verify signature because signer account does not exist on
    /// chain.
    MissingAccount,
    /// Failed to verify signature because data was malformed.
    MalformedData,
    /// Failed signature verification: Invalid signature.
    WrongSignature,
    /// Failed signature verification: A different nonce is expected.
    NonceMismatch,
    /// Failed signature verification: Signature was intended for a different
    /// contract.
    WrongContract,
    /// Failed signature verification: Signature was intended for a different
    /// entry_point.
    WrongEntryPoint,
    /// Failed signature verification: Signature is expired.
    Expired,
}

pub type ContractError = Cis2Error<CustomContractError>;

pub type ContractResult<A> = Result<A, ContractError>;

/// Mapping of the logging errors to ContractError.
impl From<LogError> for CustomContractError {
    fn from(le: LogError) -> Self {
        match le {
            LogError::Full => Self::LogFull,
            LogError::Malformed => Self::LogMalformed,
        }
    }
}

/// Mapping of errors related to contract invocations to CustomContractError.
impl<T> From<CallContractError<T>> for CustomContractError {
    fn from(_cce: CallContractError<T>) -> Self {
        Self::InvokeContractError
    }
}

/// Mapping of CustomContractError to ContractError.
impl From<CustomContractError> for ContractError {
    fn from(c: CustomContractError) -> Self {
        Cis2Error::Custom(c)
    }
}

/// Mapping of NewReceiveNameError to CustomContractError.
impl From<NewReceiveNameError> for CustomContractError {
    fn from(_: NewReceiveNameError) -> Self {
        Self::InvalidContractName
    }
}
/// Mapping of NewContractNameError to CustomContractError.
impl From<NewContractNameError> for CustomContractError {
    fn from(_: NewContractNameError) -> Self {
        Self::InvalidContractName
    }
}

impl<S: HasStateApi> State<S> {
    /// Construct a state with no tokens.
    fn empty(state_builder: &mut StateBuilder<S>, admin: Address) -> Self {
        let mut state = State {
            state: state_builder.new_map(),
            token_balance: state_builder.new_map(),
            implementors: state_builder.new_map(),
            paused: false,
            roles: state_builder.new_map(),
            blocklist: state_builder.new_set(),
            nonces_registry:  state_builder.new_map(),
        };
        state.grant_role(&admin, Roles::AdminRole, state_builder);
        state
    }

    /// Creates (mints) an amount of tokens to the address passed in `owner`.
    fn mint(
        &mut self,
        token_id: &ContractTokenId,
        amount: ContractTokenAmount,
        owner: &Address,
        state_builder: &mut StateBuilder<S>,
    ) {
        let mut owner_state =
            self.state.entry(*owner).or_insert_with(|| AddressState::empty(state_builder));
        let mut owner_balance = owner_state.balances.entry(*token_id).or_insert(0.into());
        *owner_balance += amount;
        // Add the minted amount to the circulating supply.
        let mut circulating_supply = self.token_balance.entry(*token_id).or_insert(0.into());
        *circulating_supply += amount;
    }

    /// Removes (burns)  an amount of tokens from the address passed in `owner`.
    fn burn(
        &mut self,
        token_id: &ContractTokenId,
        amount: ContractTokenAmount,
        owner: &Address,
    ) ->  ContractResult<()> {
        ensure_eq!(token_id, &TOKEN_ID_EUROE, ContractError::InvalidTokenId);
        if amount == 0u64.into() {
            return Ok(());
        }

        match self.state.get_mut(owner) {
            Some(mut address_state) => match address_state.balances.get_mut(token_id) {
                Some(mut b) => {
                    ensure!(
                        *b >= amount,
                        Cis2Error::Custom(CustomContractError::NoBalanceToBurn)
                    );

                    *b -= amount;
                    // Deduct the burned amount from the circulating supply.
                    match self.token_balance.get_mut(token_id) {
                        Some(mut circulating_supply) => {
                            ensure!(
                                circulating_supply.cmp(&amount).is_ge(),
                                Cis2Error::Custom(CustomContractError::NoBalanceToBurn)
                            );
                            *circulating_supply -= amount;
                        }
                        None => return Err(Cis2Error::Custom(CustomContractError::NoBalanceToBurn)),
                    }
                    Ok(())
                }
                None => Err(Cis2Error::Custom(CustomContractError::NoBalanceToBurn)),
            },
            None => Err(Cis2Error::Custom(CustomContractError::NoBalanceToBurn)),
        }
    }

    /// Returns the current token supply (cumulative mints less cumulative burns).
    #[inline(always)]
    fn get_circulating_supply(
        &self,
        token_id: &ContractTokenId,
    ) -> ContractResult<ContractTokenAmount> {
        ensure_eq!(token_id, &TOKEN_ID_EUROE, ContractError::InvalidTokenId);
        let circulating_supply = self.token_balance.get(token_id).map_or(0.into(), |x| *x);
        Ok(circulating_supply)
    }

    /// Get the current balance of a given token id for a given address.
    /// Results in an error if the token id does not exist in the state.
    fn balance(
        &self,
        token_id: &ContractTokenId,
        address: &Address,
    ) -> ContractResult<ContractTokenAmount> {
        ensure_eq!(token_id, &TOKEN_ID_EUROE, ContractError::InvalidTokenId);
        let balance = self.state.get(address).map_or(0.into(), |address_state| {
            address_state.balances.get(token_id).map_or(0.into(), |x| *x)
        });
        Ok(balance)
    }

    /// Check if an address is an operator of a given owner address.
    fn is_operator(&self, address: &Address, owner: &Address) -> bool {
        self.state
            .get(owner)
            .map(|address_state| address_state.operators.contains(address))
            .unwrap_or(false)
    }

    /// Update the state with a transfer.
    /// Results in an error if the token ID does not exist in the state or if
    /// the source address has insufficient amount of tokens to do the transfer.
    fn transfer(
        &mut self,
        token_id: &ContractTokenId,
        amount: ContractTokenAmount,
        from: &Address,
        to: &Address,
        state_builder: &mut StateBuilder<S>,
    ) -> ContractResult<()> {
        ensure_eq!(token_id, &TOKEN_ID_EUROE, ContractError::InvalidTokenId);
        // A zero transfer does not modify the state.
        if amount == 0.into() {
            return Ok(());
        }

        // Get the `from` address state and balance. If not present it will fail since
        // the balance is interpreted as 0 and the transfer amount must be more than 0.
        {
            let mut from_address_state =
                self.state.entry(*from).occupied_or(ContractError::InsufficientFunds)?;
            let mut from_balance = from_address_state
                .balances
                .entry(*token_id)
                .occupied_or(ContractError::InsufficientFunds)?;
            ensure!(*from_balance >= amount, ContractError::InsufficientFunds);
            *from_balance -= amount;
        }

        let mut to_address_state =
            self.state.entry(*to).or_insert_with(|| AddressState::empty(state_builder));
        let mut to_address_balance = to_address_state.balances.entry(*token_id).or_insert(0.into());
        *to_address_balance += amount;

        Ok(())
    }

    /// Update the state adding a new operator for a given address.
    /// Succeeds even if the `operator` is already an operator for the `address`.
    fn add_operator(
        &mut self,
        owner: &Address,
        operator: &Address,
        state_builder: &mut StateBuilder<S>,
    ) {
        let mut owner_state =
            self.state.entry(*owner).or_insert_with(|| AddressState::empty(state_builder));
        owner_state.operators.insert(*operator);
    }

    /// Update the state removing an operator for a given address.
    /// Succeeds even if the `operator` is not an operator for the `address`.
    fn remove_operator(&mut self, owner: &Address, operator: &Address) {
        self.state.entry(*owner).and_modify(|address_state| {
            address_state.operators.remove(operator);
        });
    }

    /// Check if the state contains any implementors for a given standard.
    fn have_implementors(&self, std_id: &StandardIdentifierOwned) -> SupportResult {
        if let Some(addresses) = self.implementors.get(std_id) {
            SupportResult::SupportBy(addresses.to_vec())
        } else {
            SupportResult::NoSupport
        }
    }

    /// Set implementors for a given standard.
    fn set_implementors(
        &mut self,
        std_id: StandardIdentifierOwned,
        implementors: Vec<ContractAddress>,
    ) {
        self.implementors.insert(std_id, implementors);
    }

    /// Check if the contract has a given role for a specific Address.
    fn has_role(&self, account: &Address, role: Roles) -> bool {
        return match self.roles.get(account) {
            None => false,
            Some(roles) => roles.roles.contains(&role),
        };
    }

    /// Grants a role to a specific ddress.
    fn grant_role(&mut self, account: &Address, role: Roles, state_builder: &mut StateBuilder<S>) {
        self.roles
            .entry(*account)
            .or_insert_with(|| AddressRoleState {
                roles: state_builder.new_set(),
            });

        self.roles.entry(*account).and_modify(|entry| {
            entry.roles.insert(role);
        });
    }

    /// Remove a role from a specific Address.
    fn remove_role(&mut self, account: &Address, role: Roles) {
        self.roles.entry(*account).and_modify(|entry| {
            entry.roles.remove(&role);
        });
    }

    /// Block a specific Address
    fn block_address(
        &mut self,
        blocklistaddress: &Address,
    ) {
        self.blocklist.insert(*blocklistaddress);
    }

    /// Unblock a specific Address
    fn unblock_address(
        &mut self,
        blocklistaddress: &Address,
    ) {
        self.blocklist.remove(blocklistaddress);
    }

    /// Check if a specific Address is blocked
    fn is_blocked(
        &self,
        blocklistaddress: &Address,
    ) -> bool {
        self.blocklist.contains(blocklistaddress)
    }

}

/// Build a string from TOKEN_METADATA_BASE_URL.
fn build_token_metadata_url() -> String {
    String::from(TOKEN_METADATA_BASE_URL)
}

/// Initialize contract instance with no token types.
#[init(contract = "euroe_stablecoin")]
fn contract_init<S: HasStateApi>(
    ctx: &impl HasInitContext,
    state_builder: &mut StateBuilder<S>,
) -> InitResult<State<S>> {
    // Construct the initial contract state.
    let invoker: Address = Address::Account(ctx.init_origin());
    Ok(State::empty(state_builder, invoker))
}

#[derive(Serialize, SchemaType, PartialEq, Eq, Debug)]
pub struct ViewAddressState {
    pub balances: Vec<(ContractTokenId, ContractTokenAmount)>,
    pub operators: Vec<Address>,
}

#[derive(Serialize, SchemaType, PartialEq, Eq)]
pub struct ViewState {
    pub state: Vec<(Address, ViewAddressState)>,
}

/// View function for testing. This reports the entire state of the contract
/// for testing purposes.
#[receive(contract = "euroe_stablecoin", name = "view", return_value = "ViewState")]
fn contract_view<S: HasStateApi>(
    _ctx: &impl HasReceiveContext,
    host: &impl HasHost<State<S>, StateApiType = S>,
) -> ReceiveResult<ViewState> {
    let state = host.state();

    let mut inner_state = Vec::new();
    for (k, a_state) in state.state.iter() {
        let mut balances = Vec::new();
        let mut operators = Vec::new();
        for (token_id, amount) in a_state.balances.iter() {
            balances.push((*token_id, *amount));
        }
        for o in a_state.operators.iter() {
            operators.push(*o);
        }

        inner_state.push((
            *k,
            ViewAddressState {
                balances,
                operators,
            },
        ));
    }

    Ok(ViewState {
        state: inner_state,
    })
}

#[derive(Serialize, SchemaType, Eq, PartialEq, Debug)]
pub struct ViewCirculatingSupply {
    pub circulating_supply : ContractTokenAmount,
}

/// This viewSupply function returns the current circulating supply of EUROe.
#[receive(contract = "euroe_stablecoin", name = "viewSupply", return_value = "ViewCirculatingSupply")]
fn contract_get_circulating_supply<S: HasStateApi>(
    _ctx: &impl HasReceiveContext,
    host: &impl HasHost<State<S>, StateApiType = S>,
) -> ReceiveResult<ViewCirculatingSupply> {
    let supply = host.state().get_circulating_supply(&TOKEN_ID_EUROE);
    Ok(ViewCirculatingSupply {
        circulating_supply: supply.unwrap(),
    })
}

/// The parameter for the contract function `mint` which mints an amount of EUROe to a given address.
#[derive(Serial, Deserial, SchemaType)]
pub struct MintParams {
    pub owner: Address,
    pub amount: TokenAmountU64,
}

/// Mint new EUROe to a given address.
/// Can only be called by an address with the `MintRole` role.
/// Logs a `Mint` and a `TokenMetadata` event for each token.
///
/// It rejects if:
/// - The sender does not have the role `MintRole`.
/// - Fails to parse parameter.
/// - The sender or the receiving address (owner) is blocked.
#[receive(
    contract = "euroe_stablecoin",
    name = "mint",
    parameter = "MintParams",
    error = "ContractError",
    enable_logger,
    mutable
)]
fn contract_mint<S: HasStateApi>(
    ctx: &impl HasReceiveContext,
    host: &mut impl HasHost<State<S>, StateApiType = S>,
    logger: &mut impl HasLogger,
) -> ContractResult<()> {

    // Check if the contract is paused.
    ensure!(!host.state().paused, ContractError::Custom(CustomContractError::ContractPaused));

    // Get the sender of the transaction.
    let sender = ctx.sender();

    // Check if the sender is blocked.
    ensure!(!host.state().is_blocked(&sender),ContractError::Custom(CustomContractError::AddressBlocklisted));

    // Check if the sender has the correct role.
    ensure!(host.state().has_role(&sender, Roles::MintRole),ContractError::Unauthorized);

    // Parse the parameters.
    let params: MintParams = ctx.parameter_cursor().get()?;

    let (state, builder) = host.state_and_builder();

    let owner: Address = params.owner;
    let amount: TokenAmountU64 = params.amount;

    // If the owner in the parameters is blocked the transaction is rejected.
    ensure!(!state.is_blocked(&owner),ContractError::Custom(CustomContractError::AddressBlocklisted));
  
    // Mint the token in the state.
    state.mint(&TOKEN_ID_EUROE, amount, &owner, builder);
  
    // Log the mint event.
    logger.log(&Cis2Event::Mint(MintEvent {
        token_id: TOKEN_ID_EUROE,
        amount,
        owner,
    }))?;


    logger.log(&Cis2Event::TokenMetadata::<_, ContractTokenAmount>(TokenMetadataEvent {
        token_id: TOKEN_ID_EUROE,
        metadata_url: MetadataUrl {
            url:  build_token_metadata_url(),
            hash: None,
        },
    }))?;
    Ok(())
}

#[derive(Serial, Deserial, SchemaType)]
pub struct BurnParams {
   pub amount: ContractTokenAmount,
   pub burnaddress: Address,
}

/// Burn EUROe from the sender's account.
/// Logs a `Burn` event for each token.
///
/// It rejects if:
/// - the sender does not have the role `BurnRole`.
/// - the sender is blocked.
/// - the contract is paused.
#[receive(
    contract = "euroe_stablecoin",
    name = "burn",
    parameter = "BurnParams",
    error = "ContractError",
    enable_logger,
    mutable
)]
fn contract_burn<S: HasStateApi>(
    ctx: &impl HasReceiveContext,
    host: &mut impl HasHost<State<S>, StateApiType = S>,
    logger: &mut impl HasLogger,
) -> ContractResult<()> {
    // Check if the contract is paused.
    ensure!(!host.state().paused, ContractError::Custom(CustomContractError::ContractPaused));

    // Get the sender of the transaction.
    let sender = ctx.sender();

    // Check if the sender is blocked.
    ensure!(!host.state().is_blocked(&sender),ContractError::Custom(CustomContractError::AddressBlocklisted));

    // Check if the sender has the correct role.
    ensure!(host.state().has_role(&sender, Roles::BurnRole),ContractError::Unauthorized);

    // Parse the parameters.
    let params: BurnParams = ctx.parameter_cursor().get()?;

    let amount = params.amount;

    let burnaddress = params.burnaddress;

    // Check if the address from which EUROe are burned is blocklisted.
    ensure!(!host.state().is_blocked(&burnaddress),ContractError::Custom(CustomContractError::AddressBlocklisted));

    let (state, _builder) = host.state_and_builder();

    state.burn(&TOKEN_ID_EUROE, amount, &burnaddress)?;

    // Log the burn event.
    logger.log(&Cis2Event::Burn(BurnEvent {
        token_id: TOKEN_ID_EUROE,
        amount,
        owner: burnaddress,
    }))?;
    Ok(())
}

type TransferParameter = TransferParams<ContractTokenId, ContractTokenAmount>;

/// Execute a list of token transfers, in the order of the list.
///
/// Logs a `Transfer` event and invokes a receive hook function for every
/// transfer in the list.
///
/// It rejects if:
/// - It fails to parse the parameter.
/// - Any of the transfers fail to be executed, which could be if:
///     - The `token_id` does not exist.
///     - The sender is not the owner of the token, or an operator for this
///       specific `token_id` and `from` address.
///     - The EUROe balance of `from` is not sufficient.
///     - The sender, owner, or receiving address is blocked.
#[receive(
    contract = "euroe_stablecoin",
    name = "transfer",
    parameter = "TransferParameter",
    error = "ContractError",
    enable_logger,
    mutable
)]
fn contract_transfer<S: HasStateApi>(
    ctx: &impl HasReceiveContext,
    host: &mut impl HasHost<State<S>, StateApiType = S>,
    logger: &mut impl HasLogger,
) -> ContractResult<()> {

    // Check if the contract is paused.
    ensure!(!host.state().paused, ContractError::Custom(CustomContractError::ContractPaused));

    // Get the sender Address.
    let sender = ctx.sender();

    // Check if the sender is blocked.
    ensure!(!host.state().is_blocked(&sender),ContractError::Custom(CustomContractError::AddressBlocklisted));

    // Parse the parameters.
    let TransferParams(transfers): TransferParameter = ctx.parameter_cursor().get()?;

    for transfer in transfers
    {
        let state = host.state();

         // Authorize the sender for this transfer.
        ensure!(transfer.from == sender || state.is_operator(&sender, &transfer.from), ContractError::Unauthorized);

         // Calls the transfer helper function to execute the transfer.
         transfer_helper(transfer, host, logger)?;
    }
    Ok(())
}

/// Enable or disable addresses as operators of the sender address.
/// Logs an `UpdateOperator` event.
///
/// It rejects if:
/// - It fails to parse the parameter.
/// - Either of the addresses is blocked.
/// - The contract is paused.
#[receive(
    contract = "euroe_stablecoin",
    name = "updateOperator",
    parameter = "UpdateOperatorParams",
    error = "ContractError",
    enable_logger,
    mutable
)]
fn contract_update_operator<S: HasStateApi>(
    ctx: &impl HasReceiveContext,
    host: &mut impl HasHost<State<S>, StateApiType = S>,
    logger: &mut impl HasLogger,
) -> ContractResult<()> {
    // Check if the contract is paused.
    ensure!(!host.state().paused, ContractError::Custom(CustomContractError::ContractPaused));

    // Get the sender who invoked this contract function.
    let sender = ctx.sender();

    // Check if the sender is blocklisted.
    ensure!(!host.state().is_blocked(&sender),ContractError::Custom(CustomContractError::AddressBlocklisted));

    // Parse the parameters.
    let UpdateOperatorParams(params) = ctx.parameter_cursor().get()?;

    let (state, builder) = host.state_and_builder();
    for param in params {
        // Check if the operator is blocklisted.
         ensure!(!state.is_blocked(&param.operator),ContractError::Custom(CustomContractError::AddressBlocklisted));

         update_operator(param.update, sender, param.operator, state, builder, logger)?;
    }
    Ok(())
}

/// Parameter type for the CIS-2 function `balanceOf` specialized to the subset
/// of TokenIDs used by this contract.
pub type ContractBalanceOfQueryParams = BalanceOfQueryParams<ContractTokenId>;

/// Response type for the CIS-2 function `balanceOf` specialized to the subset
/// of TokenAmounts used by this contract.
pub type ContractBalanceOfQueryResponse = BalanceOfQueryResponse<ContractTokenAmount>;

/// Get the balance of given token IDs and addresses.
/// Anyone can call this function.
/// It rejects if:
/// - It fails to parse the parameter.
/// - Any of the queried `token_id` does not exist.
#[receive(
    contract = "euroe_stablecoin",
    name = "balanceOf",
    parameter = "ContractBalanceOfQueryParams",
    return_value = "ContractBalanceOfQueryResponse",
    error = "ContractError"
)]
fn contract_balance_of<S: HasStateApi>(
    ctx: &impl HasReceiveContext,
    host: &impl HasHost<State<S>, StateApiType = S>,
) -> ContractResult<ContractBalanceOfQueryResponse> {

    // Parse the parameters.
    let params: ContractBalanceOfQueryParams = ctx.parameter_cursor().get()?;

    // Build the response.
    let mut response = Vec::with_capacity(params.queries.len());

    for query in params.queries {
        // Query the state for balance.
        let amount = host.state().balance(&query.token_id, &query.address)?;
        response.push(amount);
    }
    let result = ContractBalanceOfQueryResponse::from(response);
    Ok(result)
}

/// Takes a list of queries. Each query is an owner address and some address to
/// check as an operator of the owner address.
/// Anyone can call this function.
/// It rejects if:
/// - It fails to parse the parameter.
#[receive(
    contract = "euroe_stablecoin",
    name = "operatorOf",
    parameter = "OperatorOfQueryParams",
    return_value = "OperatorOfQueryResponse",
    error = "ContractError"
)]
fn contract_operator_of<S: HasStateApi>(
    ctx: &impl HasReceiveContext,
    host: &impl HasHost<State<S>, StateApiType = S>,
) -> ContractResult<OperatorOfQueryResponse> {
    // Parse the parameter.
    let params: OperatorOfQueryParams = ctx.parameter_cursor().get()?;

    // Build the response.
    let mut response = Vec::with_capacity(params.queries.len());

    for query in params.queries {
        // Check if an address is an operator of a given owner address.
        let is_operator = host.state().is_operator(&query.address, &query.owner);
        response.push(is_operator);
    }
    let result = OperatorOfQueryResponse::from(response);
    Ok(result)
}

/// Parameter type for the CIS-2 function `tokenMetadata` specialized to the
/// subset of TokenIDs used by this contract.
type ContractTokenMetadataQueryParams = TokenMetadataQueryParams<ContractTokenId>;

/// Get the token metadata URLs and checksums given a list of token IDs.
/// Anyone can call this function.
/// It rejects if:
/// - It fails to parse the parameter.
/// - Any of the queried `token_id` does not exist.
#[receive(
    contract = "euroe_stablecoin",
    name = "tokenMetadata",
    parameter = "ContractTokenMetadataQueryParams",
    return_value = "TokenMetadataQueryResponse",
    error = "ContractError"
)]

fn contract_token_metadata<S: HasStateApi>(
    ctx: &impl HasReceiveContext,
    _host: &impl HasHost<State<S>, StateApiType = S>,
) -> ContractResult<TokenMetadataQueryResponse> {

     // Parse the parameters.
     let params: ContractTokenMetadataQueryParams = ctx.parameter_cursor().get()?;

     // Build the response.
     let mut response = Vec::with_capacity(params.queries.len());

     for token_id in params.queries {
         // Check the token exists.
         ensure!(token_id == TOKEN_ID_EUROE, ContractError::InvalidTokenId);
 
         let metadata_url = MetadataUrl {
             url:  build_token_metadata_url(),
             hash: None,
         };
         response.push(metadata_url);
     }
     let result = TokenMetadataQueryResponse::from(response);
     Ok(result)
}

/// Get the supported standards or addresses for a implementation given list of
/// standard identifiers.
///
/// It rejects if:
/// - It fails to parse the parameter.
#[receive(
    contract = "euroe_stablecoin",
    name = "supports",
    parameter = "SupportsQueryParams",
    return_value = "SupportsQueryResponse",
    error = "ContractError"
)]
fn contract_supports<S: HasStateApi>(
    ctx: &impl HasReceiveContext,
    host: &impl HasHost<State<S>, StateApiType = S>,
) -> ContractResult<SupportsQueryResponse> {
    // Parse the parameters.
    let params: SupportsQueryParams = ctx.parameter_cursor().get()?;

    // Build the response.
    let mut response = Vec::with_capacity(params.queries.len());
    for std_id in params.queries {
        if SUPPORTS_STANDARDS.contains(&std_id.as_standard_identifier()) {
            response.push(SupportResult::Support);
        } else {
            response.push(host.state().have_implementors(&std_id));
        }
    }
    let result = SupportsQueryResponse::from(response);
    Ok(result)
}

/// The parameter type for the contract function `setImplementors`.
/// Takes a standard identifier and a list of contract addresses providing
/// implementations of this standard.
#[derive(Debug, Serialize, SchemaType)]
pub struct SetImplementorsParams {
    /// The identifier for the standard.
    pub id: StandardIdentifierOwned,
    /// The addresses of the implementors of the standard.
    pub implementors: Vec<ContractAddress>,
}

/// Set the addresses for an implementation given a standard identifier and a
/// list of contract addresses.
/// The contract can only be called by the Admin Role
/// It rejects if:
/// - It fails to parse the parameter.
/// - Sender does not have the `AdminRole` role.
#[receive(
    contract = "euroe_stablecoin",
    name = "setImplementors",
    parameter = "SetImplementorsParams",
    error = "ContractError",
    mutable
)]
fn contract_set_implementor<S: HasStateApi>(
    ctx: &impl HasReceiveContext,
    host: &mut impl HasHost<State<S>, StateApiType = S>,
) -> ContractResult<()> {

    let sender = ctx.sender();

    // Check if the sender has the correct role.
    ensure!(host.state().has_role(&sender, Roles::AdminRole),ContractError::Unauthorized);

    // Parse the parameters.
    let params: SetImplementorsParams = ctx.parameter_cursor().get()?;

    // Update the implementors in the state
    host.state_mut().set_implementors(params.id, params.implementors);
    Ok(())
}

/// The parameter type for the contract function `setPaused`.
#[derive(Serialize, SchemaType, Debug)]
#[repr(transparent)]
pub struct SetPausedParams {
   pub paused: bool,
}

/// Pause or unpause the smart contract. No non-administrative
/// state-mutative functions (mint, burn, transfer, updateOperator, permit) can be
/// executed when the contract is paused.
///
/// It rejects if:
/// - It fails to parse the parameter.
/// - Sender does not have the `PauseUnpauseRole` role.
#[receive(
    contract = "euroe_stablecoin",
    name = "setPaused",
    parameter = "SetPausedParams",
    error = "ContractError",
    mutable
)]
fn contract_set_paused<S: HasStateApi>(
    ctx: &impl HasReceiveContext,
    host: &mut impl HasHost<State<S>, StateApiType = S>,
) -> ContractResult<()> {
    let sender = ctx.sender();

    // Check that the sender has the correct role.
    ensure!(host.state().has_role(&sender, Roles::PauseUnpauseRole),ContractError::Unauthorized);

    // Parse the parameters.
    let params: SetPausedParams = ctx.parameter_cursor().get()?;

    // Update the paused variable.
    host.state_mut().paused = params.paused;

    Ok(())
}

#[derive(Serialize, Debug, PartialEq, Eq, Reject, SchemaType, Clone)]
pub enum Roles {
    MintRole,
    BurnRole,
    PauseUnpauseRole,
    BlockUnblockRole,
    AdminRole,
}
#[derive(Serial, DeserialWithState, Deletable)]
#[concordium(state_parameter = "S")]
struct AddressRoleState<S> {
    roles: StateSet<Roles, S>,
}

#[derive(Serialize, SchemaType)]
pub struct RoleTypes {
    pub mintrole: Address,
    pub burnrole: Address,
    pub blockrole: Address,
    pub pauserole: Address,
    pub adminrole: Address,
}


/// Grant roles to addresses. Roles are used to restrict access to certain
/// functions in the contract.
/// It rejects if:
/// - It fails to parse the parameter.
/// - Sender does not have the `AdminRole` role.
#[receive(
    contract = "euroe_stablecoin",
    name = "grantRole",
    parameter = "RoleTypes",
    error = "ContractError",
    enable_logger,
    mutable
)]
fn contract_grant_role<S: HasStateApi>(
    ctx: &impl HasReceiveContext,
    host: &mut impl HasHost<State<S>, StateApiType = S>,
    _logger: &mut impl HasLogger,
) -> ContractResult<()> {

    // Get the sender of the transaction
    let sender = ctx.sender();

    // Check if the sender has AdminRole role.
    ensure!(host.state().has_role(&sender, Roles::AdminRole),ContractError::Unauthorized);

    // Parse the parameters.
    let params: RoleTypes = ctx.parameter_cursor().get()?;

    // Build the response
    let (state, builder) = host.state_and_builder();

    // Modify contract state with the updated role assignments.
    state.grant_role(&params.mintrole, Roles::MintRole, builder);
    state.grant_role(&params.pauserole, Roles::PauseUnpauseRole, builder);
    state.grant_role(&params.burnrole, Roles::BurnRole, builder);
    state.grant_role(&params.blockrole, Roles::BlockUnblockRole, builder);
    state.grant_role(&params.adminrole, Roles::AdminRole, builder);
    Ok(())
}


/// Remove roles from addresses. Roles are used to restrict access to certain
/// functions in the contract.
/// It rejects if:
/// - It fails to parse the parameter.
/// - Sender does not have the `AdminRole` role.
#[receive(
    contract = "euroe_stablecoin",
    name = "removeRole",
    parameter = "RoleTypes",
    error = "ContractError",
    enable_logger,
    mutable
)]
fn contract_remove_role<S: HasStateApi>(
    ctx: &impl HasReceiveContext,
    host: &mut impl HasHost<State<S>, StateApiType = S>,
    _logger: &mut impl HasLogger,
) -> ContractResult<()> {

    // Get the sender of the transaction
    let sender = ctx.sender();

    // Check if the sender has the correct role.
    ensure!(host.state().has_role(&sender, Roles::AdminRole),ContractError::Unauthorized);

    // Parse the parameters.
    let params: RoleTypes = ctx.parameter_cursor().get()?;

    // Build the response
    let (state, _builder) = host.state_and_builder();

    // Modify contract state with the updated role assignments.
    state.remove_role(&params.mintrole, Roles::MintRole);
    state.remove_role(&params.pauserole, Roles::PauseUnpauseRole);
    state.remove_role(&params.burnrole, Roles::BurnRole);
    state.remove_role(&params.blockrole, Roles::BlockUnblockRole);
    state.remove_role(&params.adminrole, Roles::AdminRole);
    Ok(())
}

/// Blocklist struct. 
#[derive(Debug, Serialize, SchemaType)]
pub struct BlocklistParams {
    pub address_to_block: Address,
}

/// Blocklist function which blocks an address.
/// The contract can only be called by the `BlockRole` role
/// 
/// It rejects if:
/// - Sender does not have the correct role.
/// - It fails to parse the parameter.
#[receive(
    contract = "euroe_stablecoin",
    name = "block",
    parameter = "BlocklistParams",
    error = "ContractError",
    enable_logger,
    mutable
)]
fn contract_blocklist<S: HasStateApi>(
    ctx: &impl HasReceiveContext,
    host: &mut impl HasHost<State<S>, StateApiType = S>,
    _logger: &mut impl HasLogger,
) -> ContractResult<()> {

    // Get the sender of the transaction
    let sender = ctx.sender();

    // Check if the sender has the correct role.
    ensure!(host.state().has_role(&sender, Roles::BlockUnblockRole),ContractError::Unauthorized);

    // Parse the parameters.
    let params: BlocklistParams = ctx.parameter_cursor().get()?;

    // Blocklist the address.
    host.state_mut().block_address(&params.address_to_block);

    Ok(())
}

///  Unblocklist struct. 
#[derive(Debug, Serialize, SchemaType)]
struct UnBlocklistParams {
    address_to_unblock: Address,
}

/// Unblocklisting function which unblocks an address.
/// The contract can only be called by the `BlockRole` Role
/// 
/// It rejects if:
/// - Sender is does not have the correct role.
/// - It fails to parse the parameter.
#[receive(
    contract = "euroe_stablecoin",
    name = "unblock",
    parameter = "UnBlocklistParams",
    error = "ContractError",
    enable_logger,
    mutable
)]
fn contract_unblocklist<S: HasStateApi>(
    ctx: &impl HasReceiveContext,
    host: &mut impl HasHost<State<S>, StateApiType = S>,
    _logger: &mut impl HasLogger,
) -> ContractResult<()> {

    // Get the sender of the transaction
    let sender = ctx.sender();

    // Check if the sender has the correct role.
    ensure!(host.state().has_role(&sender, Roles::BlockUnblockRole),ContractError::Unauthorized);

    // Parse the parameters.
    let params: UnBlocklistParams = ctx.parameter_cursor().get()?;

    // Remove the address from the blocklist.
    host.state_mut().unblock_address(&params.address_to_unblock);

    Ok(())
}


/// The parameter type for the contract function `upgrade`.
/// Takes the new module and optionally an entrypoint to call in the new module
/// after triggering the upgrade. The upgrade is reverted if the entrypoint
/// fails. This is useful for doing migration in the same transaction triggering
/// the upgrade.
#[derive(Serialize, SchemaType)]
pub struct UpgradeParams {
    /// The new module reference.
    pub module:  ModuleReference,
    /// Optional entrypoint to call in the new module after upgrade.
    pub migrate: Option<(OwnedEntrypointName, OwnedParameter)>,
}

/// Upgrade this smart contract instance to a new module and call optionally a
/// migration function after the upgrade.
///
/// It rejects if:
/// - Reading the state root fails.
/// - It fails to parse the parameter.
/// - Upgrade fails.
/// - Migration invoke fails.
/// - Sender does not have the `AdminRole` role.
///
/// This function is marked as `low_level`. This is **necessary** since the
/// high-level mutable functions store the state of the contract at the end of
/// execution. This conflicts with migration since the shape of the state
/// **might** be changed by the migration function. If the state is then written
/// by this function it would overwrite the state stored by the migration
/// function.
#[receive(
    contract = "euroe_stablecoin",
    name = "upgrade",
    parameter = "UpgradeParams",
    error = "CustomContractError",
    low_level
)]
fn contract_upgrade<S: HasStateApi>(
    ctx: &impl HasReceiveContext,
    host: &mut impl HasHost<S>,
) -> ContractResult<()> {
    // Read the top-level contract state.
    let state: State<S> = host.state().read_root()?;

    let sender = ctx.sender();
  
    // Check if the sender has the correct role.
    ensure!(state.has_role(&sender, Roles::AdminRole),ContractError::Unauthorized);

    // Parse the parameters.
    let params: UpgradeParams = ctx.parameter_cursor().get()?;

    // Trigger the upgrade.
    host.upgrade(params.module)?;

    // Call the migration function if provided.
    if let Some((func, parameters)) = params.migrate {
        host.invoke_contract_raw(
            &ctx.self_address(),
            parameters.as_parameter(),
            func.as_entrypoint_name(),
            Amount::zero(),
        )?;
    }
    Ok(())
}

impl From<UpgradeError> for CustomContractError {
    #[inline(always)]
    fn from(ue: UpgradeError) -> Self {
        match ue {
            UpgradeError::MissingModule => Self::FailedUpgradeMissingModule,
            UpgradeError::MissingContract => Self::FailedUpgradeMissingContract,
            UpgradeError::UnsupportedModuleVersion => Self::FailedUpgradeUnsupportedModuleVersion,
        }
    }
}

/// Mapping account signature error to CustomContractError
impl From<CheckAccountSignatureError> for CustomContractError {
    fn from(e: CheckAccountSignatureError) -> Self {
        match e {
            CheckAccountSignatureError::MissingAccount => Self::MissingAccount,
            CheckAccountSignatureError::MalformedData => Self::MalformedData,
        }
    }
}

/// Part of the parameter type for the contract function `permit`.
/// Specifies the message that is signed.
#[derive(SchemaType, Serialize)]
pub struct PermitMessage {
    /// The contract_address that the signature is intended for.
    pub contract_address: ContractAddress,
    /// A nonce to prevent replay attacks.
    pub nonce:            u64,
    /// A timestamp to make signatures expire.
    pub timestamp:        Timestamp,
    /// The entry_point that the signature is intended for.
    pub entry_point:      OwnedEntrypointName,
    /// The serialized payload that should be forwarded to either the `transfer`
    /// or the `updateOperator` function.
    #[concordium(size_length = 2)]
    pub payload:          Vec<u8>,
}
/// The parameter type for the contract function `permit`.
/// Takes a signature, the signer, and the message that was signed.
#[derive(Serialize, SchemaType)]
pub struct PermitParam {
    /// Signature/s. The CIS3 standard supports multi-sig accounts.
    pub signature: AccountSignatures,
    /// Account that created the above signature.
    pub signer:    AccountAddress,
    /// Message that was signed.
    pub message:   PermitMessage,
}
#[derive(Serialize)]
pub struct PermitParamPartial {
    /// Signature/s. The CIS3 standard supports multi-sig accounts.
    signature: AccountSignatures,
    /// Account that created the above signature.
    signer:    AccountAddress,
}

/// Tagged events to be serialized for the event log.
#[derive(Debug, Serial, Deserial, PartialEq, Eq)]
#[concordium(repr(u8))]
pub enum Event {
    /// The event tracks the nonce used by the signer of the `PermitMessage`
    /// whenever the `permit` function is invoked.
    #[concordium(tag = 250)]
    Nonce(NonceEvent),
    #[concordium(forward = cis2_events)]
    Cis2Event(Cis2Event<ContractTokenId, ContractTokenAmount>),
}

/// The NonceEvent is logged when the `permit` function is invoked. The event
/// tracks the nonce used by the signer of the `PermitMessage`.
#[derive(Debug, Serialize, SchemaType, PartialEq, Eq)]
pub struct NonceEvent {
    /// Account that signed the `PermitMessage`.
    pub account: AccountAddress,
    /// The nonce that was used in the `PermitMessage`.
    pub nonce:   u64,
}


/// Verify an ed25519 signature and allow the transfer of tokens or update of an
/// operator.
///
/// In case of a `transfer` action:
/// Logs a `Transfer` event and invokes a receive hook function for the
/// transfer.
///
/// In case of a `updateOperator` action:
/// Logs an `UpdateOperator` event.
///
/// It rejects if:
/// - It fails to parse the parameter.
/// - The contract is paused.
/// - The sender is blocked.
/// - A different nonce is expected.
/// - The signature was intended for a different contract.
/// - The signature was intended for a different `entry_point`.
/// - The signature is expired.
/// - The signature can not be validated.
/// - Fails to log event.
/// - In case of a `transfer` action: it fails to be executed, which could be
///   if:
///     - The `token_id` does not exist.
///     - The token is not owned by the `from` address.
///     - The receive hook function call rejects.
#[receive(
    contract = "euroe_stablecoin",
    name = "permit",
    parameter = "PermitParam",
    crypto_primitives,
    mutable,
    enable_logger
)]
fn contract_permit<S: HasStateApi>(
    ctx: &ReceiveContext,
    host: &mut impl HasHost<State<S>, StateApiType = S>,
    logger: &mut impl HasLogger,
    crypto_primitives: &impl HasCryptoPrimitives,
) -> ContractResult<()> {
    // Check if the contract is paused.
    ensure!(!host.state().paused, ContractError::Custom(CustomContractError::ContractPaused));
    // Get the sender Address.
    let sender = ctx.sender();
    // Check if the sender is blocked.
    ensure!(!host.state().is_blocked(&sender),ContractError::Custom(CustomContractError::AddressBlocklisted));

    // Parse the parameter.
    let param: PermitParam = ctx.parameter_cursor().get()?;

    let signer_of_permit = concordium_std::Address::Account(param.signer);
    // Check if the signer is blocked.
    ensure!(!host.state().is_blocked(&signer_of_permit),ContractError::Custom(CustomContractError::AddressBlocklisted));
    // Update the nonce.
    let mut entry = host.state_mut().nonces_registry.entry(param.signer).or_insert_with(|| 0);

    // Get the current nonce.
    let nonce = *entry;
    // Bump nonce.
    *entry += 1;
    drop(entry);

    let message = param.message;

    // Check the nonce to prevent replay attacks.
    ensure_eq!(message.nonce, nonce, CustomContractError::NonceMismatch.into());

    // Check that the signature was intended for this contract.
    ensure_eq!(
        message.contract_address,
        ctx.self_address(),
        CustomContractError::WrongContract.into()
    );

    // Check signature is not expired.
    ensure!(message.timestamp > ctx.metadata().slot_time(), CustomContractError::Expired.into());

    let message_hash = contract_view_message_hash(ctx, host, crypto_primitives)?;

    // Check signature.
    let valid_signature =
        host.check_account_signature(param.signer, &param.signature, &message_hash)?;
    ensure!(valid_signature, CustomContractError::WrongSignature.into());

    if message.entry_point.as_entrypoint_name() == EntrypointName::new_unchecked("transfer") {
        // Transfer the tokens.

        let TransferParams(transfers): TransferParameter = from_bytes(&message.payload)?;

        for transfer_struct in transfers {
            ensure!(
                transfer_struct.from.matches_account(&param.signer),
                ContractError::Unauthorized
            );

            transfer_helper(transfer_struct, host, logger)?
        }
    } else if message.entry_point.as_entrypoint_name()
        == EntrypointName::new_unchecked("updateOperator")
    {
        // Update the operator.
        let UpdateOperatorParams(updates): UpdateOperatorParams = from_bytes(&message.payload)?;

        let (state, builder) = host.state_and_builder();

        for update in updates {

            // Check if the operator is blocklisted.
            ensure!(!state.is_blocked(&update.operator),ContractError::Custom(CustomContractError::AddressBlocklisted));
            update_operator(
                update.update,
                concordium_std::Address::Account(param.signer),
                update.operator,
                state,
                builder,
                logger,
            )?;
        }
    } else {
        bail!(CustomContractError::WrongEntryPoint.into())
    }

    // Log the nonce event.
    logger.log(&Event::Nonce(NonceEvent {
        account: param.signer,
        nonce,
    }))?;

    Ok(())
}


/// Calculates the message hash
/// The contract can only be called by any account
/// Returns message hash
/// 
/// It rejects if:
/// - It fails to parse the parameter
#[receive(
    contract = "euroe_stablecoin",
    name = "viewMessageHash",
    parameter = "PermitParam",
    return_value = "[u8;32]",
    crypto_primitives,
)]
fn contract_view_message_hash<S: HasStateApi>(
    ctx: &ReceiveContext,
    _host: &impl HasHost<State<S>, StateApiType = S>,
    crypto_primitives: &impl HasCryptoPrimitives,
) -> ContractResult<[u8; 32]> {
    // Parse the parameter.
    let mut cursor = ctx.parameter_cursor();
    // The input parameter is `PermitParam` but we only read the initial part of it
    // with `PermitParamPartial`. I.e. we read the `signature` and the
    // `signer`, but not the `message` here.
    let param: PermitParamPartial = cursor.get()?;

    // The input parameter is `PermitParam` but we have only read the initial part
    // of it with `PermitParamPartial` so far. We read in the `message` now.
    // `(cursor.size() - cursor.cursor_position()` is the length of the message in
    // bytes.
    let mut message_bytes = vec![0; (cursor.size() - cursor.cursor_position()) as usize];

    cursor.read_exact(&mut message_bytes)?;

    // The message signed in the Concordium browser wallet is prepended with the
    // `account` address and 8 zero bytes. Accounts in the Concordium browser wallet
    // can either sign a regular transaction (in that case the prepend is
    // `account` address and the nonce of the account which is by design >= 1)
    // or sign a message (in that case the prepend is `account` address and 8 zero
    // bytes). Hence, the 8 zero bytes ensure that the user does not accidentally
    // sign a transaction. The account nonce is of type u64 (8 bytes).
    let mut msg_prepend = vec![0; 32 + 8];
    // Prepend the `account` address of the signer.
    msg_prepend[0..32].copy_from_slice(param.signer.as_ref());
    // Prepend 8 zero bytes.
    msg_prepend[32..40].copy_from_slice(&[0u8; 8]);
    // Calculate the message hash.
    let message_hash =
        crypto_primitives.hash_sha2_256(&[&msg_prepend[0..40], &message_bytes].concat()).0;

    Ok(message_hash)
}

/// The parameter type for the contract function `supportsPermit`.
#[derive(Debug, Serialize, SchemaType)]
pub struct SupportsPermitQueryParams {
    /// The list of supportPermit queries.
    #[concordium(size_length = 2)]
    pub queries: Vec<OwnedEntrypointName>,
}
/// Get the entrypoints supported by the `permit` function given a
/// list of entrypoints.
///
/// It rejects if:
/// - It fails to parse the parameter.
#[receive(
    contract = "euroe_stablecoin",
    name = "supportsPermit",
    parameter = "SupportsPermitQueryParams",
    return_value = "SupportsQueryResponse",
    error = "ContractError"
)]
fn contract_supports_permit<S: HasStateApi>(
    ctx: &ReceiveContext,
    _host: &impl HasHost<State<S>, StateApiType = S>,
) -> ContractResult<SupportsQueryResponse> {
    // Parse the parameter.
    let params: SupportsPermitQueryParams = ctx.parameter_cursor().get()?;

    // Build the response.
    let mut response = Vec::with_capacity(params.queries.len());
    for entrypoint in params.queries {
        if SUPPORTS_PERMIT_ENTRYPOINTS.contains(&entrypoint.as_entrypoint_name()) {
            response.push(SupportResult::Support);
        } else {
            response.push(SupportResult::NoSupport);
        }
    }
    let result = SupportsQueryResponse::from(response);
    Ok(result)
}


///  ## HELPER FUNCTIONS ##
///  Below are a list of helper functions 
///  They are usually used if a function has to call a specific code more than once
/// 

/// Internal `transfer/permit` helper function. Invokes the `transfer`
/// function of the state. Logs a `Transfer` event and invokes a receive hook
/// function. The function assumes that the transfer is authorized.
fn transfer_helper<S: HasStateApi>(
    transfer: concordium_cis2::Transfer<ContractTokenId, ContractTokenAmount>,
    host: &mut impl HasHost<State<S>, StateApiType = S>,
    logger: &mut impl HasLogger,
) -> ContractResult<()> {
    let (state, builder) = host.state_and_builder();

    let to_address = transfer.to.address();

     // Check if the destination address is blocked.
     ensure!(!state.is_blocked(&to_address),ContractError::Custom(CustomContractError::AddressBlocklisted));
     // Check if the source address is blocked. 
     ensure!(!state.is_blocked(&transfer.from),ContractError::Custom(CustomContractError::AddressBlocklisted));

    // Update the contract state
    state.transfer(&transfer.token_id, transfer.amount, &transfer.from, &to_address, builder)?;

    // Log transfer event
    logger.log(&Cis2Event::Transfer(TransferEvent {
        token_id: transfer.token_id,
        amount:   transfer.amount,
        from:     transfer.from,
        to:       to_address,
    }))?;

    // If the receiver is a contract: invoke the receive hook function.
    if let Receiver::Contract(address, function) = transfer.to {
        let parameter = OnReceivingCis2Params {
            token_id: transfer.token_id,
            amount:   transfer.amount,
            from:     transfer.from,
            data:     transfer.data,
        };
        host.invoke_contract(&address, &parameter, function.as_entrypoint_name(), Amount::zero())?;
    }

    Ok(())
}


// Internal `updateOperator/permit` helper function. Invokes the
/// `add_operator/remove_operator` function of the state.
/// Logs a `UpdateOperator` event. The function assumes that the sender is
/// authorized to do the `updateOperator` action.
fn update_operator<S: HasStateApi>(
    update: OperatorUpdate,
    sender: Address,
    operator: Address,
    state: &mut State<S>,
    builder: &mut StateBuilder<S>,
    logger: &mut impl HasLogger,
) -> ContractResult<()> {
    // Update the operator in the state.
    match update {
        OperatorUpdate::Add => state.add_operator(&sender, &operator, builder),
        OperatorUpdate::Remove => state.remove_operator(&sender, &operator),
    }

    // Log the appropriate event
    logger.log(&Cis2Event::<ContractTokenId, ContractTokenAmount>::UpdateOperator(
        UpdateOperatorEvent {
            owner: sender,
            operator,
            update,
        },
    ))?;

    Ok(())
}

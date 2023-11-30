//! Integration tests for the euroe_stablecoin  contract.

use euroe_stablecoin::*;
use concordium_cis2::{TokenIdUnit, *};
use concordium_smart_contract_testing::{AccountAccessStructure, AccountKeys, *};
use concordium_std::{AccountSignatures, CredentialSignatures, HashSha2256, SignatureEd25519,
    Timestamp,
};
use std::collections::BTreeMap;
/// The tests accounts.

// Alice is considered the admin of the contract for the following tests.
// Alice assigns the role as she gets the admin role in the initialize function.
const ALICE: AccountAddress = AccountAddress([0; 32]);
const ALICE_ADDR: Address = Address::Account(ALICE);

const BOB: AccountAddress = AccountAddress([1; 32]);
const BOB_ADDR: Address = Address::Account(BOB);

const CHARLIE: AccountAddress = AccountAddress([2u8; 32]);

const MINT_ACCOUNT: AccountAddress = AccountAddress([2; 32]);
const MINT_ADDRESS_ROLE: Address = Address::Account(MINT_ACCOUNT);

const BURN_ACCOUNT: AccountAddress = AccountAddress([3; 32]);
const BURN_ADDRESS_ROLE: Address = Address::Account(BURN_ACCOUNT);

const PAUSE_ACCOUNT: AccountAddress = AccountAddress([4; 32]);
const PAUSE_ADDRESS: Address = Address::Account(PAUSE_ACCOUNT);

const ADMIN_ACCOUNT: AccountAddress = AccountAddress([5; 32]);
const ADMIN_ADDRESS: Address = Address::Account(ADMIN_ACCOUNT);

const BLOCK_ACCOUNT: AccountAddress = AccountAddress([6; 32]);
const BLOCK_ADDRESS: Address = Address::Account(BLOCK_ACCOUNT);

const RANDOM_BLOCKLIST_ACCOUNT: AccountAddress = AccountAddress([7; 32]);
const RANDOM_BLOCKLIST_ADDRESS: Address = Address::Account(RANDOM_BLOCKLIST_ACCOUNT);

const RANDOM_MINT_ACCOUNT: AccountAddress = AccountAddress([8; 32]);
const _RANDOM_MINT_ADDRESS: Address = Address::Account(RANDOM_MINT_ACCOUNT);

const PUBLIC_KEY: [u8; 32] = [
    120, 154, 141, 6, 248, 239, 77, 224, 80, 62, 139, 136, 211, 204, 105, 208, 26, 11, 2, 208, 195,
    253, 29, 192, 126, 199, 208, 39, 69, 4, 246, 32,
];

const SIGNATURE_UPDATE_OPERATOR: SignatureEd25519 = SignatureEd25519([
    199, 250, 51, 48, 15, 210, 20, 180, 70, 191, 98, 217, 109, 67, 115, 94, 195, 81, 16, 157, 59,
    26, 36, 147, 91, 196, 254, 133, 149, 27, 148, 124, 130, 206, 68, 195, 139, 189, 244, 43, 253,
    12, 58, 17, 102, 63, 203, 35, 159, 54, 94, 59, 12, 193, 48, 78, 144, 112, 245, 149, 12, 181,
    74, 10,
]);

const DUMMY_SIGNATURE: SignatureEd25519 = SignatureEd25519([
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
]);

/// Token IDs.
const EUROE_TOKEN: ContractTokenId = TokenIdUnit();

/// Initial balance of the accounts.
const ACC_INITIAL_BALANCE: Amount = Amount::from_ccd(10000);

/// A signer for all the transactions.
const SIGNER: Signer = Signer::with_one_key();

const EUROE_URL: &str = "https://dev.euroe.com/persistent/euroe-concordium-offchain-data.json";

// Testing that the token supply is the correct when minting tokens to an account.
// The 400 tokens that ALICE has from the initialize_contract_with_euroe_tokens function.
#[test]
fn test_view_circulating_supply(){
    let (chain, contract_address, _update) = initialize_contract_with_euroe_tokens();

    let invoke = chain
        .contract_invoke(ALICE, ALICE_ADDR, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.viewSupply".to_string()),
            address:      contract_address,
            message:      OwnedParameter::empty(),
        })
        .expect("Invoke view");

    let rv: ViewCirculatingSupply = invoke.parse_return_value().expect("ViewCirculatingSupply return value");

    assert_eq!(rv, ViewCirculatingSupply {
        circulating_supply: 400.into(),
    });
}
/// Test minting succeeds and the tokens are owned by the given address and
/// the appropriate events are logged.
#[test]
fn test_minting() {
    let (chain, contract_address, update) = initialize_contract_with_euroe_tokens();
    // Invoke the view entrypoint and check that the tokens are owned by Alice.
    let invoke = chain
        .contract_invoke(ALICE, ALICE_ADDR, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.view".to_string()),
            address:      contract_address,
            message:      OwnedParameter::empty(),
        })
        .expect("Invoke view");

    let rv: ViewState = invoke.parse_return_value().expect("ViewState return value");

    assert_eq!(rv.state, vec![(ALICE_ADDR, ViewAddressState {
        balances:  vec![(EUROE_TOKEN, ContractTokenAmount::from(400))],
        operators: Vec::new(),
    })]);

    //Check that the events are logged.
    let events = update.events().flat_map(|(_addr, events)| events);

    let events: Vec<Cis2Event<ContractTokenId, ContractTokenAmount>> =
        events.map(|e| e.parse().expect("Deserialize event")).collect();
    assert_eq!(events, [
        Cis2Event::Mint(MintEvent {
            token_id: TokenIdUnit(),
            amount:   TokenAmountU64(400),
            owner:    ALICE_ADDR,
        }),
        Cis2Event::TokenMetadata(TokenMetadataEvent {
            token_id:     TokenIdUnit(),
            metadata_url: MetadataUrl {
                url:  EUROE_URL.to_string(),
                hash: None,
            },
        }),
    ]);
}

// Test that minting fails when the contract is paused 
// and that the appropriate error is returned.
#[test]
fn test_minting_pause() {
    let (mut chain, contract_address, _update) = initialize_contract_with_euroe_tokens();

    // Pause the contract.
    let params = SetPausedParams {
        paused: true,
    };

    // The role that is allowed to call the pause function is pauseunpause role
    chain
        .contract_update(SIGNER, PAUSE_ACCOUNT, PAUSE_ADDRESS, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.setPaused".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&params).expect("Pause params"),
        })
        .expect("Pause contract");

    // Attempt to mint tokens.
    let mint_params: MintParams = MintParams {
        owner: ALICE_ADDR,
        amount: 400.into(),
    };

    let update = chain
        .contract_update(SIGNER, MINT_ACCOUNT, MINT_ADDRESS_ROLE, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.mint".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&mint_params).expect("Mint params"),
        })
        .expect_err("Mint tokens");

    // Check that the correct error is returned.
    let rv: ContractError = update.parse_return_value().expect("ContractError return value");
    assert_eq!(rv, ContractError::Custom(CustomContractError::ContractPaused));
}

/// Test that minting fails when the minting EUROe to a blocked address
/// and that the appropriate error is returned.
#[test]
fn test_block_on_mint() {
    let (mut chain, contract_address, _update) = initialize_contract_with_euroe_tokens();

    // Block the contract.
    let params = BlocklistParams {
        address_to_block: RANDOM_BLOCKLIST_ADDRESS,
    };

    // The role that is allowed to call the block function is blockunblock role
    chain
        .contract_update(SIGNER, BLOCK_ACCOUNT, BLOCK_ADDRESS, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.block".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&params).expect("Block params"),
        })
        .expect("Block contract");

    // Attempt to mint tokens.
    let mint_params: MintParams = MintParams {
        owner: RANDOM_BLOCKLIST_ADDRESS,
        amount: 400.into(),
    };

    let update = chain
        .contract_update(SIGNER, RANDOM_BLOCKLIST_ACCOUNT, RANDOM_BLOCKLIST_ADDRESS, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.mint".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&mint_params).expect("Mint params"),
        })
        .expect_err("Mint tokens");

    // Check that the correct error is returned.
    let rv: ContractError = update.parse_return_value().expect("ContractError return value");
    assert_eq!(rv, ContractError::Custom(CustomContractError::AddressBlocklisted));
}

// Test that the mint fails if the role is wrong
#[test]
fn test_minting_wrong_role() {
    let (mut chain, contract_address, _update) = initialize_contract_with_euroe_tokens();

    // Attempt to mint tokens.
    let mint_params: MintParams = MintParams {
        owner: ALICE_ADDR,
        amount: 400.into(),
    };

    let update = chain
        .contract_update(SIGNER, ALICE, ALICE_ADDR, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.mint".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&mint_params).expect("Mint params"),
        })
        .expect_err("Mint tokens");

    // Check that the correct error is returned.
    let rv: ContractError = update.parse_return_value().expect("ContractError return value");
    assert_eq!(rv, ContractError::Unauthorized);
}

// Test mint fail if the sender is the blocked address
#[test]
fn test_minting_blocked_sender() {
    let (mut chain, contract_address, _update) = initialize_contract_with_euroe_tokens();

    // Block the contract.
    let params = BlocklistParams {
        address_to_block: RANDOM_BLOCKLIST_ADDRESS,
    };

    // The role that is allowed to call the block function is blockunblock role
    chain
        .contract_update(SIGNER, BLOCK_ACCOUNT, BLOCK_ADDRESS, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.block".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&params).expect("Block params"),
        })
        .expect("Block contract");

    // Attempt to mint tokens.
    let mint_params: MintParams = MintParams {
        owner: ALICE_ADDR,
        amount: 400.into(),
    };

    let update = chain
        .contract_update(SIGNER, RANDOM_BLOCKLIST_ACCOUNT, RANDOM_BLOCKLIST_ADDRESS, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.mint".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&mint_params).expect("Mint params"),
        })
        .expect_err("Mint tokens");

    // Check that the correct error is returned.
    let rv: ContractError = update.parse_return_value().expect("ContractError return value");
    assert_eq!(rv, ContractError::Custom(CustomContractError::AddressBlocklisted));
}

/// Test that burning succeeds and the appropriate events are logged.
#[test]
fn test_burning() {
    let (mut chain, contract_address, _update) = initialize_contract_with_euroe_tokens();

    // Burn 100 tokens from alice, since she already has 400
    let burn_params: BurnParams = BurnParams {
        burnaddress: ALICE_ADDR,
        amount: 100.into(),
    };

    let update = chain
        .contract_update(SIGNER, BURN_ACCOUNT, BURN_ADDRESS_ROLE, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.burn".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&burn_params).expect("Burn params"),
        })
        .expect("Burn tokens");

    let invoke = chain
        .contract_invoke(ALICE, ALICE_ADDR, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.view".to_string()),
            address:      contract_address,
            message:      OwnedParameter::empty(),
        })
        .expect("Invoke view");

    let rv: ViewState = invoke.parse_return_value().expect("ViewState return value");

    assert_eq!(rv.state, vec![(ALICE_ADDR, ViewAddressState {
        balances:  vec![(EUROE_TOKEN, ContractTokenAmount::from(300))],
        operators: Vec::new(),
    })]);

    //Check that the events are logged.
    let events = update.events().flat_map(|(_addr, events)| events);

    let events: Vec<Cis2Event<ContractTokenId, ContractTokenAmount>> =
        events.map(|e| e.parse().expect("Deserialize event")).collect();
    assert_eq!(events, [
        Cis2Event::Burn(BurnEvent {
            token_id: TokenIdUnit(),
            amount:   TokenAmountU64(100),
            owner:    ALICE_ADDR,
        })
    ]);
}

// Test burn function paused
#[test]
fn test_burn_pause(){
    let (mut chain, contract_address, _update) = initialize_contract_with_euroe_tokens();

    // Pause the contract.
    let params = SetPausedParams {
        paused: true,
    };

    // The role that is allowed to call the pause function is pauseunpause role
    chain
        .contract_update(SIGNER, PAUSE_ACCOUNT, PAUSE_ADDRESS, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.setPaused".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&params).expect("Pause params"),
        })
        .expect("Pause contract");

   // Burn 100 tokens from alice, since she already has 400
    let burn_params: BurnParams = BurnParams {
        burnaddress: ALICE_ADDR,
        amount: 100.into(),
    };

    let update = chain
        .contract_update(SIGNER, BURN_ACCOUNT, BURN_ADDRESS_ROLE, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.burn".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&burn_params).expect("Burn params"),
        })
        .expect_err("Burn tokens");

    // Check that the correct error is returned.
    let rv: ContractError = update.parse_return_value().expect("ContractError return value");
    assert_eq!(rv, ContractError::Custom(CustomContractError::ContractPaused));
}

// Test burn function blocked for the address
#[test]
fn test_burn_block(){
    let (mut chain, contract_address, _update) = initialize_contract_with_euroe_tokens();

    // Block the address.
    let params = BlocklistParams {
        address_to_block: RANDOM_BLOCKLIST_ADDRESS,
    };

    // The role that is allowed to call the block function is blockunblock role
    chain
        .contract_update(SIGNER, BLOCK_ACCOUNT, BLOCK_ADDRESS, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.block".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&params).expect("Block params"),
        })
        .expect("Block contract");

    // Burn 100 tokens from alice, since she already has 400
    let burn_params: BurnParams = BurnParams {
        burnaddress: RANDOM_BLOCKLIST_ADDRESS,
        amount: 100.into(),
    };

    let update = chain
        .contract_update(SIGNER, BURN_ACCOUNT, BURN_ADDRESS_ROLE, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.burn".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&burn_params).expect("Burn params"),
        })
        .expect_err("Burn tokens");

    // Check that the correct error is returned.
    let rv: ContractError = update.parse_return_value().expect("ContractError return value");
    assert_eq!(rv, ContractError::Custom(CustomContractError::AddressBlocklisted));

}

// Test burn fail with wrong role. 
#[test]
fn test_burn_wrong_role(){
    let (mut chain, contract_address, _update) = initialize_contract_with_euroe_tokens();

    // Burn 100 tokens from alice, since she already has 400
    let burn_params: BurnParams = BurnParams {
        burnaddress: ALICE_ADDR,
        amount: 100.into(),
    };

    let update = chain
        .contract_update(SIGNER, ALICE, ALICE_ADDR, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.burn".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&burn_params).expect("Burn params"),
        })
        .expect_err("Burn tokens");

    // Check that the correct error is returned.
    let rv: ContractError = update.parse_return_value().expect("ContractError return value");
    assert_eq!(rv, ContractError::Unauthorized);
}
// Test burn function blocked for the sender 
#[test]
fn test_burn_block_sender(){
    let (mut chain, contract_address, _update) = initialize_contract_with_euroe_tokens();

    // Block the address.
    let params = BlocklistParams {
        address_to_block: RANDOM_BLOCKLIST_ADDRESS,
    };

    // The role that is allowed to call the block function is blockunblock role
    chain
        .contract_update(SIGNER, BLOCK_ACCOUNT, BLOCK_ADDRESS, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.block".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&params).expect("Block params"),
        })
        .expect("Block contract");

    // Burn 100 tokens from alice, since she already has 400
    let burn_params: BurnParams = BurnParams {
        burnaddress: RANDOM_BLOCKLIST_ADDRESS,
        amount: 100.into(),
    };

    let update = chain
        .contract_update(SIGNER, RANDOM_BLOCKLIST_ACCOUNT, RANDOM_BLOCKLIST_ADDRESS, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.burn".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&burn_params).expect("Burn params"),
        })
        .expect_err("Burn tokens");

    // Check that the correct error is returned.
    let rv: ContractError = update.parse_return_value().expect("ContractError return value");
    assert_eq!(rv, ContractError::Custom(CustomContractError::AddressBlocklisted));

}
// Test burning with insufficient balance
#[test]
fn test_burn_with_zero_balance() {
    let (mut chain, contract_address, _update) = initialize_contract_with_euroe_tokens();

    // Burn 500 when alice only has 400
    let burn_params: BurnParams = BurnParams {
        burnaddress: ALICE_ADDR,
        amount: 500.into(),
    };

    let update = chain
        .contract_update(SIGNER, BURN_ACCOUNT, BURN_ADDRESS_ROLE, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.burn".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&burn_params).expect("Burn params"),
        })
        .expect_err("Burn tokens");

    // Check that the correct error is returned.
    let rv: ContractError = update.parse_return_value().expect("ContractError return value");

    assert_eq!(rv, ContractError::Custom(CustomContractError::NoBalanceToBurn));
}
/// Test regular transfer where sender is the owner.
#[test]
fn test_account_transfer() {
    let (mut chain, contract_address, _update) = initialize_contract_with_euroe_tokens();

    // Transfer one EUROe from Alice to Bob.
    let transfer_params = TransferParams::from(vec![concordium_cis2::Transfer {
        from:     ALICE_ADDR,
        to:       Receiver::Account(BOB),
        token_id: EUROE_TOKEN,
        amount:   TokenAmountU64(1),
        data:     AdditionalData::empty(),
    }]);

    let update = chain
        .contract_update(SIGNER, ALICE, ALICE_ADDR, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.transfer".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&transfer_params).expect("Transfer params"),
        })
        .expect("Transfer tokens");

    // Check that Bob has 1 `EUROE_TOKEN` and Alice has 399.
    let invoke = chain
        .contract_invoke(ALICE, ALICE_ADDR, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.view".to_string()),
            address:      contract_address,
            message:      OwnedParameter::empty(),
        })
        .expect("Invoke view");

    let rv: ViewState = invoke.parse_return_value().expect("ViewState return value");

    assert_eq!(rv.state, vec![
        (ALICE_ADDR, ViewAddressState {
            balances:  vec![(EUROE_TOKEN, 399.into())],
            operators: Vec::new(),
        }),
        (BOB_ADDR, ViewAddressState {
            balances:  vec![(EUROE_TOKEN, 1.into())],
            operators: Vec::new(),
        }),
    ]);


    //Check that the events are logged.
    let events = update
        .events()
        .flat_map(|(_addr, events)| events.iter().map(|e| e.parse().expect("Deserialize event")))
        .collect::<Vec<Cis2Event<_, _>>>();

    assert_eq!(events, [Cis2Event::Transfer(TransferEvent {
        token_id: EUROE_TOKEN,
        amount:   TokenAmountU64(1),
        from:     ALICE_ADDR,
        to:       BOB_ADDR,
    }),]);
}

/// Test 2 transfers budnled into one transaction
#[test]
fn test_double_transfer() {
    let (mut chain, contract_address, _update) = initialize_contract_with_euroe_tokens();

    // Transfer one EUROe from Alice to Bob.
    let transfer_params = TransferParams::from(vec![concordium_cis2::Transfer {
        from:     ALICE_ADDR,
        to:       Receiver::Account(BOB),
        token_id: EUROE_TOKEN,
        amount:   TokenAmountU64(1),
        data:     AdditionalData::empty(),
    },concordium_cis2::Transfer {
        from:     ALICE_ADDR,
        to:       Receiver::Account(BOB),
        token_id: EUROE_TOKEN,
        amount:   TokenAmountU64(1),
        data:     AdditionalData::empty(),
    }]);

    chain
        .contract_update(SIGNER, ALICE, ALICE_ADDR, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.transfer".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&transfer_params).expect("Transfer params"),
        })
        .expect("Transfer tokens");

    // Check that Bob has 1 `EUROE_TOKEN` and Alice has 399.
    let invoke = chain
        .contract_invoke(ALICE, ALICE_ADDR, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.view".to_string()),
            address:      contract_address,
            message:      OwnedParameter::empty(),
        })
        .expect("Invoke view");

    let rv: ViewState = invoke.parse_return_value().expect("ViewState return value");

    assert_eq!(rv.state, vec![
        (ALICE_ADDR, ViewAddressState {
            balances:  vec![(EUROE_TOKEN, 398.into())],
            operators: Vec::new(),
        }),
        (BOB_ADDR, ViewAddressState {
            balances:  vec![(EUROE_TOKEN, 2.into())],
            operators: Vec::new(),
        }),
    ]);
}

/// Test 2 transfers budnled into one transaction, but with one blocklisted user.
/// Both the transfer should fail, alice will mantain the 400 EUROe and the blocklisted user will not receive any.
#[test]
fn test_double_transfer_with_one_failed() {
    let (mut chain, contract_address, _update) = initialize_contract_with_euroe_tokens();

    // Block the address.
    let params = BlocklistParams {
        address_to_block: RANDOM_BLOCKLIST_ADDRESS,
    };

    // The role that is allowed to call the block function is blockunblock role
    chain
        .contract_update(SIGNER, BLOCK_ACCOUNT, BLOCK_ADDRESS, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.block".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&params).expect("Block params"),
        })
        .expect("Block contract");

    // Transfer one EUROe from Alice to Bob.
    // Transfer one EUROe from Alice to RANDOM_BLOCKLIST_ADDRESS.
    let transfer_params = TransferParams::from(vec![concordium_cis2::Transfer {
        from:     ALICE_ADDR,
        to:       Receiver::Account(BOB),
        token_id: EUROE_TOKEN,
        amount:   TokenAmountU64(1),
        data:     AdditionalData::empty(),
    },concordium_cis2::Transfer {
        from:     ALICE_ADDR,
        to:       Receiver::Account(RANDOM_BLOCKLIST_ACCOUNT),
        token_id: EUROE_TOKEN,
        amount:   TokenAmountU64(1),
        data:     AdditionalData::empty(),
    }]);

    let update = chain
        .contract_update(SIGNER, ALICE, ALICE_ADDR, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.transfer".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&transfer_params).expect("Transfer params"),
        })
        .expect_err("Transfer tokens");

    // Check that the correct error is returned.
    let rv: ContractError = update.parse_return_value().expect("ContractError return value");
    assert_eq!(rv, ContractError::Custom(CustomContractError::AddressBlocklisted));

    // Check that Bob has 1 `EUROE_TOKEN` and Alice has 399.
    let invoke = chain
        .contract_invoke(ALICE, ALICE_ADDR, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.view".to_string()),
            address:      contract_address,
            message:      OwnedParameter::empty(),
        })
        .expect("Invoke view");

    let rv: ViewState = invoke.parse_return_value().expect("ViewState return value");

    assert_eq!(rv.state, vec![
        (ALICE_ADDR, ViewAddressState {
            balances:  vec![(EUROE_TOKEN, 400.into())],
            operators: Vec::new(),
        })
    ]);

}

//  Test transferring an amount that exceeds the owner's balance
#[test]
fn test_transfer_exceed_balance() {
    let (mut chain, contract_address, _update) = initialize_contract_with_euroe_tokens();

    // Transfer 401 tokens from Alice to Bob. 
    // Alice only has 400
    let transfer_params = TransferParams::from(vec![concordium_cis2::Transfer {
        from:     ALICE_ADDR,
        to:       Receiver::Account(BOB),
        token_id: EUROE_TOKEN,
        amount:   TokenAmountU64(401),
        data:     AdditionalData::empty(),
    }]);

    let update = chain
        .contract_update(SIGNER, ALICE, ALICE_ADDR, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.transfer".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&transfer_params).expect("Transfer params"),
        })
        .expect_err("Transfer tokens");

    // Check that the correct error is returned.
    let rv: ContractError = update.parse_return_value().expect("ContractError return value");

    assert_eq!(rv, ContractError::InsufficientFunds);
}

// Test transfer fails if contract is paused
#[test]
fn test_transfer_pause(){
    let (mut chain, contract_address, _update) = initialize_contract_with_euroe_tokens();

    // Pause the contract.
    let params = SetPausedParams {
        paused: true,
    };

    // The role that is allowed to call the pause function is pauseunpause role
    chain
        .contract_update(SIGNER, PAUSE_ACCOUNT, PAUSE_ADDRESS, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.setPaused".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&params).expect("Pause params"),
        })
        .expect("Pause contract");

    // Transfer one EUROe from Alice to Bob.
    let transfer_params = TransferParams::from(vec![concordium_cis2::Transfer {
        from:     ALICE_ADDR,
        to:       Receiver::Account(BOB),
        token_id: EUROE_TOKEN,
        amount:   TokenAmountU64(1),
        data:     AdditionalData::empty(),
    }]);

    let update = chain
        .contract_update(SIGNER, ALICE, ALICE_ADDR, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.transfer".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&transfer_params).expect("Transfer params"),
        })
        .expect_err("Transfer tokens");

    // Check that the correct error is returned.
    let rv: ContractError = update.parse_return_value().expect("ContractError return value");

    assert_eq!(rv, ContractError::Custom(CustomContractError::ContractPaused));
}

// Test transfer fail if sender is blocked 
#[test]
fn test_transfer_block_sender(){
    let (mut chain, contract_address, _update) = initialize_contract_with_euroe_tokens();

    // Block the address.
    let params = BlocklistParams {
        address_to_block: RANDOM_BLOCKLIST_ADDRESS,
    };

    // The role that is allowed to call the block function is blockunblock role
    chain
        .contract_update(SIGNER, BLOCK_ACCOUNT, BLOCK_ADDRESS, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.block".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&params).expect("Block params"),
        })
        .expect("Block contract");

    // Transfer one EUROe from Alice to Bob.
    let transfer_params = TransferParams::from(vec![concordium_cis2::Transfer {
        from:     RANDOM_BLOCKLIST_ADDRESS,
        to:       Receiver::Account(BOB),
        token_id: EUROE_TOKEN,
        amount:   TokenAmountU64(1),
        data:     AdditionalData::empty(),
    }]);

    let update = chain
        .contract_update(SIGNER, RANDOM_BLOCKLIST_ACCOUNT, RANDOM_BLOCKLIST_ADDRESS, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.transfer".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&transfer_params).expect("Transfer params"),
        })
        .expect_err("Transfer tokens");

    // Check that the correct error is returned.
    let rv: ContractError = update.parse_return_value().expect("ContractError return value");

    assert_eq!(rv, ContractError::Custom(CustomContractError::AddressBlocklisted));
}

// Test transfer failed if the reciver is blocked
#[test]
fn test_transfer_block_receiver(){
    let (mut chain, contract_address, _update) = initialize_contract_with_euroe_tokens();

    // Block the address.
    let params = BlocklistParams {
        address_to_block: RANDOM_BLOCKLIST_ADDRESS,
    };

    // The role that is allowed to call the block function is blockunblock role
    chain
        .contract_update(SIGNER, BLOCK_ACCOUNT, BLOCK_ADDRESS, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.block".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&params).expect("Block params"),
        })
        .expect("Block contract");

    // Transfer one EUROe from Alice to Bob.
    let transfer_params = TransferParams::from(vec![concordium_cis2::Transfer {
        from:     ALICE_ADDR,
        to:       Receiver::Account(RANDOM_BLOCKLIST_ACCOUNT),
        token_id: EUROE_TOKEN,
        amount:   TokenAmountU64(1),
        data:     AdditionalData::empty(),
    }]);

    let update = chain
        .contract_update(SIGNER, ALICE, ALICE_ADDR, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.transfer".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&transfer_params).expect("Transfer params"),
        })
        .expect_err("Transfer tokens");

    // Check that the correct error is returned.
    let rv: ContractError = update.parse_return_value().expect("ContractError return value");
    assert_eq!(rv, ContractError::Custom(CustomContractError::AddressBlocklisted));

}


/// Test that you can add an operator.
/// Initialize the contract with tokenss owned by Alice.
/// Then add Bob as an operator for Alice.
#[test]
fn test_add_operator() {
    let (mut chain, contract_address, _update) = initialize_contract_with_euroe_tokens();

    // Add Bob as an operator for Alice.
    let params = UpdateOperatorParams(vec![UpdateOperator {
        update:   OperatorUpdate::Add,
        operator: BOB_ADDR,
    }]);

    let update = chain
        .contract_update(SIGNER, ALICE, ALICE_ADDR, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.updateOperator".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&params).expect("UpdateOperator params"),
        })
        .expect("Update operator");

    // Check that an operator event occurred.
    let events = update
        .events()
        .flat_map(|(_addr, events)| events.iter().map(|e| e.parse().expect("Deserialize event")))
        .collect::<Vec<Cis2Event<ContractTokenId, ContractTokenAmount>>>();
    assert_eq!(events, [Cis2Event::UpdateOperator(UpdateOperatorEvent {
        operator: BOB_ADDR,
        owner:    ALICE_ADDR,
        update:   OperatorUpdate::Add,
    }),]);

    // Construct a query parameter to check whether Bob is an operator for Alice.
    let query_params = OperatorOfQueryParams {
        queries: vec![OperatorOfQuery {
            owner:   ALICE_ADDR,
            address: BOB_ADDR,
        }],
    };

    // Invoke the operatorOf view entrypoint and check that Bob is an operator for
    // Alice.
    let invoke = chain
        .contract_invoke(ALICE, ALICE_ADDR, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.operatorOf".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&query_params).expect("OperatorOf params"),
        })
        .expect("Invoke view");

    let rv: OperatorOfQueryResponse = invoke.parse_return_value().expect("OperatorOf return value");
    assert_eq!(rv, OperatorOfQueryResponse(vec![true]));
}

// Test adding operator fails if the sender and the operator are blocklisted
#[test]
fn test_add_operator_fail(){
    let (mut chain, contract_address, _update) = initialize_contract_with_euroe_tokens();

    // Block the address.
    let params = BlocklistParams {
        address_to_block: RANDOM_BLOCKLIST_ADDRESS,
    };

    // The role that is allowed to call the block function is blockunblock role
    chain
        .contract_update(SIGNER, BLOCK_ACCOUNT, BLOCK_ADDRESS, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.block".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&params).expect("Block params"),
        })
        .expect("Block contract");

    // Add Bob as an operator for Alice.
    let params = UpdateOperatorParams(vec![UpdateOperator {
        update:   OperatorUpdate::Add,
        operator: RANDOM_BLOCKLIST_ADDRESS,
    }]);

    let update = chain
        .contract_update(SIGNER, RANDOM_BLOCKLIST_ACCOUNT, RANDOM_BLOCKLIST_ADDRESS, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.updateOperator".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&params).expect("UpdateOperator params"),
        })
        .expect_err("Update operator");

    // Check that the correct error is returned.
    let rv: ContractError = update.parse_return_value().expect("ContractError return value");

    assert_eq!(rv, ContractError::Custom(CustomContractError::AddressBlocklisted));

    // now lets resend another transaction but this time to check if the operator address is blocklisted

    let update_op = chain
        .contract_update(SIGNER, ADMIN_ACCOUNT, ADMIN_ADDRESS, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.updateOperator".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&params).expect("UpdateOperator params"),
        })
        .expect_err("Update operator");

    // Check that the correct error is returned.
    let rv_op: ContractError = update_op.parse_return_value().expect("ContractError return value");

    assert_eq!(rv_op, ContractError::Custom(CustomContractError::AddressBlocklisted));

}

/// Test that you can add an operator.
/// Initialize the contract with tokenss owned by Alice.
/// Then add Bob as an operator for Alice.
/// Then remove Bob as an opeartor of Alice.
#[test]
fn test_remove_operator() {
    let (mut chain, contract_address, _update) = initialize_contract_with_euroe_tokens();

    // Add Bob as an operator for Alice.
    let params = UpdateOperatorParams(vec![UpdateOperator {
        update:   OperatorUpdate::Add,
        operator: BOB_ADDR,
    }]);

    let update = chain
        .contract_update(SIGNER, ALICE, ALICE_ADDR, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.updateOperator".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&params).expect("UpdateOperator params"),
        })
        .expect("Update operator");

    // Check that an operator event occurred.
    let events = update
        .events()
        .flat_map(|(_addr, events)| events.iter().map(|e| e.parse().expect("Deserialize event")))
        .collect::<Vec<Cis2Event<ContractTokenId, ContractTokenAmount>>>();
    assert_eq!(events, [Cis2Event::UpdateOperator(UpdateOperatorEvent {
        operator: BOB_ADDR,
        owner:    ALICE_ADDR,
        update:   OperatorUpdate::Add,
    }),]);

    // Construct a query parameter to check whether Bob is an operator for Alice.
    let query_params = OperatorOfQueryParams {
        queries: vec![OperatorOfQuery {
            owner:   ALICE_ADDR,
            address: BOB_ADDR,
        }],
    };

    // Invoke the operatorOf view entrypoint and check that Bob is an operator for
    // Alice.
    let invoke = chain
        .contract_invoke(ALICE, ALICE_ADDR, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.operatorOf".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&query_params).expect("OperatorOf params"),
        })
        .expect("Invoke view");

    let rv: OperatorOfQueryResponse = invoke.parse_return_value().expect("OperatorOf return value");
    assert_eq!(rv, OperatorOfQueryResponse(vec![true]));

    // Lets remove Bob as an operator for Alice.
    // Add Bob as an operator for Alice.
    let params = UpdateOperatorParams(vec![UpdateOperator {
        update:   OperatorUpdate::Remove,
        operator: BOB_ADDR,
    }]);

    let update = chain
        .contract_update(SIGNER, ALICE, ALICE_ADDR, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.updateOperator".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&params).expect("UpdateOperator params"),
        })
        .expect("Update operator");

    // Check that an operator event occurred.
    let events = update
        .events()
        .flat_map(|(_addr, events)| events.iter().map(|e| e.parse().expect("Deserialize event")))
        .collect::<Vec<Cis2Event<ContractTokenId, ContractTokenAmount>>>();
    assert_eq!(events, [Cis2Event::UpdateOperator(UpdateOperatorEvent {
        operator: BOB_ADDR,
        owner:    ALICE_ADDR,
        update:   OperatorUpdate::Remove,
    }),]);

    // Invoke the operatorOf view entrypoint and check that Bob is an operator for
    // Alice.
    let invoke = chain
        .contract_invoke(ALICE, ALICE_ADDR, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.operatorOf".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&query_params).expect("OperatorOf params"),
        })
        .expect("Invoke view");

    let rv: OperatorOfQueryResponse = invoke.parse_return_value().expect("OperatorOf return value");
    assert_eq!(rv, OperatorOfQueryResponse(vec![false]));
}

// Test operator add fail when contract is paused. 
#[test]
fn test_add_operator_pause(){
    let (mut chain, contract_address, _update) = initialize_contract_with_euroe_tokens();

    // Pause the contract.
    let params = SetPausedParams {
        paused: true,
    };

    // The role that is allowed to call the pause function is pauseunpause role
    chain
        .contract_update(SIGNER, PAUSE_ACCOUNT, PAUSE_ADDRESS, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.setPaused".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&params).expect("Pause params"),
        })
        .expect("Pause contract");

    // Add Bob as an operator for Alice.
    let params = UpdateOperatorParams(vec![UpdateOperator {
        update:   OperatorUpdate::Add,
        operator: BOB_ADDR,
    }]);

    let update = chain
        .contract_update(SIGNER, ALICE, ALICE_ADDR, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.updateOperator".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&params).expect("UpdateOperator params"),
        })
        .expect_err("Update operator");

    // Check that the correct error is returned.
    let rv: ContractError = update.parse_return_value().expect("ContractError return value");

    assert_eq!(rv, ContractError::Custom(CustomContractError::ContractPaused));
}

// Test operator remove fail when contract is paused. 
#[test]
fn test_remove_operator_pause(){
    let (mut chain, contract_address, _update) = initialize_contract_with_euroe_tokens();

    // Pause the contract.
    let params = SetPausedParams {
        paused: true,
    };

    // The role that is allowed to call the pause function is pauseunpause role
    chain
        .contract_update(SIGNER, PAUSE_ACCOUNT, PAUSE_ADDRESS, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.setPaused".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&params).expect("Pause params"),
        })
        .expect("Pause contract");

    // Add Bob as an operator for Alice.
    let params = UpdateOperatorParams(vec![UpdateOperator {
        update:   OperatorUpdate::Remove,
        operator: BOB_ADDR,
    }]);

    let update = chain
        .contract_update(SIGNER, ALICE, ALICE_ADDR, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.updateOperator".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&params).expect("UpdateOperator params"),
        })
        .expect_err("Update operator");

    // Check that the correct error is returned.
    let rv: ContractError = update.parse_return_value().expect("ContractError return value");

    assert_eq!(rv, ContractError::Custom(CustomContractError::ContractPaused));
}

// Test operator can transfer fail if the contract is paused. 
#[test]
fn test_operator_can_transfer_pause(){
    let (mut chain, contract_address, _update) = initialize_contract_with_euroe_tokens();

    // Add Bob as an operator for Alice.
    let params = UpdateOperatorParams(vec![UpdateOperator {
        update:   OperatorUpdate::Add,
        operator: BOB_ADDR,
    }]);

    chain
        .contract_update(SIGNER, ALICE, ALICE_ADDR, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.updateOperator".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&params).expect("UpdateOperator params"),
        })
        .expect("Update operator");

    // Pause the contract.
    let params = SetPausedParams {
        paused: true,
    };

    // The role that is allowed to call the pause function is pauseunpause role
    chain
        .contract_update(SIGNER, PAUSE_ACCOUNT, PAUSE_ADDRESS, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.setPaused".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&params).expect("Pause params"),
        })
        .expect("Pause contract");

    // Let Bob make a transfer to himself on behalf of Alice.
    let transfer_params = TransferParams::from(vec![concordium_cis2::Transfer {
        from:     ALICE_ADDR,
        to:       Receiver::Account(BOB),
        token_id: EUROE_TOKEN,
        amount:   TokenAmountU64(1),
        data:     AdditionalData::empty(),
    }]);

    let update = chain
        .contract_update(SIGNER, BOB, BOB_ADDR, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.transfer".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&transfer_params).expect("Transfer params"),
        })
        .expect_err("Transfer tokens");

    // Check that the correct error is returned.
    let rv: ContractError = update.parse_return_value().expect("ContractError return value");
    assert_eq!(rv, ContractError::Custom(CustomContractError::ContractPaused));
}

/// Test that a transfer fails when the sender is neither an operator or the
/// owner. In particular, Bob will attempt to transfer some of Alice's tokens to
/// himself.
#[test]
fn test_unauthorized_sender() {
    let (mut chain, contract_address, _update) = initialize_contract_with_euroe_tokens();

    // Construct a transfer of `EUROE_TOKEN` from Alice to Bob, which will be submitted
    // by Bob.
    let transfer_params = TransferParams::from(vec![concordium_cis2::Transfer {
        from:     ALICE_ADDR,
        to:       Receiver::Account(BOB),
        token_id: EUROE_TOKEN,
        amount:   TokenAmountU64(1),
        data:     AdditionalData::empty(),
    }]);

    // Notice that Bob is the sender/invoker.
    let update = chain
        .contract_update(SIGNER, BOB, BOB_ADDR, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.transfer".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&transfer_params).expect("Transfer params"),
        })
        .expect_err("Transfer tokens");

    // Check that the correct error is returned.
    let rv: ContractError = update.parse_return_value().expect("ContractError return value");
    assert_eq!(rv, ContractError::Unauthorized);
}

/// Test that an operator can make a transfer.
#[test]
fn test_operator_can_transfer() {
    let (mut chain, contract_address, _update) = initialize_contract_with_euroe_tokens();

    // Add Bob as an operator for Alice.
    let params = UpdateOperatorParams(vec![UpdateOperator {
        update:   OperatorUpdate::Add,
        operator: BOB_ADDR,
    }]);
    chain
        .contract_update(SIGNER, ALICE, ALICE_ADDR, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.updateOperator".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&params).expect("UpdateOperator params"),
        })
        .expect("Update operator");

    // Let Bob make a transfer to himself on behalf of Alice.
    let transfer_params = TransferParams::from(vec![concordium_cis2::Transfer {
        from:     ALICE_ADDR,
        to:       Receiver::Account(BOB),
        token_id: EUROE_TOKEN,
        amount:   TokenAmountU64(1),
        data:     AdditionalData::empty(),
    }]);

    chain
        .contract_update(SIGNER, BOB, BOB_ADDR, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.transfer".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&transfer_params).expect("Transfer params"),
        })
        .expect("Transfer tokens");

    // Check that Bob now has 1 of `EUROE_TOKEN` and Alice has 399.
    let invoke = chain
        .contract_invoke(ALICE, ALICE_ADDR, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.view".to_string()),
            address:      contract_address,
            message:      OwnedParameter::empty(),
        })
        .expect("Invoke view");
    let rv: ViewState = invoke.parse_return_value().expect("ViewState return value");
    assert_eq!(rv.state, vec![
        (ALICE_ADDR, ViewAddressState {
            balances:  vec![(EUROE_TOKEN, 399.into())],
            operators: vec![BOB_ADDR],
        }),
        (BOB_ADDR, ViewAddressState {
            balances:  vec![(EUROE_TOKEN, 1.into())],
            operators: Vec::new(),
        }),
    ]);
}
// Test contract token metadata function
#[test]
fn test_contract_token_metadata(){
    let (mut chain, contract_address, _update) = initialize_contract_with_euroe_tokens();

    // Construct the token metadata query parameters
    let token_id_queries: Vec<ContractTokenId> = vec![EUROE_TOKEN];
    let metadata_query_params = TokenMetadataQueryParams {
        queries: token_id_queries,
    };

    let update = chain
        .contract_update(SIGNER, ALICE, ALICE_ADDR, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.tokenMetadata".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&metadata_query_params).expect("Transfer params"),
        })
        .expect("TokenMetadata");

    let expected_metadata_url = MetadataUrl {
        url:  EUROE_URL.to_string(),
        hash: None,
    };
    let expected_response = TokenMetadataQueryResponse(vec![expected_metadata_url]);

    let rv: TokenMetadataQueryResponse = update.parse_return_value().expect("TokenMetadata return value");
    // Manually compare the two instances

    assert_eq!(expected_response.0, rv.0);
    
}

// Test when paused, all the pause functionality return contractPaused.
// The pause functionalities are 
// contract_mint, contract_burn, contract_transfer, contract_updateOperator
// contract_set_implementor
#[test]
fn test_pause_functionality() {
    let (mut chain, contract_address, _update) = initialize_contract_with_euroe_tokens();

    // Pause the contract.
    let params = SetPausedParams {
        paused: true,
    };

    // The role that is allowed to call the pause function is pauseunpause role
    chain
        .contract_update(SIGNER, PAUSE_ACCOUNT, PAUSE_ADDRESS, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.setPaused".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&params).expect("Pause params"),
        })
        .expect("Pause contract");

    // Mint tokens for which Alice is the owner.
    let mint_params = MintParams {
        owner: ALICE_ADDR,
        amount: 400.into(),
    };

    let mint_update = chain
        .contract_update(SIGNER, ALICE, ALICE_ADDR, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.mint".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&mint_params).expect("Mint params"),
        })
        .expect_err("Mint tokens");

    // Check that the correct error is returned.
    let mint_rv: ContractError = mint_update.parse_return_value().expect("ContractError return value");

    assert_eq!(mint_rv, ContractError::Custom(CustomContractError::ContractPaused));

    // Burn tokens from alice
    let burn_params: BurnParams = BurnParams {
        burnaddress: ALICE_ADDR,
        amount: 100.into(),
    };

    let burn_update = chain
        .contract_update(SIGNER, BURN_ACCOUNT, BURN_ADDRESS_ROLE, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.burn".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&burn_params).expect("Burn params"),
        })
        .expect_err("Burn tokens");

    // Check that the correct error is returned.
    let burn_rv: ContractError = burn_update.parse_return_value().expect("ContractError return value");

    assert_eq!(burn_rv, ContractError::Custom(CustomContractError::ContractPaused));

    // Transfer tokens from alice to bob
    let transfer_params = TransferParams::from(vec![concordium_cis2::Transfer {
        from:     ALICE_ADDR,
        to:       Receiver::Account(BOB),
        token_id: EUROE_TOKEN,
        amount:   TokenAmountU64(1),
        data:     AdditionalData::empty(),
    }]);

    let transfer_update = chain
        .contract_update(SIGNER, ALICE, ALICE_ADDR, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.transfer".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&transfer_params).expect("Transfer params"),
        })
        .expect_err("Transfer tokens");

    // Check that the correct error is returned.
    let transfer_rv: ContractError = transfer_update.parse_return_value().expect("ContractError return value");
    assert_eq!(transfer_rv, ContractError::Custom(CustomContractError::ContractPaused));

    // Add Bob as an operator for Alice.
    let params = UpdateOperatorParams(vec![UpdateOperator {
        update:   OperatorUpdate::Add,
        operator: BOB_ADDR,
    }]);

    let operator_update = chain
        .contract_update(SIGNER, ALICE, ALICE_ADDR, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.updateOperator".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&params).expect("UpdateOperator params"),
        })
        .expect_err("Update operator");

    // Check that the correct error is returned.
    let operator_rv: ContractError = operator_update.parse_return_value().expect("ContractError return value");
    assert_eq!(operator_rv, ContractError::Custom(CustomContractError::ContractPaused));

}

// Test Unpause functionality
#[test]
fn test_unpause() {
    let (mut chain, contract_address, _update) = initialize_contract_with_euroe_tokens();

    // Pause the contract.
    let params = SetPausedParams {
        paused: true,
    };

    // The role that is allowed to call the pause function is pauseunpause role
    chain
        .contract_update(SIGNER, PAUSE_ACCOUNT, PAUSE_ADDRESS, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.setPaused".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&params).expect("Pause params"),
        })
        .expect("Pause contract");

    // Attempt to mint tokens.
    let mint_params: MintParams = MintParams {
        owner: ALICE_ADDR,
        amount: 400.into(),
    };

    let update = chain
        .contract_update(SIGNER, MINT_ACCOUNT, MINT_ADDRESS_ROLE, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.mint".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&mint_params).expect("Mint params"),
        })
        .expect_err("Mint tokens");

    // Check that the correct error is returned.
    let rv: ContractError = update.parse_return_value().expect("ContractError return value");
    assert_eq!(rv, ContractError::Custom(CustomContractError::ContractPaused));

    // Unpause the contract.
    let params = SetPausedParams {
        paused: false,
    };

    // The role that is allowed to call the pause function is pauseunpause role
    chain
        .contract_update(SIGNER, PAUSE_ACCOUNT, PAUSE_ADDRESS, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.setPaused".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&params).expect("Pause params"),
        })
        .expect("Pause contract");

    // Mint tokens for which Alice is the owner.
    let mint_params = MintParams {
        owner: ALICE_ADDR,
        amount: 400.into(),
    };

    chain
        .contract_update(SIGNER, MINT_ACCOUNT, MINT_ADDRESS_ROLE, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.mint".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&mint_params).expect("Mint params"),
        })
        .expect("Mint tokens");


    // Invoke the view entrypoint and check that the tokens are owned by Alice.
    let invoke = chain
        .contract_invoke(ALICE, ALICE_ADDR, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.view".to_string()),
            address:      contract_address,
            message:      OwnedParameter::empty(),
        })
        .expect("Invoke view");

    let rv: ViewState = invoke.parse_return_value().expect("ViewState return value");

    assert_eq!(rv.state, vec![(ALICE_ADDR, ViewAddressState {
        balances:  vec![(EUROE_TOKEN, ContractTokenAmount::from(800))],
        operators: Vec::new(),
    })]);

}

// Test unpause failed due to wrong role. 
#[test]
fn test_unpause_with_wrong_role(){
    let (mut chain, contract_address, _update) = initialize_contract_with_euroe_tokens();

    // Pause the contract.
    let params = SetPausedParams {
        paused: false,
    };

    // The role that is allowed to call the pause function is pauseunpause role
    let update = chain
        .contract_update(SIGNER, ALICE, ALICE_ADDR, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.setPaused".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&params).expect("Pause params"),
        })
        .expect_err("Pause contract");

    // Check that the correct error is returned.
    let rv: ContractError = update.parse_return_value().expect("ContractError return value");
    assert_eq!(rv, ContractError::Unauthorized);
}
// Test to check if the pause functionality is only able to be called by the pauseunpause role
#[test]
fn test_pause_functionality_wrong_role() {
    let (mut chain, contract_address, _update) = initialize_contract_with_euroe_tokens();

    // Pause the contract.
    let params = SetPausedParams {
        paused: true,
    };

    // The role that is allowed to call the pause function is pauseunpause role
    let update = chain
        .contract_update(SIGNER, ALICE, ALICE_ADDR, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.setPaused".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&params).expect("Pause params"),
        })
        .expect_err("Pause contract");

        let rv: ContractError = update.parse_return_value().expect("ContractError return value");
        assert_eq!(rv, ContractError::Unauthorized);

}

// Test that removes roles can only be added by the admin role
#[test]
fn test_remove_roles(){
    let (mut chain, contract_address, _update) = initialize_contract_with_euroe_tokens();

    let roles = RoleTypes {
        mintrole: MINT_ADDRESS_ROLE,
        pauserole: PAUSE_ADDRESS,  
        burnrole: BURN_ADDRESS_ROLE,
        blockrole: BLOCK_ADDRESS,
        adminrole: ADMIN_ADDRESS,
    };

    chain
        .contract_update(SIGNER, ALICE, ALICE_ADDR, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.removeRole".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&roles).expect("Remove roles"),
        })
        .expect("Remove roles");

    // Pause the contract. The following steps should fail, due to role has been removed.
    let params = SetPausedParams {
        paused: true,
    };

    // The role that is allowed to call the pause function is pauseunpause role
    let update = chain
        .contract_update(SIGNER, ALICE, ALICE_ADDR, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.setPaused".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&params).expect("Pause params"),
        })
        .expect_err("Pause contract");

        let rv: ContractError = update.parse_return_value().expect("ContractError return value");
        assert_eq!(rv, ContractError::Unauthorized);
}

// Test removing all roles and re-adding them using Alice as admin.
#[test]
fn test_remove_and_readd_roles(){
    let (mut chain, contract_address, _update) = initialize_contract_with_euroe_tokens();

    // Initialize already grants roles, now we will remove them.

    let roles = RoleTypes {
        mintrole: MINT_ADDRESS_ROLE,
        pauserole: PAUSE_ADDRESS,  
        burnrole: BURN_ADDRESS_ROLE,
        blockrole: BLOCK_ADDRESS,
        adminrole: ADMIN_ADDRESS,
    };

    chain
        .contract_update(SIGNER, ADMIN_ACCOUNT, ADMIN_ADDRESS, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.removeRole".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&roles).expect("Remove roles"),
        })
        .expect("Remove roles");

    // Pause contract params.
    let params = SetPausedParams {
        paused: true,
    };

    // . Lets check if we can pause a contract that has had the pause role removed.
    let update = chain
        .contract_update(SIGNER, PAUSE_ACCOUNT, PAUSE_ADDRESS, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.setPaused".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&params).expect("Pause params"),
        })
        .expect_err("Pause contract");

    // Check that the correct error is returned.
    let rv: ContractError = update.parse_return_value().expect("ContractError return value");

    assert_eq!(rv, ContractError::Unauthorized);

    // Lets re-add the roles, only alice currently is still also the admin.

    let roles = RoleTypes {
        mintrole: MINT_ADDRESS_ROLE,
        pauserole: PAUSE_ADDRESS,  
        burnrole: BURN_ADDRESS_ROLE,
        blockrole: BLOCK_ADDRESS,
        adminrole: ADMIN_ADDRESS,
    };

    chain
        .contract_update(SIGNER, ALICE, ALICE_ADDR, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.grantRole".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&roles).expect("Grant roles"),
        })
        .expect("Grant roles");

    // Pause contract params.
    let params = SetPausedParams {
        paused: true,
    };

    // . Lets check if we can pause a contract that has had the pause role removed.
    chain
        .contract_update(SIGNER, PAUSE_ACCOUNT, PAUSE_ADDRESS, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.setPaused".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&params).expect("Pause params"),
        }).expect("Pause contract");

        // Transfer one EUROe from Alice to Bob.
    let transfer_params = TransferParams::from(vec![concordium_cis2::Transfer {
        from:     ALICE_ADDR,
        to:       Receiver::Account(BOB),
        token_id: EUROE_TOKEN,
        amount:   TokenAmountU64(1),
        data:     AdditionalData::empty(),
    }]);

    let update = chain
        .contract_update(SIGNER, ALICE, ALICE_ADDR, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.transfer".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&transfer_params).expect("Transfer params"),
        })
        .expect_err("Transfer tokens");

    // Check that the correct error is returned.
    let rv: ContractError = update.parse_return_value().expect("ContractError return value");

    assert_eq!(rv, ContractError::Custom(CustomContractError::ContractPaused));
}

// This test is to check when a user is blocked, the user is not able to call any of the  functionality which has
// blocklist as a requirement.
// They are contract_mint, contract_burn, contract_transfer, contract_updateOperator
#[test]
fn test_blocklist_functionality(){
    let (mut chain, contract_address, _update) = initialize_contract_with_euroe_tokens();

    // Block the address.
    let params = BlocklistParams {
        address_to_block: RANDOM_BLOCKLIST_ADDRESS,
    };

    // The role that is allowed to call the block function is blockunblock role
    chain
        .contract_update(SIGNER, BLOCK_ACCOUNT, BLOCK_ADDRESS, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.block".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&params).expect("Block params"),
        })
        .expect("Block contract");


        let mint_params: MintParams = MintParams {
            owner: RANDOM_BLOCKLIST_ADDRESS,
            amount: 400.into(),
        };
    
        let update_mint = chain
            .contract_update(SIGNER, RANDOM_BLOCKLIST_ACCOUNT, RANDOM_BLOCKLIST_ADDRESS, Energy::from(10000), UpdateContractPayload {
                amount:       Amount::zero(),
                receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.mint".to_string()),
                address:      contract_address,
                message:      OwnedParameter::from_serial(&mint_params).expect("Mint params"),
            })
            .expect_err("Mint tokens");
    
        // Check that the correct error is returned.
        let mint_rv: ContractError = update_mint.parse_return_value().expect("ContractError return value");
        assert_eq!(mint_rv, ContractError::Custom(CustomContractError::AddressBlocklisted));

        let burn_params: BurnParams = BurnParams {
            burnaddress: RANDOM_BLOCKLIST_ADDRESS,
            amount: 100.into(),
        };
    
        let update_burn = chain
            .contract_update(SIGNER, BURN_ACCOUNT, BURN_ADDRESS_ROLE, Energy::from(10000), UpdateContractPayload {
                amount:       Amount::zero(),
                receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.burn".to_string()),
                address:      contract_address,
                message:      OwnedParameter::from_serial(&burn_params).expect("Burn params"),
            })
            .expect_err("Burn tokens");
    
        // Check that the correct error is returned.
        let burn_rv: ContractError = update_burn.parse_return_value().expect("ContractError return value");
        assert_eq!(burn_rv, ContractError::Custom(CustomContractError::AddressBlocklisted));

         // Transfer one EUROe from Alice to Bob.
    let transfer_params = TransferParams::from(vec![concordium_cis2::Transfer {
        from:     RANDOM_BLOCKLIST_ADDRESS,
        to:       Receiver::Account(BOB),
        token_id: EUROE_TOKEN,
        amount:   TokenAmountU64(1),
        data:     AdditionalData::empty(),
    }]);

    let tranfer_update = chain
        .contract_update(SIGNER, RANDOM_BLOCKLIST_ACCOUNT, RANDOM_BLOCKLIST_ADDRESS, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.transfer".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&transfer_params).expect("Transfer params"),
        })
        .expect_err("Transfer tokens");

    // Check that the correct error is returned.
    let transfer_rv: ContractError = tranfer_update.parse_return_value().expect("ContractError return value");

    assert_eq!(transfer_rv, ContractError::Custom(CustomContractError::AddressBlocklisted));
        
}

// Testing that the blocklist func returns unauthorized when the user is not the blockunblock role
#[test]
fn test_blocklist_functionality_with_wrong_role(){
    let (mut chain, contract_address, _update) = initialize_contract_with_euroe_tokens();

    // Block the address.
    let params = BlocklistParams {
        address_to_block: RANDOM_BLOCKLIST_ADDRESS,
    };

    // The role that is allowed to call the block function is blockunblock role
   let update=  chain
        .contract_update(SIGNER, ADMIN_ACCOUNT, ADMIN_ADDRESS, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.block".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&params).expect("Block params"),
        })
        .expect_err("Block contract");

    // Check that the correct error is returned.
    let transfer_rv: ContractError = update.parse_return_value().expect("ContractError return value");

    assert_eq!(transfer_rv, ContractError::Unauthorized);
}

// Test that we block a address then unblock that address and mint to it. 
#[test]
fn block_address_from_mint_then_unblock() {
    let (mut chain, contract_address, _update) = initialize_contract_with_euroe_tokens();

    // Block the contract.
    let params = BlocklistParams {
        address_to_block: BOB_ADDR,
    };

    // The role that is allowed to call the block function is blockunblock role
    chain
        .contract_update(SIGNER, BLOCK_ACCOUNT, BLOCK_ADDRESS, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.block".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&params).expect("Block params"),
        })
        .expect("Block contract");

    // Attempt to mint tokens.
    let mint_params: MintParams = MintParams {
        owner: BOB_ADDR,
        amount: 400.into(),
    };

    let update = chain
        .contract_update(SIGNER, MINT_ACCOUNT, MINT_ADDRESS_ROLE, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.mint".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&mint_params).expect("Mint params"),
        })
        .expect_err("Mint tokens");

    // Check that the correct error is returned.
    let rv: ContractError = update.parse_return_value().expect("ContractError return value");
    assert_eq!(rv, ContractError::Custom(CustomContractError::AddressBlocklisted));

    // now lets unblock this role and mint again. 
    let params = UnBlocklistParams {
        address_to_unblock: BOB_ADDR,
    };

    // The role that is allowed to call the block function is blockunblock role
    chain
        .contract_update(SIGNER, BLOCK_ACCOUNT, BLOCK_ADDRESS, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.unblock".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&params).expect("unBlock params"),
        })
        .expect("unBlock contract");

    chain
        .contract_update(SIGNER, MINT_ACCOUNT, MINT_ADDRESS_ROLE, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.mint".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&mint_params).expect("Mint params"),
        })
        .expect("Mint tokens");

    // Check balances in state.
    let balance_of_alice_and_bob = get_balances(&chain, contract_address);

    assert_eq!(balance_of_alice_and_bob.0, [TokenAmountU64(400), TokenAmountU64(400)]);
}

// Unblock is unauthorised due to wrong role.
#[test]
fn test_unblock_fail_with_wrong_role(){
    let (mut chain, contract_address, _update) = initialize_contract_with_euroe_tokens();

    // Block the address.
    let params = UnBlocklistParams {
        address_to_unblock: RANDOM_BLOCKLIST_ADDRESS,
    };

    // The role that is allowed to call the block function is blockunblock role
   let update=  chain
        .contract_update(SIGNER, ADMIN_ACCOUNT, ADMIN_ADDRESS, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.unblock".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&params).expect("Block params"),
        })
        .expect_err("Block contract");

    // Check that the correct error is returned.
    let transfer_rv: ContractError = update.parse_return_value().expect("ContractError return value");

    assert_eq!(transfer_rv, ContractError::Unauthorized);
}
/// Test permit update operator function. The signature is generated in the test
/// case. ALICE adds BOB as an operator.
#[test]
fn test_inside_signature_permit_update_operator() {
    let (mut chain, contract_address, _update, keypairs) =
        initialize_contract_with_alice_tokens_for_permit(true);

    // Check operator in state
    let bob_is_operator_of_alice = operator_of(&chain, contract_address);

    assert_eq!(bob_is_operator_of_alice, OperatorOfQueryResponse(vec![false]));

    // Create input parameters for the `permit` updateOperator function.
    let update_operator = UpdateOperator {
        update:   OperatorUpdate::Add,
        operator: BOB_ADDR,
    };
    let payload = UpdateOperatorParams(vec![update_operator]);

    // The `viewMessageHash` function uses the same input parameter `PermitParam` as
    // the `permit` function. The `PermitParam` type includes a `signature` and
    // a `signer`. Because these two values (`signature` and `signer`) are not
    // read in the `viewMessageHash` function, any value can be used and we choose
    // to use `DUMMY_SIGNATURE` and `ALICE` in the test case below.
    let signature_map = BTreeMap::from([(0u8, CredentialSignatures {
        sigs: BTreeMap::from([(0u8, concordium_std::Signature::Ed25519(DUMMY_SIGNATURE))]),
    })]);

    let mut permit_update_operator_param = PermitParam {
        signature: AccountSignatures {
            sigs: signature_map,
        },
        signer:    ALICE,
        message:   PermitMessage {
            timestamp:        Timestamp::from_timestamp_millis(10_000_000_000),
            contract_address: ContractAddress::new(0, 0),
            entry_point:      OwnedEntrypointName::new_unchecked("updateOperator".into()),
            nonce:            0,
            payload:          to_bytes(&payload),
        },
    };

    // Get the message hash to be signed.
    let invoke = chain
        .contract_invoke(BOB, BOB_ADDR, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            address:      contract_address,
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.viewMessageHash".to_string()),
            message:      OwnedParameter::from_serial(&permit_update_operator_param)
                .expect("Should be a valid inut parameter"),
        })
        .expect("Should be able to query viewMessageHash");

    let message_hash: HashSha2256 =
        from_bytes(&invoke.return_value).expect("Should return a valid result");

    permit_update_operator_param.signature = keypairs
        .expect("Should have a generated private key to sign")
        .sign_message(&to_bytes(&message_hash));

    // Update operator with the permit function.
    let update = chain
        .contract_update(
            Signer::with_one_key(),
            CHARLIE,
            Address::Account(CHARLIE),
            Energy::from(10000),
            UpdateContractPayload {
                amount:       Amount::zero(),
                address:      contract_address,
                receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.permit".to_string()),
                message:      OwnedParameter::from_serial(&permit_update_operator_param)
                    .expect("Should be a valid inut parameter"),
            },
        )
        .expect("Should be able to update operator with permit");

    // Check that the correct events occurred.
    let events = update
        .events()
        .flat_map(|(_addr, events)| events.iter().map(|e| e.parse().expect("Deserialize event")))
        .collect::<Vec<Event>>();

    assert_eq!(events, [
        Event::Cis2Event(Cis2Event::UpdateOperator(UpdateOperatorEvent {
            update:   OperatorUpdate::Add,
            owner:    ALICE_ADDR,
            operator: BOB_ADDR,
        })),
        Event::Nonce(NonceEvent {
            account: ALICE,
            nonce:   0,
        })
    ]);

    // Check operator in state
    let bob_is_operator_of_alice = operator_of(&chain, contract_address);

    assert_eq!(bob_is_operator_of_alice, OperatorOfQueryResponse(vec![true]));
}

/// Test permit update operator function. The signature is generated outside
/// this test case (e.g. with https://cyphr.me/ed25519_tool/ed.html). ALICE adds BOB as an operator.
#[test]
fn test_outside_signature_permit_update_operator() {
    let (mut chain, contract_address, _update, _keypairs) =
        initialize_contract_with_alice_tokens_for_permit(false);

    // Check operator in state
    let bob_is_operator_of_alice = operator_of(&chain, contract_address);

    assert_eq!(bob_is_operator_of_alice, OperatorOfQueryResponse(vec![false]));

    // Create input parameters for the `permit` updateOperator function.
    let update_operator = UpdateOperator {
        update:   OperatorUpdate::Add,
        operator: BOB_ADDR,
    };
    let payload = UpdateOperatorParams(vec![update_operator]);

    let mut inner_signature_map = BTreeMap::new();
    inner_signature_map.insert(0u8, concordium_std::Signature::Ed25519(SIGNATURE_UPDATE_OPERATOR));

    let mut signature_map = BTreeMap::new();
    signature_map.insert(0u8, CredentialSignatures {
        sigs: inner_signature_map,
    });

    let permit_update_operator_param = PermitParam {
        signature: AccountSignatures {
            sigs: signature_map,
        },
        signer:    ALICE,
        message:   PermitMessage {
            timestamp:        Timestamp::from_timestamp_millis(10_000_000_000),
            contract_address: ContractAddress::new(0, 0),
            entry_point:      OwnedEntrypointName::new_unchecked("updateOperator".into()),
            nonce:            0,
            payload:          to_bytes(&payload),
        },
    };

    // Update operator with the permit function.
    let update = chain
        .contract_update(
            Signer::with_one_key(),
            CHARLIE,
            Address::Account(CHARLIE),
            Energy::from(10000),
            UpdateContractPayload {
                amount:       Amount::zero(),
                address:      contract_address,
                receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.permit".to_string()),
                message:      OwnedParameter::from_serial(&permit_update_operator_param)
                    .expect("Should be a valid inut parameter"),
            },
        )
        .expect("Should be able to update operator with permit");

    // Check that the correct events occurred.
    let events = update
        .events()
        .flat_map(|(_addr, events)| events.iter().map(|e| e.parse().expect("Deserialize event")))
        .collect::<Vec<Event>>();

    assert_eq!(events, [
        Event::Cis2Event(Cis2Event::UpdateOperator(UpdateOperatorEvent {
            update:   OperatorUpdate::Add,
            owner:    ALICE_ADDR,
            operator: BOB_ADDR,
        })),
        Event::Nonce(NonceEvent {
            account: ALICE,
            nonce:   0,
        })
    ]);

    // Check operator in state
    let bob_is_operator_of_alice = operator_of(&chain, contract_address);

    assert_eq!(bob_is_operator_of_alice, OperatorOfQueryResponse(vec![true]));
}

/// Test permit transfer function. The signature is generated in the test case.
/// EUROE_TOKEN is transferred from Alice to Bob.
#[test]
fn test_inside_signature_permit_transfer() {
    let (mut chain, contract_address, _update, keypairs) =
        initialize_contract_with_alice_tokens_for_permit(true);

    // Check balances in state.
    let balance_of_alice_and_bob = get_balances(&chain, contract_address);

    assert_eq!(balance_of_alice_and_bob.0, [TokenAmountU64(400), TokenAmountU64(0)]);

    // Create input parameters for the `permit` transfer function.
    let transfer = concordium_cis2::Transfer {
        from:     ALICE_ADDR,
        to:       Receiver::from_account(BOB),
        token_id: EUROE_TOKEN,
        amount:   ContractTokenAmount::from(1),
        data:     AdditionalData::empty(),
    };
    let payload = TransferParams::from(vec![transfer]);

    // The `viewMessageHash` function uses the same input parameter `PermitParam` as
    // the `permit` function. The `PermitParam` type includes a `signature` and
    // a `signer`. Because these two values (`signature` and `signer`) are not
    // read in the `viewMessageHash` function, any value can be used and we choose
    // to use `DUMMY_SIGNATURE` and `ALICE` in the test case below.
    let signature_map = BTreeMap::from([(0u8, CredentialSignatures {
        sigs: BTreeMap::from([(0u8, concordium_std::Signature::Ed25519(DUMMY_SIGNATURE))]),
    })]);

    let mut permit_transfer_param = PermitParam {
        signature: AccountSignatures {
            sigs: signature_map,
        },
        signer:    ALICE,
        message:   PermitMessage {
            timestamp:        Timestamp::from_timestamp_millis(10_000_000_000),
            contract_address: ContractAddress::new(0, 0),
            entry_point:      OwnedEntrypointName::new_unchecked("transfer".into()),
            nonce:            0,
            payload:          to_bytes(&payload),
        },
    };

    // Get the message hash to be signed.
    let invoke = chain
        .contract_invoke(BOB, BOB_ADDR, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            address:      contract_address,
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.viewMessageHash".to_string()),
            message:      OwnedParameter::from_serial(&permit_transfer_param)
                .expect("Should be a valid inut parameter"),
        })
        .expect("Should be able to query viewMessageHash");

    let message_hash: HashSha2256 =
        from_bytes(&invoke.return_value).expect("Should return a valid result");

    permit_transfer_param.signature = keypairs
        .expect("Should have a generated private key to sign")
        .sign_message(&to_bytes(&message_hash));

    // Transfer token with the permit function.
    let update = chain
        .contract_update(
            Signer::with_one_key(),
            BOB,
            BOB_ADDR,
            Energy::from(10000),
            UpdateContractPayload {
                amount:       Amount::zero(),
                address:      contract_address,
                receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.permit".to_string()),
                message:      OwnedParameter::from_serial(&permit_transfer_param)
                    .expect("Should be a valid inut parameter"),
            },
        )
        .expect("Should be able to transfer token with permit");

    // Check that the correct events occurred.
    let events = update
        .events()
        .flat_map(|(_addr, events)| events.iter().map(|e| e.parse().expect("Deserialize event")))
        .collect::<Vec<Event>>();

    assert_eq!(events, [
        Event::Cis2Event(Cis2Event::Transfer(TransferEvent {
            token_id: EUROE_TOKEN,
            amount:   ContractTokenAmount::from(1),
            from:     ALICE_ADDR,
            to:       BOB_ADDR,
        })),
        Event::Nonce(NonceEvent {
            account: ALICE,
            nonce:   0,
        })
    ]);

    // Check balances in state.
    let balance_of_alice_and_bob = get_balances(&chain, contract_address);

    assert_eq!(balance_of_alice_and_bob.0, [TokenAmountU64(399), TokenAmountU64(1)]);
}

/// Helper function that sets up the contract with tokens minted to Alice.
/// Alice has 400 of `EUROE_TOKEN`.
fn initialize_contract_with_euroe_tokens() -> (Chain, ContractAddress, ContractInvokeSuccess) {
    let (mut chain, contract_address) = initialize_chain_and_contract();

    let mint_params = MintParams {
                    owner: ALICE_ADDR,
                    amount: 400.into(),
                };

    // Mint tokens for which Alice is the owner.
    let update = chain
        .contract_update(SIGNER, ALICE, MINT_ADDRESS_ROLE, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.mint".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&mint_params).expect("Mint params"),
        })
        .expect("Mint tokens");

    (chain, contract_address, update)
}

/// Setup chain and contract.
fn initialize_chain_and_contract() -> (Chain, ContractAddress) {
    let mut chain = Chain::new();

    // Create some accounts accounts on the chain.
    chain.create_account(Account::new(ALICE, ACC_INITIAL_BALANCE));
    chain.create_account(Account::new(BOB, ACC_INITIAL_BALANCE));
    chain.create_account(Account::new(MINT_ACCOUNT, ACC_INITIAL_BALANCE));
    chain.create_account(Account::new(BURN_ACCOUNT, ACC_INITIAL_BALANCE));
    chain.create_account(Account::new(PAUSE_ACCOUNT, ACC_INITIAL_BALANCE));
    chain.create_account(Account::new(ADMIN_ACCOUNT, ACC_INITIAL_BALANCE));
    chain.create_account(Account::new(BLOCK_ACCOUNT, ACC_INITIAL_BALANCE));
    chain.create_account(Account::new(RANDOM_BLOCKLIST_ACCOUNT, ACC_INITIAL_BALANCE));
    chain.create_account(Account::new(CHARLIE, ACC_INITIAL_BALANCE));
    chain.create_account(Account::new(RANDOM_MINT_ACCOUNT, ACC_INITIAL_BALANCE));
    
    // Load and deploy the module.
    let module = module_load_v1("dist/module.wasm.v1").expect("Module exists");
    let deployment = chain.module_deploy_v1(SIGNER, ALICE, module).expect("Deploy valid module");
    
    let init = chain
        .contract_init(SIGNER, ALICE, Energy::from(10000), InitContractPayload {
            amount:    Amount::zero(),
            mod_ref:   deployment.module_reference,
            init_name: OwnedContractName::new_unchecked("init_euroe_stablecoin".to_string()),
            param:     OwnedParameter::empty(),
        })
        .expect("Initialize contract");
    
    // Lets add permissions to the contract

    let roles = RoleTypes {
        mintrole: MINT_ADDRESS_ROLE,
        pauserole: PAUSE_ADDRESS,  
        burnrole: BURN_ADDRESS_ROLE,
        blockrole: BLOCK_ADDRESS,
        adminrole: ADMIN_ADDRESS,
    };

    chain
        .contract_update(SIGNER, ALICE, ALICE_ADDR, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.grantRole".to_string()),
            address:      init.contract_address,
            message:      OwnedParameter::from_serial(&roles).expect("Grant roles"),
        })
        .expect("Grant roles");

    (chain, init.contract_address)
}

/// Get the `EUROE` balances for Alice and Bob.
fn get_balances(
    chain: &Chain,
    contract_address: ContractAddress,
) -> ContractBalanceOfQueryResponse {
    let balance_of_params = ContractBalanceOfQueryParams {
        queries: vec![
            BalanceOfQuery {
                token_id: EUROE_TOKEN,
                address:  ALICE_ADDR,
            },
            BalanceOfQuery {
                token_id: EUROE_TOKEN,
                address:  BOB_ADDR,
            },
        ],
    };

    let invoke = chain
        .contract_invoke(ALICE, ALICE_ADDR, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.balanceOf".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&balance_of_params)
                .expect("BalanceOf params"),
        })
        .expect("Invoke balanceOf");
    let rv: ContractBalanceOfQueryResponse =
        invoke.parse_return_value().expect("BalanceOf return value");
    rv
}

/// Check if Bob is an operator of Alice.
fn operator_of(chain: &Chain, contract_address: ContractAddress) -> OperatorOfQueryResponse {
    let operator_of_params = OperatorOfQueryParams {
        queries: vec![OperatorOfQuery {
            address: BOB_ADDR,
            owner:   ALICE_ADDR,
        }],
    };

    // Check operator in state
    let invoke = chain
        .contract_invoke(ALICE, ALICE_ADDR, Energy::from(10000), UpdateContractPayload {
            amount:       Amount::zero(),
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.operatorOf".to_string()),
            address:      contract_address,
            message:      OwnedParameter::from_serial(&operator_of_params)
                .expect("OperatorOf params"),
        })
        .expect("Invoke operatorOf");
    let rv: OperatorOfQueryResponse = invoke.parse_return_value().expect("OperatorOf return value");
    rv
}

/// Helper function that sets up the contract for permits.
fn initialize_contract_with_alice_tokens_for_permit(
    generate_keys: bool,
) -> (Chain, ContractAddress, ContractInvokeSuccess, Option<AccountKeys>) {
    let (mut chain, contract_address, keypairs) = initialize_chain_and_contract_for_permit(generate_keys);

    let mint_params = MintParams {
        owner: ALICE_ADDR,
        amount: 400.into(),
    };

        // Mint tokens for which Alice
    let update = chain
        .contract_update(SIGNER, ALICE, MINT_ADDRESS_ROLE, Energy::from(10000), UpdateContractPayload {
        amount:       Amount::zero(),
        receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.mint".to_string()),
        address:      contract_address,
        message:      OwnedParameter::from_serial(&mint_params).expect("Mint params"),
        })
        .expect("Mint tokens");

    (chain, contract_address, update, keypairs)
}

/// Setup chain and contract.
///
/// Also creates the three accounts, Alice, Bob, and Charlie.
///
/// Alice is the admin in the beginning and has the admin role.
/// Alice's account is created with keys.
/// Hence, Alice's account signature can be checked in the test cases.
fn initialize_chain_and_contract_for_permit(
    generate_keys: bool,
) -> (Chain, ContractAddress, Option<AccountKeys>) {
    let mut chain = Chain::new();

    let (account_access_structure, keypairs) = match generate_keys {
        // If `generate_keys` is true, fresh keys are generated for Alice.
        // Since Alice's private key is available, Alice can sign and generate a valid signature in
        // the test cases.
        true => {
            let rng = &mut rand::thread_rng();

            let keypairs = AccountKeys::singleton(rng);
            ((&keypairs).into(), Some(keypairs))
        }
        // If `generate_keys` is false, Alice's account is assigned a hardcoded public key.
        // Since Alice's private key is NOT available, hardcoded signatures are used in the test
        // cases. The signatures are generated outside the test cases (e.g. with https://cyphr.me/ed25519_tool/ed.html).
        // NOTE: I am using the true version above here in false since 
        // this PR https://github.com/Concordium/concordium-rust-smart-contracts/pull/359/files 
        // has not been merged and i am unable to use the code below
        false => (
            AccountAccessStructure::singleton(
                ed25519::PublicKey::from_bytes(&PUBLIC_KEY)
                    .expect("Should be able to construct public key from bytes."),
            ),
            None,
        ),
    };

    let balance = AccountBalance {
        total:  ACC_INITIAL_BALANCE,
        staked: Amount::zero(),
        locked: Amount::zero(),
    };

    // Create some accounts accounts on the chain.
    chain.create_account(Account::new_with_keys(ALICE, balance, account_access_structure));
    chain.create_account(Account::new(CHARLIE, ACC_INITIAL_BALANCE));
    chain.create_account(Account::new(BOB, ACC_INITIAL_BALANCE));

    // Load and deploy the module.
    let module = module_load_v1("dist/module.wasm.v1").expect("Module exists");
    let deployment = chain.module_deploy_v1(SIGNER, ALICE, module).expect("Deploy valid module");

    // Initialize the auction contract.
    let init = chain
        .contract_init(SIGNER, ALICE, Energy::from(10000), InitContractPayload {
            amount:    Amount::zero(),
            mod_ref:   deployment.module_reference,
            init_name: OwnedContractName::new_unchecked("init_euroe_stablecoin".to_string()),
            param:     OwnedParameter::empty(),
        })
        .expect("Initialize contract");


        let roles = RoleTypes {
            mintrole: MINT_ADDRESS_ROLE,
            pauserole: PAUSE_ADDRESS,  
            burnrole: BURN_ADDRESS_ROLE,
            blockrole: BLOCK_ADDRESS,
            adminrole: ADMIN_ADDRESS,
        };
    
        chain
            .contract_update(SIGNER, ALICE, ALICE_ADDR, Energy::from(10000), UpdateContractPayload {
                amount:       Amount::zero(),
                receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.grantRole".to_string()),
                address:      init.contract_address,
                message:      OwnedParameter::from_serial(&roles).expect("Grant roles"),
            })
            .expect("Grant roles");

    (chain, init.contract_address, keypairs)
}
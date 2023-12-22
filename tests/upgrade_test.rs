//! Integration tests for the euroe_stablecoin  contract.

use euroe_stablecoin::*;
use concordium_smart_contract_testing::*;
/// The tests accounts.

const MINT_ACCOUNT: AccountAddress = AccountAddress([2u8; 32]);
const MINT_ADDRESS_ROLE: Address = Address::Account(MINT_ACCOUNT);

const BURN_ACCOUNT: AccountAddress = AccountAddress([2u8; 32]);
const BURN_ADDRESS_ROLE: Address = Address::Account(BURN_ACCOUNT);

const PAUSE_ACCOUNT: AccountAddress = AccountAddress([2u8; 32]);
const PAUSE_ADDRESS: Address = Address::Account(PAUSE_ACCOUNT);

const ADMIN_ACCOUNT: AccountAddress = AccountAddress([2u8; 32]);
const ADMIN_ADDRESS: Address = Address::Account(ADMIN_ACCOUNT);

const BLOCK_ACCOUNT: AccountAddress = AccountAddress([2u8; 32]);
const BLOCK_ADDRESS: Address = Address::Account(BLOCK_ACCOUNT);

const RANDOM_BLACKLIST_ACCOUNT: AccountAddress = AccountAddress([2u8; 32]);


// Alice is considered the admin of the contract for the following tests.
// Alice assigns the role as she gets the admin role in the initialize function.
const ALICE: AccountAddress = AccountAddress([0; 32]);
const ALICE_ADDR: Address = Address::Account(ALICE);
const BOB: AccountAddress = AccountAddress([1; 32]);

/// Initial balance of the accounts.
const ACC_INITIAL_BALANCE: Amount = Amount::from_ccd(10000);

/// A signer for all the transactions.
const SIGNER: Signer = Signer::with_one_key();

// The below test is ignored when running `cargo test` as you would need to manually create another version of the contract.
// Follow these instructions to run this test. 
// Change the name of the contract in Cargo.toml and in the lib.rs file to `contract_version1`.
// Build the code `cargo concordium build --schema-embed --out dist-version2/module.wasm.v1 --schema-out dist-version2/schema.bin`
// Now you can run the test with `cargo test` by removing ignore.
#[ignore]
#[test]
fn test_upgrade_with_migration_function() {
    let (mut chain, contract_address, _update) = initialize_contract_with_euroe_tokens();

    // Deploy 'the same contract' module as the one already deployed.

    // Load and deploy the second contract module.
    let module = module_load_v1("dist-version2/module.wasm.v1").expect("Module exists");
    let deployment = chain.module_deploy_v1(SIGNER, ALICE, module).expect("Deploy valid module");

    let input_parameter = UpgradeParams {
        module:  deployment.module_reference,
        migrate: None,
    };

    // Upgrade `contract_version1` to `contract_version2`.
    let update = chain.contract_update(
        Signer::with_one_key(), // Used for specifying the number of signatures.
        ADMIN_ACCOUNT,         // Invoker account.
        Address::Account(ADMIN_ACCOUNT), // Sender (can also be a contract).
        Energy::from(10000),    // Maximum energy allowed for the update.
        UpdateContractPayload {
            address: contract_address, // The contract to update.
            receive_name: OwnedReceiveName::new_unchecked("euroe_stablecoin.upgrade".into()), // The receive function to call.
            message: OwnedParameter::from_serial(&input_parameter)
                .expect("`UpgradeParams` should be a valid inut parameter"), // The parameter sent to the contract.
            amount: Amount::from_ccd(0), // Sending the contract 0 CCD.
        },
    );

    assert!(update.is_ok(), "Upgrade should succeed");

    // lets invoke and see that the balance of Alice is still 400 EUROe after the upgrade.

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
    chain.create_account(Account::new(RANDOM_BLACKLIST_ACCOUNT, ACC_INITIAL_BALANCE));
    

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
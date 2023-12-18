# EUROe on Concordium

This repository contains the EUROe stablecoin smart contract for the Concordium blockchain. Please find the higher level visual documentation on the [EUROe Developer Portal](https://dev.euroe.com/docs/Stablecoin/overview).

## Directory Structure

This directory contains four sub-directories:
1. `dist` - Contains the compiled version of the contract.
2. `interaction` - Holds JSON files used for contract interaction.
3. `src` - The main contract code resides here.
4. `tests` - Contains the tests.


The `Cargo.toml` file includes details such as the contract name and other dependencies.


### Contract Functions

The contract has the following functions:

  - 'balanceOf'       : 610 B
  - 'block'     : 596 B
  - 'burn'      : 606 B
  - 'grantRole'       : 799 B
  - 'mint'      : 600 B
  - 'operatorOf'      : 641 B
  - 'permit'    : 156 B
  - 'removeRole'      : 799 B
  - 'setImplementors' : 563 B
  - 'setPaused'       : 547 B
  - 'supports'  : 588 B
  - 'supportsPermit'  : 605 B
  - 'tokenMetadata'   : 591 B
  - 'transfer'  : 673 B
  - 'unblock'   : 598 B
  - 'updateOperator'  : 624 B
  - 'upgrade'   : 516 B
  - 'view'      : 142 B
  - 'viewMessageHash' : 162 B
  - 'viewSupply'      : 34 B


### Roles in the Contract

Roles used to invoke various contract functions are as follows:

- `AdminRole` - Handles other functionalities called via the admin, such as `setImplementors`, `updateOperator`, `upgrade`
- `BlockRole` - Blocks or unblocks an address
- `BurnRole` - Calls the burn function
- `MintRole` - Calls the mint function
- `PauseUnpauseRole` - Pauses or unpauses the contract

## Contract Tests

To run the tests, execute `cargo test`.
The tests are under `tests/test.rs`.
Remember to build first before running the tests, since it uses the dist/module.wasm.v1. Build instructions are provided below.



### Test coverage

The below list provides an overview of existing test coverage and backlog items for tests.

- Roles
  - OK/ Assigning roles as admin
  - OK/ Assigning roles as unauthorised
  - Removing roles as admin
  - Removing roles as unauthorised
- Minting
  - OK/ Minting as unauthorised
  - OK/ Minting as authorised
  - OK/ Minting to blocklisted address
  - OK/ Calling mint from a blocklisted address
  - OK/ Minting when contract is paused
- Burning
  - OK/ Burning as unauthorised
  - OK/ Burning as authorised
  - Burning with insufficient balance
  - OK/ Burning from a blocklisted address
  - OK/ Calling burn froma  blocklisted address
  - OK/ Burning when contract is paused
- Transferring 
  - OK/ Transferring as unauthorised (not token owner nor operator)
  - OK/ Transferring as authorised owner
  - Transferring with insufficient balance
  - OK/ Transferring to a blocklisted address
  - OK/ Transferring from a blocklisted address
  - OK/ Transferring when contract is paused
- Pausing and unpausing
  - OK/ Pausing as unauthorised
  - OK/ Pausing as authorised
  - Unpausing as unauthorised
  - Unpausing as authorised
- Blocklisting and unblocklisting
  - Blocking as unauthorised
  - Blocking as authorised
  - Unblocking as unauthorised
  - Unblocking as unauthorised
- Operators
  - OK/ Assigning an operator
  - Unassigning an operator
  - OK/ Blocklisted address authorising an operator
  - Blocklisted address assigned as an operator
  - OK/ Operator transfer works
  - Operator transfers to a blocklisted address
  - Operator transfers from a blocklisted address
  - Operator transfers when operator is blocklisted
  - Operator transfers during contract pause
  - Operator assigned during contract pause
  - Operator un-assigned during contract pause
- CIS2
  - Contract supports CIS2
  - OK/ Metadata URL is correct
- CIS3
  - Contract supports permit
  - View message hash works
  - OK/ Updating operator with permit works
  - OK/ Transfering with permit works
  - Nonce is incremented correctly
- Contract upgrade
  - Upgrade works 
- Miscellaneous
  - OK/ Circulating supply works
  - Circulating supply works correctly (randomised mints & burns)


## Compilation and Interaction Instructions for testnet

```bash
# Building the contract
cargo concordium build --schema-embed --out dist/module.wasm.v1 --schema-out dist/schema.bin

# Deploying the contract
concordium-client module deploy dist/module.wasm.v1 --sender <sender_address> --name euroe_stablecoin --energy 6000 --grpc-ip node.testnet.concordium.com --grpc-port 20000

# Initializing the contract
concordium-client contract init <module_reference> --sender <sender_address> --contract euroe_stablecoin --energy 6000 --grpc-ip node.testnet.concordium.com --grpc-port 20000
```

## Compilation and Interaction Instructions for mainnet
```bash
# Building the contract
cargo concordium build --schema-embed --out dist/module.wasm.v1 --schema-out dist/schema.bin

# Deploying the contract
concordium-client --secure module deploy dist/module.wasm.v1 --sender <sender_address> --name euroe_stablecoin --energy 6000 --grpc-ip grpc.mainnet.concordium.software --grpc-port 20000

# Initializing the contract
concordium-client --secure contract init <module_reference> --sender <sender_address> --contract euroe_stablecoin --energy 6000 --grpc-ip grpc.mainnet.concordium.software --grpc-port 20000
```

### Additional Commands

Additional commands are available for functionalities such as minting, burning, and transferring tokens. Please refer to the sections below for more details.
The commands below use the files from the `interaction` folder.

```bash
# Mint
concordium-client contract update <contract_id> --entrypoint mint --parameter-json interaction/mint2.json --schema dist/schema.bin --sender <sender_address> --energy 6000 --grpc-ip node.testnet.concordium.com --grpc-port 20000

# View
concordium-client contract invoke <contract_id> --entrypoint view --grpc-ip node.testnet.concordium.com --grpc-port 20000

# Transfer
concordium-client contract update <contract_id> --entrypoint transfer --parameter-json interaction/transfer.json --sender <sender_address> --energy 6000 --grpc-ip node.testnet.concordium.com --grpc-port 20000

# Burn
concordium-client contract update <contract_id> --entrypoint burn --parameter-json interaction/burn.json --sender <sender_address> --energy 6000 --grpc-ip node.testnet.concordium.com --grpc-port 20000

# Pause
concordium-client contract update <contract_id> --entrypoint setPaused --parameter-json interaction/pause.json --sender <sender_address> --energy 6000 --grpc-ip node.testnet.concordium.com --grpc-port 20000

# Unpause
concordium-client contract update <contract_id> --entrypoint setPaused --parameter-json interaction/pause.json --sender <sender_address> --energy 6000 --grpc-ip node.testnet.concordium.com --grpc-port 20000

# Add role
concordium-client contract update <contract_id> --entrypoint grantRole --parameter-json interaction/auth.json --schema dist/schema.bin --sender <sender_address> --energy 6000 --grpc-ip node.testnet.concordium.com --grpc-port 20000

# Remove role
concordium-client contract update <contract_id> --entrypoint removeRole --parameter-json interaction/auth.json --schema dist/schema.bin --sender <sender_address> --energy 6000 --grpc-ip node.testnet.concordium.com --grpc-port 20000

# Upgrade contract
concordium-client contract update <contract_id> --entrypoint upgrade --parameter-json interaction/upgrade.json --energy 5000 --sender <sender_address> --grpc-ip node.testnet.concordium.com --grpc-port 20000

```


### Adding another wallet to the concordium client 
To add a wallet to invoke this contract, you will have to export a wallet from the web wallet.
Then use the below command.
`concordium-client config account import <imported-wallet-name> --name <name-you-want-to-use-for-wallet>`
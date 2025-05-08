# Seed Phrase to Address

A Rust-based command-line tool that converts BIP39 seed phrases to Bitcoin addresses. This tool implements the BIP32, BIP39, and BIP84 standards for hierarchical deterministic wallet generation.

## Features

-   Converts BIP39 mnemonic phrases to Bitcoin addresses
-   Supports both mainnet and testnet
-   Generates multiple addresses from a single seed phrase
-   Supports custom account and change indices
-   Implements BIP84 (Native SegWit) address generation

## Prerequisites

-   Rust and Cargo (latest stable version recommended)

## Installation

1. Clone the repository:

```bash
git clone https://github.com/Toskosz/seed-phrase-to-address.git
cd seed-phrase-to-address
```

2. Build the project:

```bash
cargo build --release
```

## Usage

```bash
./target/release/seed-phrase-to-address "your twelve word seed phrase here" [options]
```

### Options

-   `--passphrase <PASSPHRASE>`: Optional passphrase for the seed (default: empty)
-   `--count <COUNT>`: Number of addresses to generate (default: 1)
-   `--network <NETWORK>`: Network to use (mainnet or testnet, default: mainnet)
-   `--account <ACCOUNT>`: Account index (default: 0)
-   `--change-flag <CHANGE_FLAG>`: Change flag (default: 0)

### Examples

Generate a mainnet address:

```bash
./target/release/seed-phrase-to-address "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
```

Generate multiple testnet addresses:

```bash
./target/release/seed-phrase-to-address "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" --network testnet --count 5
```

## Dependencies

-   anyhow: Error handling
-   bitvec: Bit manipulation
-   clap: Command-line argument parsing
-   sha2: SHA-256 hashing
-   pbkdf2: Key derivation
-   k256: Elliptic curve operations
-   hmac: HMAC implementation
-   ripemd: RIPEMD-160 hashing
-   hex: Hexadecimal encoding/decoding

## Security Warning

This tool is for educational purposes. Never enter your real seed phrase into any software unless you fully understand the implications and trust the software completely.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

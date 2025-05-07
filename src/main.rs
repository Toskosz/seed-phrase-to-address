mod bip39;
mod bip32;
mod bech32;
mod address;

use bip32::ExtPriv;
use clap::{Arg, Parser};

#[derive(Parser)]
struct Args {
    /// 12 or 12 word BIP39 mnemonic
    mnemonic: String,
    #[arg(long, default_value_t = String::new())] 
    passphrase: String,
    #[arg(long, default_value_t = 1)]
    count: u32,
    #[arg(long, default_value = "mainnet")]
    network: String,
    #[arg(long, default_value_t = 0)]
    account: u32,
    #[arg(long, default_value_t = 0)]
    change_flag: u32,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    bip39::mnemonic_to_entropy(&args.mnemonic)?;
    let seed = bip39::seed_from_mnemonic(&args.mnemonic, &args.passphrase)?;
    
    // print hex seed
    let seed_hex = hex::encode(&seed);
    println!("seed: {}", seed_hex);

    let coin = if args.network == "testnet" {1} else {0};
    let hardened = |i| i + 0x8000_0000;
    let mut node = ExtPriv::new_master(&seed);

    for index in [84u32, coin, args.account].map(hardened) {
        node = node.derive_child(index)?;
    }

    for i in 0..args.count {
        let child = node.derive_child(args.change_flag)?.derive_child(i)?;
        let hrp = if coin == 0 {"bc"} else {"tb"};
        let addr = address::p2wpkh(hrp, &ExtPriv::serP_point_kpar(&child.key))?;
        println!("{i}: {addr}");
    }

    Ok(())
}

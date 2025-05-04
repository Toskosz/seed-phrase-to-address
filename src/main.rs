mod bip39;
mod bip32;
mod bech32;
mod address;

use clap::Parser;

#[derive(Parser)]
struct Cli {
    /// 12 or 12 word BIP39 mnemonic
    mnemonic: String,

    #[arg(long, default_value_t = String::new())]
    passphrase: String,

    #[arg(long, default_value_t = 1)]
    address_count: u32,
    
    #[arg(long, default_value="mainnet")]
    network: String,

    #[arg(long, default_value_t = 0)]
    account_index: u32,
}

fn main() {
    let args = Cli::parse();
}

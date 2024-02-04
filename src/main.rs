use bitcoin::address::{Address, Payload};
use bitcoin::blockdata::script::witness_version::WitnessVersion;
use bitcoin::key::PublicKey;
use std::env;
use std::str::FromStr;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        println!("Usage: {} <Bitcoin address>", args[0]);
        return;
    }

    let address_str = &args[1];
    let address = Address::from_str(address_str)
        .map_err(|_| "Failed to parse address".to_string())
        .unwrap();

    let pkh_bytes = match address.payload() {
        Payload::PubkeyHash(pubkey_hash) => {
            // Handle P2PKH address
            let pkh: &[u8] = pubkey_hash.as_ref();
            pkh.to_vec()
        }
        Payload::WitnessProgram(program) => {
            // Handle P2WPKH address
            println!("witness version {}", program.version());
            match program.version() {
                WitnessVersion::V1 => {
                    /* Taproot. In the case of the key-path spend, the pub key is not tweaked.
                    It is 32-byte only X-coordinate however, missing the 33-d byte Y "tie-breaker"
                    https://archive.is/AsKEb
                                        From BIP 340: "To avoid gratuitous incompatibilities, we pick that option for P, and thus our X-only public keys become equivalent to a compressed public key that is the X-only key prefixed by the byte 0x02."
                    */
                    let witness_program_bytes = program.program().as_bytes();
                    assert_eq!(witness_program_bytes.len(), 32);
                    // it is the actual row compressed 32 byte pubkey
                    let pk = PublicKey::from_slice(witness_program_bytes).unwrap();
                    let pkh = pk.pubkey_hash();
                    let pkh_slice: &[u8] = pkh.as_raw_hash().as_ref();
                    pkh_slice.to_vec()
                }
                _ => program.program().as_bytes().to_vec(),
            }
        }
        _ => panic!("Unsupported address type"),
    };

    println!("pkh {}", hex::encode(pkh_bytes));
}

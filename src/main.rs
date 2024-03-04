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
                    // Taproot. In the case of the key-path spend, the pub key is not tweaked.
                    //It is 32-byte only X-coordinate however, missing the 33-d byte Y "tie-breaker"
                    //https://archive.is/AsKEb
                    //From BIP 340: "To avoid gratuitous incompatibilities, we pick that option for P, and thus
                    //our X-only public keys become equivalent to a compressed public key that is the X-only key prefixed by the byte 0x02."
                    let witness_program_bytes = program.program().as_bytes();
                    //x-coordinate absent:
                    assert_eq!(witness_program_bytes.len(), 32);
                    let mut witness_program_vec = witness_program_bytes.to_vec();
                    //BIP 340:
                    witness_program_vec.insert(0, 0x02);
                    // it is the actual compressed 33 byte pubkey
                    let pk = PublicKey::from_slice(&witness_program_vec).unwrap();
                    let pkh = pk.pubkey_hash();
                    let pkh_slice: &[u8] = pkh.as_raw_hash().as_ref();
                    pkh_slice.to_vec()
                }
                //BIP 141 "If the version byte is 0, and the witness program is 20 bytes"
                WitnessVersion::V0 if program.program().len() == 20 => {
                    program.program().as_bytes().to_vec()
                }
                WitnessVersion::V0 if program.program().len() == 32 => {
                    panic!("P2WSH address")
                }
                _ => panic!("Unsupported P2W Witness output script"),
            }
        }
        _ => panic!("Unsupported address type"),
    };

    println!("pkh {}", hex::encode(pkh_bytes));
    match address.payload() {
        Payload::PubkeyHash(pkh) => {
            let pkh_bytes: &[u8] = pkh.as_ref();
            if pkh_bytes.len() != 20 {
                panic!("Invalid hash length for P2PKH");
            }
            let hash = bitcoin_hashes::hash160::Hash::from_bytes_ref(pkh_bytes.try_into().unwrap());
            println!(
                "{}",
                bitcoin::address::Address::new(
                    bitcoin::Network::Bitcoin,
                    bitcoin::address::Payload::PubkeyHash(bitcoin::key::PubkeyHash::from_raw_hash(
                        *hash,
                    )),
                )
                .to_string()
            )
        }
        Payload::WitnessProgram(program) => {
            let program_bytes = program.program().as_bytes();
            match program.version() {
                WitnessVersion::V0 => {
                    if program_bytes.len() != 20 {
                        panic!("Invalid hash length for Bech32P2WPKHa");
                    }
                    let hash = bitcoin_hashes::hash160::Hash::from_bytes_ref(
                        program_bytes.try_into().unwrap(),
                    );
                    println!(
                        "{}",
                        bitcoin::address::Address::new(
                            bitcoin::Network::Bitcoin,
                            bitcoin::address::Payload::WitnessProgram(
                                bitcoin::blockdata::script::witness_program::WitnessProgram::new(
                                    bitcoin::blockdata::script::witness_version::WitnessVersion::V0,
                                    bitcoin::key::PubkeyHash::from_raw_hash(*hash),
                                )
                                .unwrap(),
                            ),
                        )
                        .to_string()
                    )
                }
                WitnessVersion::V1 => {
                    if program_bytes.len() != 32 {
                        panic!("Invalid X coordinate pubkey length");
                    }
                    // Convert program_bytes to a public key
                    let secp = bitcoin::secp256k1::Secp256k1::new();
                    let pubkey = bitcoin::XOnlyPublicKey::from_slice(program_bytes).unwrap();
                    // Create a P2TR address
                    let script = bitcoin::Script::new();
                    script.to_p2tr(&secp, pubkey);
                    println!(
                        "{}",
                        bitcoin::Address::from_script(&script, bitcoin::Network::Bitcoin)
                            .unwrap()
                            .to_string(),
                    )
                }

                _ => panic!("Unsupported P2W Witness version"),
            }
        }

        _ => panic!("unknow addr type"),
    }
}

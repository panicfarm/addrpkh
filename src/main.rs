use bitcoin::blockdata::script::witness_version::WitnessVersion;
use bitcoin::Address;
use std::env;
use std::str::FromStr;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        println!("Usage: {} <Bitcoin address>", args[0]);
        return;
    }

    let address_str = &args[1];
    let address_net_unchecked = Address::from_str(address_str)
        .map_err(|_| "Failed to parse address".to_string())
        .unwrap();
    let address = address_net_unchecked
        .require_network(bitcoin::Network::Bitcoin)
        .unwrap();

    let pkh_bytes = match address.address_type().unwrap() {
        bitcoin::AddressType::P2pkh => {
            let pkh = address.pubkey_hash();
            <bitcoin::PubkeyHash as AsRef<[u8; 20]>>::as_ref(&pkh.unwrap()).to_vec()
        }
        bitcoin::AddressType::P2wpkh | bitcoin::AddressType::P2tr => {
            let program = address.witness_program().unwrap();
            match program.version() {
                WitnessVersion::V1 => {
                    assert_eq!(bitcoin::AddressType::P2tr, address.address_type().unwrap());
                    // Taproot. In the case of the key-path spend, the pub key is not tweaked.
                    //It is 32-byte only X-coordinate however, missing the 33-d byte Y "tie-breaker"
                    //https://archive.is/AsKEb
                    //From BIP 340: "To avoid gratuitous incompatibilities, we pick that option for P, and thus
                    //our X-only public keys become equivalent to a compressed public key that is the X-only key prefixed by the byte 0x02."
                    let witness_program_bytes = program.program().as_bytes();
                    //x-coordinate absent, compressed pubkey:
                    assert_eq!(witness_program_bytes.len(), 32);
                    let xonly_pubkey =
                        bitcoin::XOnlyPublicKey::from_slice(witness_program_bytes).unwrap();
                    let pk = bitcoin::PublicKey::new(
                        xonly_pubkey.public_key(bitcoin::key::Parity::Even),
                    );
                    let pkh = pk.pubkey_hash();
                    let pkh_slice: &[u8] = pkh.as_raw_hash().as_ref();
                    pkh_slice.to_vec()
                }
                //BIP 141 "If the version byte is 0, and the witness program is 20 bytes"
                WitnessVersion::V0 if program.program().len() == 20 => {
                    assert_eq!(
                        bitcoin::AddressType::P2wpkh,
                        address.address_type().unwrap()
                    );
                    program.program().as_bytes().to_vec()
                }
                WitnessVersion::V0 if program.program().len() == 32 => {
                    assert_eq!(bitcoin::AddressType::P2wsh, address.address_type().unwrap());
                    panic!("P2WSH address")
                }
                _ => panic!("Unsupported P2W Witness output script"),
            }
        }
        _ => panic!("Unsupported address type"),
    };

    println!("pkh {}", hex::encode(&pkh_bytes));
    //reverse process. I copy the code again so that it's easier to convert to a function later
    match address.address_type().unwrap() {
        bitcoin::AddressType::P2pkh => {
            if pkh_bytes.len() != 20 {
                panic!("Invalid hash length for P2PKH");
            }
            let hash = bitcoin_hashes::hash160::Hash::from_bytes_ref(
                pkh_bytes.as_slice().try_into().unwrap(),
            );
            println!(
                "{}",
                bitcoin::Address::p2pkh(
                    bitcoin::PubkeyHash::from_raw_hash(*hash),
                    bitcoin::Network::Bitcoin
                )
            )
        }
        bitcoin::AddressType::P2wpkh | bitcoin::AddressType::P2tr => {
            let program = address.witness_program().unwrap();
            let program_bytes = program.program().as_bytes();
            match program.version() {
                WitnessVersion::V0 => {
                    if program_bytes.len() != 20 {
                        panic!("Invalid hash length for Bech32P2WPKHa");
                    }
                    let hash = bitcoin_hashes::hash160::Hash::from_bytes_ref(
                        program_bytes.try_into().unwrap(),
                    );
                    //This demonstrates how to reconstruct the bc1q wpkh address just from the hash
                    //Obviously this could be done much easier, from the witness program
                    println!(
                        "{}",
                        bitcoin::address::Address::from_witness_program(
                            bitcoin::WitnessProgram::new(
                                bitcoin::blockdata::script::witness_version::WitnessVersion::V0,
                                hash.as_ref(),
                            )
                            .unwrap(),
                            bitcoin::Network::Bitcoin,
                        )
                        .to_string()
                    )
                }
                WitnessVersion::V1 => {
                    if program_bytes.len() != 32 {
                        panic!("Invalid X coordinate pubkey length");
                    }
                    // Convert program_bytes to a public key
                    let secp = bitcoin::secp256k1::Secp256k1::verification_only();
                    let xonly_pubkey = bitcoin::XOnlyPublicKey::from_slice(program_bytes).unwrap();
                    // Create a Taproot address from the XOnlyPublicKey
                    let tr_address = bitcoin::address::Address::p2tr(
                        &secp,
                        xonly_pubkey,
                        None,
                        bitcoin::Network::Bitcoin,
                    );
                    let tr_address_1 = bitcoin::address::Address::from_witness_program(
                        program,
                        bitcoin::Network::Bitcoin,
                    );

                    println!("{}\n{}", tr_address, tr_address_1)
                }

                _ => panic!("Unsupported P2W Witness version"),
            }
        }

        _ => panic!("unknow addr type"),
    }
}

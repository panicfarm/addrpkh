### Given a bitcoin address, compute its pubKeyHash. Then given that pubKeyHash, reproduce the original address back.

Works for:
- P2PKH - addresses of the type `1....`
- P2PWKH - addresses of the type `bc1q...`

For P2TR `bc1p...`, one can extract a tweaked pubKey Q (using terminology from [BIP 341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)), and hash it. Then the address can be reconstructed from this pubKey Q. This tweaked key Q however in most cases (even in the case of key-path spend) is not the same as `internal key P`. For example, `bitcoin-cli getnewaddress "" "bech32"` creates an already tweaked pubkey Q; this can be deduced by looking at `bitcoin-cli getaddressinfo $newaddress`
and
comparing
```
"witness_program" : <tweaked pubkey Q>
with
"desc" :
"tr([<master key fingerprint>/<86 for BIP-86>'/<network>'/0'/0/0]<untweaked internal key P>)#checksum"
```
And seeing that P and Q are different.
 

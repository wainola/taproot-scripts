# Taproot transaction script

```bash
yarn install
yarn start
```

This scripts take the taproot addresss generated by the script and send `tBTC` to another taproot address.

The script will wait for any utxo and then it will create the transaction and it will broadcast it. Once you run `yarn start`, send `tBTC` to the generated address -with a any wallet- and wait for the transaction to be broadcasted.

Every time you run this script, it generates a new taproot address. The transacton has data embed. Paste your emv address + destination domain id following the format `address_destdomainId`

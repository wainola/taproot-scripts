import {
  initEccLib,
  networks,
  Signer,
  payments,
  crypto,
  Psbt
} from "bitcoinjs-lib";
import { broadcast, waitUntilUTXO } from "./blockstream_utils";
import { ECPairFactory, ECPairAPI, TinySecp256k1Interface } from 'ecpair';

const tinysecp: TinySecp256k1Interface = require('tiny-secp256k1');
initEccLib(tinysecp as any);
const ECPair: ECPairAPI = ECPairFactory(tinysecp);
const network = networks.testnet;

async function start() {
  const keypair = ECPair.makeRandom({ network });

  await start_p2pktr(keypair);
}

async function start_p2pktr(keypair: Signer) {
  console.log(`Running "Pay to Pubkey with taproot example"`);
  // Tweak the original keypair
  const tweakedSigner = tweakSigner(keypair, { network });
  // Generate an address from the tweaked public key
  const p2pktr = payments.p2tr({
    pubkey: toXOnly(tweakedSigner.publicKey),
    network
  });
  const p2pktr_addr = p2pktr.address ?? "";
  console.log(`Waiting till UTXO is detected at this Address: ${p2pktr_addr}`);

  const utxos = await waitUntilUTXO(p2pktr_addr)

  const psbt = new Psbt({ network });
  psbt.addInput({
    hash: utxos[0].txid,
    index: utxos[0].vout,
    witnessUtxo: { value: utxos[0].value, script: p2pktr.output! },
    tapInternalKey: toXOnly(keypair.publicKey)
});

  const data = Buffer.from(
    "", // EMV ADDRESS + DESTINATION DOMAIN ID HERE
    "utf8",
  );
  const embed = payments.embed({ data: [data] });

  psbt.addOutput({
    script: embed.output!,
    value: 0,
  });

  psbt.addOutput({
    address: "tb1pkwg7akwja3ec03j3pk09fmt5d59g8axc5mya3gptxd6uacvq35usmhh8x6",
    value: utxos[0].value - (16183 + 1000)
  });

  psbt.signInput(0, tweakedSigner);
  psbt.finalizeAllInputs();

  const tx = psbt.extractTransaction(true);

  console.log(`Broadcasting Transaction Hex: ${tx.toHex()}`);
  const txid = await broadcast(tx.toHex());
  console.log(`Success! Txid is ${txid}`);
}

start().then(() => process.exit());

function tweakSigner(signer: Signer, opts: any = {}): Signer {
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  let privateKey: Uint8Array | undefined = signer.privateKey!;
  // @ts-ignore
  if (!privateKey) {
    throw new Error('Private key is required for tweaking signer!');
  }
  if (signer.publicKey[0] === 3) {
    privateKey = tinysecp.privateNegate(privateKey);
  }

  const tweakedPrivateKey = tinysecp.privateAdd(
    privateKey,
    tapTweakHash(toXOnly(signer.publicKey), opts.tweakHash),
  );
  if (!tweakedPrivateKey) {
    throw new Error('Invalid tweaked private key!');
  }

  return ECPair.fromPrivateKey(Buffer.from(tweakedPrivateKey), {
    network: opts.network,
  });
}

function tapTweakHash(pubKey: Buffer, h: Buffer | undefined): Buffer {
  return crypto.taggedHash(
    'TapTweak',
    Buffer.concat(h ? [pubKey, h] : [pubKey]),
  );
}

function toXOnly(pubkey: Buffer): Buffer {
  return pubkey.subarray(1, 33)
}

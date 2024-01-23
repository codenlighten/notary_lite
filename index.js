require("dotenv").config();
const bsv = require("bsv");
const fetch = require("node-fetch");
const express = require("express");
const { generateKeys } = require("./keys");
const app = express();
const port = process.env.PORT || 3000;
const path = require("path");
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, "public")));

const wif = process.env.FUNDING_WIF;
const privateKey = bsv.PrivateKey.fromWIF(wif);
const publicKey = bsv.PublicKey.fromPrivateKey(privateKey);
const address = bsv.Address.fromPublicKey(publicKey);
let busy = false;
const getUtxos = async () => {
  const response = await fetch(
    `https://api.whatsonchain.com/v1/bsv/main/address/${address.toString()}/unspent`
  );
  const json = await response.json();
  const utxos = json.map((utxo) => {
    return new bsv.Transaction.UnspentOutput({
      txid: utxo.tx_hash,
      vout: utxo.tx_pos,
      script: bsv.Script.buildPublicKeyHashOut(address).toHex(),
      satoshis: utxo.value,
    });
  });
  return utxos;
};

const broadcast = async (tx) => {
  try {
    const response = await fetch(
      `https://api.whatsonchain.com/v1/bsv/main/tx/raw`,
      {
        method: "POST",
        body: JSON.stringify({ txhex: tx.toString() }),
      }
    );
    const json = await response.json();
    return json;
  } catch (e) {
    console.log(e);
  }
};

const publishOpReturn = async (data) => {
  const utxos = await getUtxos();
  const tx = new bsv.Transaction().from(utxos);
  const opArray = ["17RtQzMm1fXK1foJGWLquGNum5HHfLGH1x", ...data];
  const opReturnArray = opArray.map((d) => Buffer.from(d));
  data.map((d) => Buffer.from(d));
  const opReturn = bsv.Script.buildSafeDataOut(opReturnArray);
  tx.addOutput(
    new bsv.Transaction.Output({
      script: opReturn,
      satoshis: 0,
    })
  );
  const size = tx._estimateSize();
  const fee = Math.ceil(size * 0.015);
  const totalSats = utxos.reduce((acc, utxo) => acc + utxo.satoshis, 0);
  const change = totalSats - fee;
  tx.addOutput(
    new bsv.Transaction.Output({
      script: bsv.Script.buildPublicKeyHashOut(address),
      satoshis: change,
    })
  );
  tx.sign(privateKey);
  const txid = await broadcast(tx);
  return txid;
};

const hashData = (data) => {
  const hash = bsv.crypto.Hash.sha256(Buffer.from(data));
  const bn = bsv.crypto.BN.fromBuffer(hash);
  const address = new bsv.PrivateKey(bn).toAddress();
  return address;
};
const signData = (data) => {
  const hash = bsv.crypto.Hash.sha256(Buffer.from(data));
  const sig = bsv.crypto.ECDSA.sign(hash, privateKey).toString();
  return sig;
};

const verifyData = (data, sig, address) => {
  const hash = bsv.crypto.Hash.sha256(Buffer.from(data));
  const pubKey = bsv.PublicKey.fromAddress(address);
  const res = bsv.crypto.ECDSA.verify(hash, sig, pubKey);
  return res;
};

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// app.post to handle the data publish to blockchain

app.post("/publish", async (req, res) => {
  try {
    if (busy) {
      res.send("busy");
      return;
    }
    busy = true;
    const data = req.body.data;
    const hash = req.body.hash;
    const sig = req.body.signature;
    const address = req.body.address;
    const txid = await publishOpReturn([data, hash, sig, address]);
    busy = false;
    res.send(txid);
  } catch (e) {
    console.log(e);
    res.send("error");
  }
});
// app.post to handle the data publish to blockchain
app.post("/hash", (req, res) => {
  try {
    if (busy) {
      res.send("busy");
      return;
    }
    busy = true;
    const data = req.body.data;
    const hash = hashData(data);
    busy = false;
    res.send(hash.toString());
  } catch (e) {
    console.log(e);
    res.send("error");
  }
});

// app.post to handle the data publish to blockchain
app.post("/sign", (req, res) => {
  const data = req.body.data;
  const sig = signData(data);
  res.send(sig);
});

// app.post to handle the data publish to blockchain
app.post("/verify", (req, res) => {
  const data = req.body.data;
  const sig = req.body.sig;
  const address = req.body.address;
  const result = verifyData(data, sig, address);
  res.send(result);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

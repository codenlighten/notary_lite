require("dotenv").config();
const bsv = require("bsv");
const fetch = require("node-fetch");
const express = require("express");
const { generateKeys } = require("./keys");
const app = express();
const port = process.env.PORT || 3000;
const path = require("path");
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ limit: "50mb", extended: true }));
app.use(express.static(path.join(__dirname, "public")));

const wif = process.env.FUNDING_WIF;
const fundingAddress = process.env.FUNDING_ADDRESS;
const privateKey = bsv.PrivateKey.fromWIF(wif);
const publicKey = bsv.PublicKey.fromPrivateKey(privateKey);
const address = bsv.Address.fromPublicKey(publicKey);

const approvedPublicKeys = [];

let busy = false;
const getUtxos = async () => {
  const response = await fetch(
    `https://api.whatsonchain.com/v1/bsv/main/address/${address.toString()}/unspent`
  );
  const json = await response.json();
  console.log(json);
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
const publishOpReturn = async (mimetype, data, signature, address, hash) => {
  try {
    const utxos = await getUtxos();
    if (utxos.length === 0) {
      return new Error("No UTXOs available");
    }

    const tx = new bsv.Transaction().from(utxos);
    // MAP SET app <appame> type publish | AIP BITCOIN_ECDSA <address> <signature>
    // Ensure data is in the correct format
    const bufferArray = [
      "17RtQzMm1fXK1foJGWLquGNum5HHfLGH1x",
      data,
      mimetype,
      "MAP",
      "SET",
      "app",
      "NotaryHash",
      "type",
      "publish",
      "|",
      "AIP",
      "BITCOIN_ECDSA",
      address,
      signature,
      "hash",
      hash,
    ].map((item) => (Buffer.isBuffer(item) ? item : Buffer.from(item)));

    // Add OP_RETURN output
    const opReturn = bsv.Script.buildSafeDataOut(bufferArray);
    tx.addOutput(
      new bsv.Transaction.Output({
        script: opReturn,
        satoshis: 0,
      })
    );

    // Calculate transaction fee (consider increasing the fee rate if necessary)
    const feePerKb = 0.015; // This is just an example rate
    const estimatedSize = tx._estimateSize();
    const fee = Math.ceil(estimatedSize * feePerKb);

    // Calculate change
    const totalSats = utxos.reduce((acc, utxo) => acc + utxo.satoshis, 0);
    const change = totalSats - fee;
    if (change < 0) {
      throw new Error("Insufficient funds for fee");
    }

    // Add change output
    tx.addOutput(
      new bsv.Transaction.Output({
        script: bsv.Script.buildPublicKeyHashOut(fundingAddress),
        satoshis: change,
      })
    );

    tx.sign(privateKey);
    const txid = await broadcast(tx);
    return txid;
  } catch (e) {
    console.error("Error in publishOpReturn:", e.message);
    throw e; // Rethrow the error after logging
  }
};

const hashData = (data) => {
  const hash = bsv.crypto.Hash.sha256(Buffer.from(data));
  const bn = bsv.crypto.BN.fromBuffer(hash);
  const address = new bsv.PrivateKey(bn).toAddress();
  return address;
};
const signData = (data, wifString) => {
  const privateKey = bsv.PrivateKey.fromWIF(wifString);
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
app.get("/register", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "register.html"));
});

app.post("/registerId", async (req, res) => {
  try {
    if (busy) {
      res.send("busy");
      return;
    }
    busy = true;
    const data = req.body.data;
    const encryptedData = req.body.encryptedData;
    const firstName = req.body.firstName;
    const lastName = req.body.lastName;
    const birthdate = req.body.birthdate;
    const country = req.body.country;
    const password = req.body.password;
    const hash = req.body.hash;
    const signature = req.body.signature;
    const address = req.body.address;
    const publicKey = req.body.publicKey;
    const txid = await publishOpReturn(
      "text/plain",
      data,
      signature,
      address,
      hash
    );
    busy = false;
    approvedPublicKeys.push(publicKey);
    res.send(txid);
  } catch (e) {
    busy = false;
    console.log(e);
    res.send("error");
  }
});

//login with password, signed data and public key
app.post("/login", async (req, res) => {
  try {
    if (busy) {
      res.send("busy");
      return;
    }
    busy = true;
    const data = req.body.data;
    const signature = req.body.signature;
    const address = req.body.address;
    const publicKey = req.body.publicKey;
    //check if public key is approved
    if (!approvedPublicKeys.includes(publicKey)) {
      res.send("not approved");
      busy = false;
      return;
    }
    //verify data
    const result = verifyData(data, signature, address);
    if (!result) {
      res.send("not verified");
      busy = false;
      return;
    }
    //verify password
    res.send("success");
  } catch (e) {
    busy = false;
    console.log(e);
    res.send("error");
  }
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
    const publicKey = req.body.publicKey;
    const txid = await publishOpReturn("text/plain", data, sig, address, hash);
    busy = false;
    res.send(txid);
  } catch (e) {
    busy = false;
    console.log(e);
    res.send("error");
  }
});
// app.post to handle the file data publish to blockchain
app.post("/publishFile", async (req, res) => {
  try {
    if (busy) {
      res.status(503).send("Server busy, please try again later");
      return;
    }
    busy = true;

    const base64 = req.body.data;
    const mimeType = req.body.mimeType;
    const hash = req.body.hash;
    const sig = req.body.signature;
    const data = Buffer.from(base64, "base64");
    const address = req.body.address;
    const publicKey = req.body.publicKey;
    // Use 'data' if the function expects a buffer
    const txid = await publishOpReturn(mimeType, data, sig, address, hash);

    busy = false;
    res.send(txid);
  } catch (e) {
    busy = false;
    console.error(e);
    res.status(500).send("An error occurred while processing the request");
  }
});

// app.post to handle the data publish to blockchain
app.post("/hash", async (req, res) => {
  if (busy) {
    res.send("busy");
    return;
  }
  busy = true;
  const data = req.body.data;
  const sig = req.body.signature;
  const address = req.body.address;
  const hash = hashData(data);
  try {
    const txid = await publishOpReturn("text/plain", data, sig, address, hash);
    if (!txid) {
      res.send("error");
      return;
    }
    busy = false;
    res.send(txid);
  } catch (e) {
    console.log(e);
    res.send("error");
  }
});

// app.post to handle the data publish to blockchain
app.post("/sign", async (req, res) => {
  try {
    const data = req.body.data;
    const hash = req.body.hash;
    const sig = req.body.signature;
    const address = req.body.address;
    const publicKey = req.body.publicKey;
    const result = signData(data, wif);
    const txid = await publishOpReturn(
      "text/plain",
      data,
      result,
      address,
      hash
    );
    res.send(txid);
  } catch (e) {
    console.log(e);
    res.send("error");
  }
});

// app.post to handle the data publish to blockchain
app.post("/verify", (req, res) => {
  const data = req.body.data;
  const sig = req.body.sig;
  const address = req.body.address;
  const result = verifyData(data, sig, address);
  res.send(result);
});

//api to post data
app.post("/api/postdata", async (req, res) => {
  try {
    const data = req.body.data;
    const hash = hashData(data);
    const keys = generateKeys();
    const address = keys.address;
    const publicKey = keys.publicKey;
    const sig = signData(data, keys.privateKey);
    const result = verifyData(data, sig, address);
    console.log(result);
    const txid = await publishOpReturn("text/plain", data, sig, address, hash);
    res.send({ txid, hash, publicKey, keys });
  } catch (e) {
    console.log(e);
    res.send("error");
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

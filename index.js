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
const fs = require("fs");
//uuid
const { v4: uuidv4 } = require("uuid");
const jwt = require("jsonwebtoken");
//otp-generator
const otp = require("otp-generator");
const { send2FACode } = require("./nodemail");
const wif = process.env.FUNDING_WIF;
const fundingAddress = process.env.FUNDING_ADDRESS;
const monitorinAddress = process.env.MONITORING_ADDRESS;
const registeredAddress = process.env.REGISTERED_ADDRESS;
const privateKey = bsv.PrivateKey.fromWIF(wif);
const publicKey = bsv.PublicKey.fromPrivateKey(privateKey);
const address = bsv.Address.fromPublicKey(publicKey);

// jwt token function
const generateToken = (data) => {
  const token = jwt.sign(data, process.env.JWT_SECRET);
  return token;
};
//uuid function
const generateUUID = () => {
  const uuid = uuidv4();
  console.log(uuid);
  return uuid;
};
//otp function
const generateOTP = () => {
  const otpCode = otp.generate(6, {
    upperCase: false,
    specialChars: false,
    alphabets: false,
  });
  console.log(otpCode);
  return otpCode;
};
const otpFile = fs.readFileSync("otp.json", "utf8");
const otpJson = JSON.parse(otpFile);
//store otp in json file
const storeOTP = (otpCode, email) => {
  const data = {
    email,
    otpCode,
    date: new Date(),
  };
  otpJson.push(data);
  fs.writeFileSync("otp.json", JSON.stringify(otpJson, null, 2));
};

//get otp.json file and check array of otp for code plus data
const checkOTP = (otpCode, email) => {
  const data = otpJson.find((item) => {
    return item.email === email && item.otpCode === otpCode;
  });
  return data;
};

//remove otp from json file
const removeOTP = (otpCode, email) => {
  const index = otpJson.findIndex((item) => {
    return item.email === email && item.otpCode === otpCode;
  });
  otpJson.splice(index, 1);
  fs.writeFileSync("otp.json", JSON.stringify(otpJson, null, 2));
};

const approvedPublicKeys = [];
//check if file exists authorized.json
if (fs.existsSync("authorized.json")) {
  const data = fs.readFileSync("authorized.json", "utf8");
  const json = JSON.parse(data);
  json.forEach((item) => {
    approvedPublicKeys.push(item);
  });
}

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
const publishOpReturn = async (
  mimetype,
  data,
  signature,
  address,
  hash,
  monitor,
  type = "publish"
) => {
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
      type,
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
    //1 sat to monitoring address
    tx.addOutput(
      new bsv.Transaction.Output({
        script: bsv.Script.buildPublicKeyHashOut(monitor),
        satoshis: 1,
      })
    );
    // Calculate transaction fee (consider increasing the fee rate if necessary)
    const feePerKb = 0.015; // This is just an example rate
    const estimatedSize = tx._estimateSize();
    const fee = Math.ceil(estimatedSize * feePerKb);

    // Calculate change
    const totalSats = utxos.reduce((acc, utxo) => acc + utxo.satoshis, 0);
    const change = totalSats - fee - 1;
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
  return hash.toString("hex");
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
    let data = req.body.data;
    const encryptedData = req.body.encryptedData;
    let firstName = req.body.firstName;
    let lastName = req.body.lastName;
    const email = req.body.email;
    const birthdate = req.body.birthdate;
    let country = req.body.country;
    let passwordHash = req.body.password;
    //lowercase
    data = data.toLowerCase();
    firstName = firstName.toLowerCase();
    lastName = lastName.toLowerCase();
    country = country.toLowerCase();
    //remove spaces
    data = data.replace(/\s/g, "");
    firstName = firstName.replace(/\s/g, "");
    lastName = lastName.replace(/\s/g, "");
    country = country.replace(/\s/g, "");
    const hash = req.body.hash;
    const signature = req.body.signature;
    let address = req.body.address;
    const publicKey = req.body.publicKey;
    const txid = await publishOpReturn(
      "text/plain",
      encryptedData,
      signature,
      address,
      hash,
      registeredAddress,
      "register"
    );
    busy = false;
    approvedPublicKeys.push(publicKey);
    fs.writeFileSync(
      "authorized.json",
      JSON.stringify(approvedPublicKeys, null, 2)
    );
    //otp
    const otpCode = generateOTP();
    //send email
    storeOTP(otpCode, email);
    send2FACode(email, otpCode);
    res.send({
      txid,
      message:
        "An email has been sent to your email address, please check your inbox or spam folder",
    });
  } catch (e) {
    busy = false;
    console.log(e);
    res.send("error");
  }
});

//login with password, signed data and public key

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
    const email = req.body.email;

    //check if public key is approved
    if (!approvedPublicKeys.includes(publicKey)) {
      res.send({ message: "not approved" });
      busy = false;
      return;
    }
    //verify data
    const result = verifyData(data, signature, address);
    if (!result) {
      res.send({ message: "not verified" });
      busy = false;
      return;
    }
    //op return
    const hash = hashData(data);
    const txid = await publishOpReturn(
      "text/plain",
      data,
      signature,
      address,
      hash,
      monitorinAddress,
      "login"
    );
    //generate token
    //otp
    const otpCode = generateOTP();
    storeOTP(otpCode, email);
    //send email
    send2FACode(email, otpCode);
    busy = false;
    res.send({
      txid,
      message:
        "An email has been sent to your email address with a one time password, please check your inbox or spam folder",
    });
  } catch (e) {
    busy = false;
    console.log(e);
    res.send("error");
  }
});
app.post("/otpVerify", async (req, res) => {
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
    const email = req.body.email;
    const otpCode = req.body.otpCode;
    //check if otp exists
    const otpData = checkOTP(otpCode, email);
    console.log(otpData);
    if (!otpData) {
      res.send({ message: "otp not found" });
      busy = false;
      return;
    }
    const date = new Date(otpData.date);
    const now = new Date();
    const diff = now - date;
    //check if otp is expired 5 minutes
    if (diff > 300000) {
      res.send({ message: "otp expired" });
      busy = false;
      //remove otp
      removeOTP(otpCode, email);
      return;
    } else {
      //check if public key is approved
      if (!approvedPublicKeys.includes(publicKey)) {
        res.send({ message: "not approved" });
        busy = false;
        return;
      }
      //verify data
      const result = verifyData(data, signature, address);
      console.log(result);
      if (!result) {
        res.send({ message: "not verified" });
        busy = false;
        return;
      }
      //jwt token
      //op return
      const hash = hashData(data);
      const txid = await publishOpReturn(
        "text/plain",
        data,
        signature,
        address,
        hash,
        monitorinAddress,
        "otpVerify"
      );
      const token = generateToken({ email });
      res.send({ token, message: "success", txid });
      //remove otp
      busy = false;
      removeOTP(otpCode, email);
    }
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
    const txid = await publishOpReturn(
      "text/plain",
      data,
      sig,
      address,
      hash,
      monitorinAddress,
      "publish"
    );
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
    const txid = await publishOpReturn(
      mimeType,
      data,
      sig,
      address,
      hash,
      monitorinAddress,
      "publish"
    );

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
    const txid = await publishOpReturn(
      "text/plain",
      data,
      sig,
      address,
      hash,
      monitorinAddress,
      "hash"
    );
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
      hash,
      monitorinAddress,
      "sign"
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
app.post("/api/v1/postdata", async (req, res) => {
  try {
    const data = req.body.data;
    const hash = hashData(data);
    const keys = generateKeys();
    const address = keys.address;
    const publicKey = keys.publicKey;
    const sig = signData(data, keys.privateKey);
    const result = verifyData(data, sig, address);
    console.log(result);
    const txid = await publishOpReturn(
      "text/plain",
      data,
      sig,
      address,
      hash,
      monitorinAddress,
      "postdata"
    );
    res.send({ txid, hash, publicKey, keys });
  } catch (e) {
    console.log(e);
    res.send("error");
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

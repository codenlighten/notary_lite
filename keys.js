const bsv = require("bsv");
//uuid
const { v4: uuidv4 } = require("uuid");
const defaultPath = "m/44'/0'/0'/0/0";
const Mnemonic = require("bsv/mnemonic");
const mnemonic = new Mnemonic();

const generateKeys = (path = defaultPath) => {
  const randomMnemonic = mnemonic.toString();
  const rootSeed = mnemonic.toSeed(randomMnemonic);
  const hdPrivateKey = bsv.HDPrivateKey.fromSeed(rootSeed);
  const child = hdPrivateKey.deriveChild(path);
  const privateKey = child.privateKey;
  const publicKey = bsv.PublicKey.fromPrivateKey(privateKey);
  const address = bsv.Address.fromPublicKey(publicKey);
  const uuid = uuidv4();
  console.log("uuid:", uuid);
  console.log("mnemonic:", randomMnemonic);
  console.log("path:", path);
  console.log("privateKey:", privateKey.toString());
  console.log("publicKey:", publicKey.toString());
  console.log("address:", address.toString());
  return {
    uuid,
    mnemonic: randomMnemonic,
    path,
    privateKey: privateKey.toString(),
    publicKey: publicKey.toString(),
    address: address.toString(),
  };
};

generateKeys();

module.exports = {
  generateKeys,
};

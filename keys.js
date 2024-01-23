const bsv = require("bsv");
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
  console.log("mnemonic:", randomMnemonic);
  console.log("path:", path);
  console.log("privateKey:", privateKey.toString());
  console.log("publicKey:", publicKey.toString());
  console.log("address:", address.toString());
};

generateKeys();

module.exports = {
  generateKeys,
};

const express = require("express");
const secp256k1 = require('secp256k1');
const { sha256 } = require("ethereum-cryptography/sha256");
const { utf8ToBytes } = require("ethereum-cryptography/utils");


const app = express();
const cors = require("cors");
const port = 3042;

app.use(cors());
app.use(express.json());

const balances = {
// private key: b3c8ed2e42af6389d29a856943e2d0c4499737bdd4542d5008ab4cd6d4bab897
  "030ab5cabe46138ec48f450e52f6633ca13c8514de4c9145cd7af1fd121b712c6a": 100,
// private key: 18cac8a93162082b7523af408daf911fd9579e27062a48368703c152593fdf5f
  "03092addd341a3bcb21f9476101f55e4ab29b08da63cf6c1c446cf96bf254b4439": 50,
// private key: ddbd557be0c04745f43da82a6f7806b72f79cfda4f12d37cf51f4177297aecff
  "038d88f218295399c2b872cbd952ddfca3b4668a6b293154c9602651aa7e127954": 75,
};

const nonces = {
  "030ab5cabe46138ec48f450e52f6633ca13c8514de4c9145cd7af1fd121b712c6a": 0,
  "03092addd341a3bcb21f9476101f55e4ab29b08da63cf6c1c446cf96bf254b4439": 0,
  "038d88f218295399c2b872cbd952ddfca3b4668a6b293154c9602651aa7e127954": 0,
};

app.get("/balance/:address", (req, res) => {
  const { address } = req.params;
  const balance = balances[address] || 0;
  res.send({ balance });
});

app.get("/nonce/:address", (req, res) => {
  const { address } = req.params;
  const nonce = nonces[address] || 0;
  res.send({ nonce });
});

app.post("/send", (req, res) => {
  // receiving message and signature from the app
  const { sender, recipient, amount, signature } = req.body;
  
  // preparing values for verifying
  const hash = hashMessage(recipient + sender + amount + nonces[sender]);
  const sig = new Uint8Array(Object.values(signature));
  
  const fromHexString = (hexString) =>
      Uint8Array.from(hexString.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));

  // verifying the sender public address with the signature
  const isValid = secp256k1.ecdsaVerify(sig, hash, fromHexString(sender));
  if(!isValid) {
    res.status(400).send({ message: "Incorrect signature!" });
    return;
  }
  
  setInitialBalance(sender);
  setInitialBalance(recipient);
  
  if (balances[sender] < amount) {
    res.status(400).send({ message: "Not enough funds!" });
  } else {
    balances[sender] -= amount;
    balances[recipient] += amount;
    // incrementing sender's nonce to prevent signature replaying 
    nonces[sender] += 1;
    res.send({ balance: balances[sender] });
  }  
});

app.listen(port, () => {
  console.log(`Listening on port ${port}!`);
});

function setInitialBalance(address) {
  if (!balances[address]) {
    balances[address] = 0;
  }
}

function hashMessage(message) {
  const bytes = utf8ToBytes(message);
  const hash = sha256(bytes);
  return hash;
}

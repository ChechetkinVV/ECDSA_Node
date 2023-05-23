import { useState } from "react";
import server from "./server";

import secp256k1 from 'secp256k1';
import { sha256 } from "ethereum-cryptography/sha256.js";
import { utf8ToBytes } from "ethereum-cryptography/utils";


function Transfer({ address, setBalance, privateKey }) {
  const [sendAmount, setSendAmount] = useState("");
  const [recipient, setRecipient] = useState("");

  const setValue = (setter) => (evt) => setter(evt.target.value);

  async function transfer(evt) {
    evt.preventDefault();   

    // receiving current nonce from the server
    const {
      data: { nonce },
    } = await server.get(`nonce/${address}`);

    // preparing values for signature with current nonce
    const amount = parseInt(sendAmount);    
    const hash = hashMessage(recipient + address + amount + nonce);

    const fromHexString = (hexString) =>
      Uint8Array.from(hexString.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));

    const sigObj = secp256k1.ecdsaSign(hash, fromHexString(privateKey), { recovered: true });

    // extracting signature uint8array
    const signature = sigObj.signature;

    try {
      const {
        data: { balance },
      } = await server.post(`send`, {
        sender: address,
        amount,
        recipient,
        signature,
      });
      setBalance(balance);
    } catch (ex) {
      alert(ex.response.data.message);
    }
  }

  return (
    <form className="container transfer" onSubmit={transfer}>
      <h1>Send Transaction</h1>

      <label>
        Send Amount
        <input
          placeholder="1, 2, 3..."
          value={sendAmount}
          onChange={setValue(setSendAmount)}
        ></input>
      </label>

      <label>
        Recipient
        <input
          placeholder="Type an address, for example: 0x2"
          value={recipient}
          onChange={setValue(setRecipient)}
        ></input>
      </label>

      <input type="submit" className="button" value="Transfer" />
    </form>
  );
}

function hashMessage(message) {
  const bytes = utf8ToBytes(message);
  const hash = sha256(bytes);
  return hash;
}

export default Transfer;

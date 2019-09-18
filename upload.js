// Max 15 checkmultisig per p2sh
// TODO: Move to P2SH which is strictly better
// Use Script.prototype.toScriptHashOut
// which uses Script.buildScriptHashOut
// internally buildP2SHMultisigIn
//https://github.com/bitcoin/bitcoin/blob/4cef8e05938e/src/policy/policy.cpp#L99
// 3 = m + n + OP_CHECKMULTISIG
// +1 = data push
// (520-3-(33+1))/(65+1)
// Thus max 7 data pushes
// Thus use 1-of-8

// This is ES 2017. All browsers that support
// WASM have ES 2017

/*
// int lzma_decompress(const unsigned char *data, unsigned int datalen, unsigned char * out, int outlen);
var decompress = Module.cwrap("lzma_decompress", "number", ["number", "number", "number", "number"]);
// int lzma_compress(const unsigned char *data, unsigned int datalen, unsigned char * out);
var compress = Module.cwrap("lzma_compress", "number", ["number", "number", "number"]);
// void full_encrypt(const unsigned char * key, int keylen, const unsigned char nonce[16], const unsigned char * data, int datalen, unsigned char * out);
var encrypt = Module.cwrap("full_encrypt", null, ["number", "number", "number", "number", "number", "number"]);
// int full_decrypt(const unsigned char * key, int keylen, const unsigned char nonce[16], const unsigned char * data, int datalen, unsigned char * out);
var decrypt = Module.cwrap("full_decrypt", "number", ["number", "number", "number", "number", "number", "number"]);
// void checksum(const unsigned char * __restrict data, int datalen, unsigned char out[__restrict 8])
var generate_checksum = Module.cwrap("checksum", null, ["number", "number", "number"]);
*/

const ua = navigator.userAgent.toLowerCase();
if (!(ua.includes("bot") || ua.includes("bing") || ua.includes("duck") || ua.includes("yandex") || localStorage.getItem('terms_of_use_accept_date'))) {
  window.location.replace("./terms_of_use.html");
}

var bitcore = require('bitcore-lib');
// find module.exports.Output = require('./output');
// OR var MAX_SAFE_INTEGER = 0x1fffffffffffff
var outpt = require(191);
// find module.exports.PublicKeyHash = require('./publickeyhash');
var pkhash = require(192).PublicKeyHash;
// Buffer, search for
// The buffer module from node.js, for the browser.
// exports.INSPECT_MAX_BYTES = 50
// If an error happens, replace bueffer.Buffer.from(x)
// with bueffer.buffer.from(encodeHex(x), "hex")
var bueffer = require(52);
// TODO: move to button continue
var fileName = "";
var fileBackup, fileContents;

document.getElementById("chosen-file").onclick = function() {
  clearEverything();
  document.getElementById("file-upload-div").style = "";
  //document.getElementById("output").src = "";
  document.getElementById("continue-button").onclick = fileCheck;
  document.getElementById("comment").value = ""
}

const hex_str = "0123456789abcdef";

function encodeHex(arr) {
  var out = "";
  const arrLen = arr.length;
  for (var i = 0; i < arrLen; i++) {
    // if str[i] > 102
    // return;
    out += hex_str[arr[i] >>> 4];
    out += hex_str[arr[i] & 15];
  }
  return out;
}

function textCheck() {
  document.getElementById("change-box").style.display = "none";
  const val = document.getElementById("comment").value;
  if (val.length == 0) {
    setError("No text entered.");
    return;
  }
  fileContents = ToUTF8(FromString(val));
  if (fileContents.length === 0) {
    setError("Text encoding error. Please tell the developer!")
    return;
  }
  buttonContinue();
}

function fileCheck() {
  document.getElementById("change-box").style.display = "none";
  fileContents = fileBackup.slice(0);
  buttonContinue();
}

var qrcode = new QRCode("qrcode", {
  text: "",
  width: 256,
  height: 256,
  colorDark: "#000000",
  colorLight: "#d7f6b0",
  correctLevel: QRCode.CorrectLevel.M
});

function calculateChecksum(arr, out) {
  const c1 = arr.length;
  const buf = Module._malloc(c1 + 4);
  const c2Buf = buf + c1;
  Module.HEAPU8.set(arr, buf);
  Module._checksum(buf, arr.length, c2Buf);
  out.set(Module.HEAPU8.subarray(c2Buf, c2Buf + 4));
  Module._free(buf);
}

function buttonContinue() {
  if (document.getElementById("legal").checked === false) {
    setError(
      "Please accept the informal notice above (This is only to remind you of copyright laws. The legal terms of use can be accessed from the homepage).");
    return;
  }
  clearError();
  const realFileName = document.getElementById("filename").value;
  const fileName = ToUTF8(FromString(realFileName));
  if (realFileName.length > 80) {
    setError("Filename too long!");
    return;
  } else if (realFileName.length === 0) {
    setError("No filename specified!");
    return;
  } else if (fileName.length === 0) {
    setError("Filename encoding error. Please tell the developer!")
    return;
  }
  const shouldEncrypt = document.getElementById("encrypt").checked;
  const encryptFileName = !document.getElementById("encrypt-name-public").checked;
  const password = document.getElementById("input-password").value;
  const passwordBytes = ToUTF8(FromString(password));
  const passwordBytesLen = passwordBytes.length;
  var fileNameInside = true;
  if (shouldEncrypt) {
    // TODO here password must be at most 128 bytes
    if (password.length > 256) {
      setError("Password too long! At most 256 characters.");
      return;
    } else if (password.length < 8) {
      setError("Password must be longer than 7 characters!");
      return;
    }
    if (passwordBytesLen === 0) {
      setError("Password encoding error! Please contact the developer and use a different password.");
      return;
    }
  }
  if (!(fileContents instanceof Uint8Array)) {
    setError("Internal error. Was the file too big?");
    return;
  }
  if (fileContents.length === 0) {
    setError("Empty file!");
    return;
  }
  var i = 0;
  if (!shouldEncrypt || encryptFileName) {
    const nLen = fileName.length, cLen = fileContents.length;
    var dataWithName = new Uint8Array(nLen + 2 + cLen);
    for (i = 0; i < nLen; i++) {
      dataWithName[i] = fileName[i];
    }
    for (i = 0; i < cLen; i++) {
      dataWithName[nLen + 2 + i] = fileContents[i];
    }
    fileContents = dataWithName;
  } else {
    fileNameInside = false;
  }
  var shouldCompress = fileContents.length > 128, nonce;
  // TODO: DEBUG
  //shouldCompress = false;
  console.log("Disabled compression.");
  if (shouldCompress) {
    setStatus("Compression in progress...");
    const fcLen = fileContents.length;
    const buf = Module._malloc(2 * fcLen);
    const c2Buf = buf + fcLen;
    Module.HEAPU8.set(fileContents, buf);
    const outLen = Module._lzma_compress(buf, fcLen, c2Buf);
    if (outLen < 4) {
      setStatus("Compression in progress...Done");
      console.error("Compression error code: " + outLen);
      shouldCompress = false;
    } else {
      console.log("Compressed to: " + outLen + " bytes, " + ((1 - (outLen / fileContents.length)) * 100).toFixed(2) + "%");
      fileContents = new Uint8Array(Module.HEAPU8.subarray(c2Buf, c2Buf + outLen));
    }
    Module._free(buf);
  }
  clearError();
  if (shouldEncrypt) {
    console.log("Started encrypt");
    const fcLen = fileContents.length;
    const fcLenPlusSixteen = fcLen + 16;
    // key-nonce-fileContents-output
    const buf = Module._malloc(passwordBytesLen + 2 * fcLenPlusSixteen);
    const c2Buf = buf + passwordBytesLen;
    const c3Buf = c2Buf + 16;
    const c4Buf = c3Buf + fcLen;
    nonce = new Uint8Array(16);
    window.crypto.getRandomValues(nonce);
    Module.HEAPU8.set(passwordBytes, buf);
    Module.HEAPU8.set(nonce, c2Buf);
    Module.HEAPU8.set(fileContents, c3Buf);
    Module._full_encrypt(buf, passwordBytesLen, c2Buf, c3Buf, fcLen, c4Buf);
    fileContents = new Uint8Array(Module.HEAPU8.subarray(c4Buf, c4Buf + fcLenPlusSixteen));
    Module._free(buf);
  }
  const fcLen = fileContents.length;
  const fLen = 4 + 4 + 4 + 4 + (shouldEncrypt ? 16 : 0) + (fileNameInside ? 0 : fileName.length) + 1 + 1 + fcLen;
  var final = new Uint8Array(fLen);
  final[0] = 0x24;
  final[1] = 0x3f;
  final[2] = 0x6a;
  final[3] = 0x88;
  final[4] = (fcLen >>> 24) & 255;
  final[5] = (fcLen >>> 16) & 255;
  final[6] = (fcLen >>> 8) & 255;
  final[7] = fcLen & 255;
  if (shouldEncrypt) {
    final[8] = 1;
  }
  if (shouldCompress) {
    final[8] |= 2;
  }
  calculateChecksum(fileContents, final.subarray(12));
  i = 16;
  if (shouldEncrypt) {
    final.set(nonce, i);
    i = 32;
  }
  if (!fileNameInside) {
    final.set(fileName, i);
    i += fileName.length;
  }
  i += 2;
  final.set(fileContents, i);
  if (fLen != (i + fileContents.length)) {
    setError("Unexpected error while concating data.");
    return;
  }
  fileContents = null;
  console.log("Unpadded length: " + fLen);
  // const perTransactionCapacity = 55055;
  // const perTransactionOpReturn = 220;
  // QUIRK: The last transaction will have one OP_RETURN
  // even if it'll be completely empty.
  var numberOfTX = 20, numberOfGroups = 1, numberOfOuts = new Uint8Array(20);
  if (fLen <= 220 * numberOfTX) {
    numberOfTX = Math.ceil(fLen / 220);
    numberOfOuts = numberOfOuts.subarray(0, numberOfTX);
  } else if (fLen < 55055) {
    // numberOfGroups still 1
    const withoutOpReturnLen = fLen - 220 * 20,
      totalOuts = Math.ceil(withoutOpReturnLen / 455),
      eachOut = (totalOuts / 20) | 0;
    let surpOut = totalOuts % 20;
    numberOfOuts.fill(eachOut);
    while (surpOut-- > 0) {
      numberOfOuts[surpOut]++;
    }
  } else {
    // TODO: test it
    // First estimation

    // TODO: replace 20 with 25
    numberOfTX = Math.ceil(fLen / 55275);
    numberOfGroups = (numberOfTX / 20) | 0;
    if (numberOfTX % 20 !== 0) {
      numberOfGroups++;
    }
    // Exact result
    numberOfTX = numberOfGroups * 20;
    numberOfOuts = new Uint8Array(numberOfTX);
    const totalOuts = Math.ceil((fLen - numberOfTX * 220) / 455),
      eachOut = (totalOuts / numberOfTX) | 0;
    let surpOut = totalOuts % numberOfTX;
    numberOfOuts.fill(eachOut);
    while (surpOut-- > 0) {
      numberOfOuts[surpOut]++;
    }
  }
  // Add padding
  var paddingIndex = 0;
  for (i = 0; i < numberOfTX; i++ , paddingIndex += 220) {
    paddingIndex += numberOfOuts[i] * 455;
  }
  console.log("Padded length: " + paddingIndex);
  console.log("Number of transactions: " + numberOfTX);
  const padDifference = paddingIndex - fLen;
  if (padDifference !== 0) {
    var oldFinal = final;
    final = new Uint8Array(paddingIndex);
    final.set(oldFinal);
    oldFinal = undefined;
    // Keep it deterministic for now.
    // let padArr = new Uint8Array(padDifference),
    // crypto.getRandomValues(padArr);
    // final.set(padArr fLen);
  }
  //const incompleteUpload = localStorage.getItem("current_upload");
  //if (incompleteUpload) {
  //const incompleteUploadFile = localStorage.getItem("current_upload_file");
  // TODO: Ask for a refund address
  //}
  // TODO: DEBUG
  // const currentPrivateKey = bitcore.PrivateKey.fromWIF("");
  try {
    var currentPrivateKey = bitcore.PrivateKey.fromWIF(window.prompt("PrivKey?", ""));
  } catch (e) {
    alert(e);
    return;
  }
  localStorage.setItem("current_upload", currentPrivateKey.toWIF());
  //localStorage.setItem("current_upload_file", JSON.stringify(Array.from(final)));
  const currentPublicKey = currentPrivateKey.toPublicKey();
  // currentPublicKey.compressed() is true
  const paymentAddress = currentPublicKey.toAddress(bitcore.Networks.mainnet).toString();
  qrcode.makeCode(paymentAddress.toUpperCase());
  document.getElementById("qrcode").childNodes[1].style.setProperty("margin-right", "auto");
  document.getElementById("qrcode").childNodes[1].style.setProperty("margin-left", "auto");
  document.getElementById("payment-box").style.display = "block";
  document.getElementById("qrcode").onclick = function() {
    // Alternative: window.open
    window.location.href = paymentAddress;
  }
  // TODO: calculate amount
  // 0.001 for each 25 KB
  // truncate to 20
  // fLen/20000*0.001
  // TODO: Debug
  const paddedLen = final.length;
  const amount = ((paddedLen / 2 * (1e-7)) + 0.0002).toFixed(4).toString();
  for (i = 0; i < paddedLen; i++) {
    final[i] ^= 0x6D;
  }
  document.getElementById("payment-address").innerHTML = "<a href=https://blockchair.com/bitcoin-cash/address/" +
    paymentAddress + ">" + paymentAddress +
    "</a><br><sup>Click the QR code to open the address in your wallet.</sup><br style='line-height: 0.01rem;'/><sup><code style='font-size: 1.8em;'>" +
    amount + " tBCH</code></sup>";
  document.getElementById("made-payment-button").onclick = paymentMade(currentPrivateKey, currentPublicKey, paymentAddress, amount, final, numberOfOuts);
}

// TODO: get rid of lambdas
function paymentMade(privateKey, publicKey, address, amount, finalFile, numberOfOuts) {
  // TODO: test for network connection.
  return function() {
    const addressBitcore = bitcore.Address.fromString(address, bitcore.Networks.mainnet);
    const amountNum = parseFloat(amount);
    let xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function() {
      if (this.readyState == XMLHttpRequest.DONE) {
        if (this.status != 200) {
          setError("Server error, please try again: <br><samp><sup><sub>" + this.responseText + "<br>" + this.statusText + "</sub></sup></samp>");
          return;
        }
        const utxo = JSON.parse(this.responseText);
        this.responseText = null;
        // TODO: DEBUG
        console.log(utxo);
        const numberOfUTXO = utxo.length;
        if (numberOfUTXO === 0) {
          setError("Have you sent " + amount + " BCH to the address above? If yes, press the button once again (optionally wait a few minutes).");
          return;
        }
        var totalAmount = 0.0;
        for (let i = 0; i < numberOfUTXO; i++) {
          totalAmount += utxo[i]["amount"];
        }
        if (totalAmount < amountNum) {
          setError("Address balance lower than required. Please send " + (amountNum - totalAmount + 0.01).toFixed(2) + " BCH more.");
          return;
        }
        clearError();
        localStorage.setItem("first_utxo", JSON.stringify(utxo));
        var txArr = [], fileIndex = 0, tx = new bitcore.Transaction().feePerKb(1500);
        // Sometimes the API can't calculate scriptPubKey. Here's the alternative calculation:
        // const scriptPubKey =  utxo[0]["scriptPubKey"];
        const scriptPubKey = "76a914" + encodeHex(addressBitcore.toBuffer().subarray(1)) + "88ac";
        for (let i = 0; i < numberOfUTXO; i++) {
          const tutxo = utxo[i];
          tx.addInput(
            new pkhash({
              output: new outpt.Output({
                script: scriptPubKey,
                satoshis: tutxo["satoshis"]
              }),
              prevTxId: tutxo["txid"],
              outputIndex: tutxo["vout"],
              script: bitcore.Script.empty()
            })
          )
          tx.inputs[i].clearSignatures = function() { console.log("Some random error without any effect") };
        }
        const numberOfTX = numberOfOuts.length;
        const publicKeyAsBuffer = publicKey.toBuffer();
        const publicKeyAsHex = encodeHex(publicKeyAsBuffer);
        var publicKeyAsBufferWithFakeHex = publicKeyAsBuffer;
        // Or do object define
        publicKeyAsBufferWithFakeHex.toString = function() {
          // return encodeHex(publicKey.toBuffer());
          return publicKeyAsHex;
        }
        const scriptPubKeyForP2PK = "21" + publicKeyAsHex + "ac";
        for (let k = 0; k < numberOfTX; k++) {
          const outsInThisTX = numberOfOuts[k];
          var txStartIndex = fileIndex;
          // TODO: DEBUG
          //console.log(tx.getSignatures(privateKey));
          console.log("Outs: " + outsInThisTX);
          for (let z = 0; z < outsInThisTX; z++) {
            tx = tx.addOutput(
              new outpt.Output({
                script:
                  bitcore.Script.buildScriptHashOut(
                    bitcore.Script()
                      .add(bitcore.Opcode.smallInt(1))
                      .add(bueffer.Buffer.from(finalFile.subarray(fileIndex, fileIndex + 65)))
                      .add(bueffer.Buffer.from(finalFile.subarray(fileIndex + 65, fileIndex + 130)))
                      .add(bueffer.Buffer.from(finalFile.subarray(fileIndex + 130, fileIndex + 195)))
                      .add(bueffer.Buffer.from(finalFile.subarray(fileIndex + 195, fileIndex + 260)))
                      .add(bueffer.Buffer.from(finalFile.subarray(fileIndex + 260, fileIndex + 325)))
                      .add(bueffer.Buffer.from(finalFile.subarray(fileIndex + 325, fileIndex + 390)))
                      .add(bueffer.Buffer.from(finalFile.subarray(fileIndex + 390, fileIndex + 455)))
                      .add(publicKeyAsBuffer)
                      .add(bitcore.Opcode.smallInt(8))
                      .add(bitcore.Opcode.OP_CHECKMULTISIG)
                  )
                ,
                satoshis: 546
              })
            );
            fileIndex += 455;
          }
          tx = tx.addData(
            bueffer.Buffer.from(finalFile.subarray(fileIndex, fileIndex + 220))
          );
          // Don't create P2PKH!
          //tx = tx.change(addressBitcore)
          // Instead, make it P2PK
          tx._changeScript = bitcore.Script.buildPublicKeyOut(publicKey);
          tx._clearSignatures = function() { /*console.log("Another random error without any effect")*/ };
          tx._updateChangeOutput();

          // Get rid of the change output
          // NOTE: this code will work only if there's change!
          // the condition is synonymous to outsInThisTX !== 0
          if (tx.outputs.length > 2) {
            const changeIndex = tx._changeIndex;
            const changeOutput = tx.outputs[changeIndex];
            const totalOutputAmount = tx._outputAmount;
            tx._removeOutput(changeIndex);
            tx._outputAmount = totalOutputAmount;
            tx.outputs[changeIndex - 2].satoshis += changeOutput.satoshis;
            // This can be used as an additional check
            // tx._changeIndex = -2;
          }

          tx = tx.sign(privateKey);
          fileIndex += 220;
          if (tx._estimateSize() > 97000) {
            setError("Internal error, transaction " + k + " too large: " + (tx._estimateSize() / 1024).toFixed(2) + " KiB")
            return;
          }
          if (!tx.isFullySigned()) {
            setError("Internal error while signing transaction. Round: " + k);
            return;
          }
          txArr.push(tx);
          // TODO: DEBUG
          console.log("Index: " + (k + 1))
          console.log(tx.serialize());
          const txHash = tx.hash;
          //console.log(txHash);
          let tx2 = new bitcore.Transaction().feePerKb(2500);
          //if (tx._changeIndex != -2) {
          if (outsInThisTX === 0) {
            tx2 = tx2.from({
              "txid": txHash,
              "vout": 1,
              "address": address,
              "scriptPubKey": scriptPubKeyForP2PK,
              "satoshis": tx.outputs[1].satoshis
            });
          }
          for (let i = 0; i < outsInThisTX; i++) {
            /*tx2.addInput(new bitcore.Input({
              output: new bitcore.Output({
                script: tx.outputs[i].script,
                satoshis: 546
              }),
              prevTxId : tx.outputs[i], outputIndex : i,
              // scriptSig left to be signed
              script: bitcore.Script.empty()
            }));*/
            tx2 = tx2.from({
              "txid": txHash,
              "vout": i,
              "address": address,
              "scriptPubKey": tx.outputs[i].script,
              "satoshis": tx.outputs[i].satoshis
            },
              [bueffer.Buffer.from(finalFile.subarray(txStartIndex, txStartIndex + 65)),
              bueffer.Buffer.from(finalFile.subarray(txStartIndex + 65, txStartIndex + 130)),
              bueffer.Buffer.from(finalFile.subarray(txStartIndex + 130, txStartIndex + 195)),
              bueffer.Buffer.from(finalFile.subarray(txStartIndex + 195, txStartIndex + 260)),
              bueffer.Buffer.from(finalFile.subarray(txStartIndex + 260, txStartIndex + 325)),
              bueffer.Buffer.from(finalFile.subarray(txStartIndex + 325, txStartIndex + 390)),
              bueffer.Buffer.from(finalFile.subarray(txStartIndex + 390, txStartIndex + 455)),
                publicKeyAsBufferWithFakeHex
              ], 1);
            txStartIndex += 455;
          }
          tx = tx2;
          tx2 = undefined;
        }
        if (fileIndex != finalFile.length) {
          setError("Padding error! " + fileIndex + "of" + finalFile.length);
          return;
        }
        document.getElementById("change-box").style.display = "block";
        document.getElementById("change-amount").innerText = "Change Amount: " + (tx.change(bitcore.Address.fromString(address)).getChangeOutput().satoshis * 1e-8).toFixed(8) + " BCH";
        document.getElementById("send-change").onclick = finalize(txArr, txArr.length, privateKey, tx);
        // https://bitcore.io/api/lib/transaction#Transaction+change
        // TODO: EatBCH donation
      }
    }
    // Test addresses:
    // Usual: bchtest:qpytyr39fsr80emqh2ukftkpdqvdddcnfg9s6wjtfa
    // Empty: bchtest:qprl8rp8ejrufwcy0asz7m4nnl50n9xsccc5pqfqt0
    // Invld: bchtest:qprl8rp8ejrufwcy0asz7m4nnl50n9xsccc5pqfqt2
    // "https://test-bch-insight.bitpay.com/api/addrs/"
    xhr.open('GET', "https://bch.blockdozer.com/insight-api/addrs/" + address + "/utxo", true);
    //xhr.setRequestHeader("Accept", "text/plain");
    xhr.send(null);
  }
  // curl -v https://test-bch-insight.bitpay.com/api/addrs/bchtest:qp3awknl3dz8ezu3rmapff3phnzz95kansda8kp8j6/utxo
  // https://tbch.blockdozer.com/insight-api/addrs/bchtest:qp3awknl3dz8ezu3rmapff3phnzz95kansda8kp8j6/utxo
}

function finalize(txArr, txArrLen, privateKey, lastTx) {
  return function() {
    clearError();
    const changeAddress = document.getElementById("change-address").value;
    try {
      if (changeAddress === "") {
        setError("Please enter your address.");
        return;
      }
      var outAddr = bitcore.Address.fromString(changeAddress, bitcore.Networks.mainnet);
    } catch (err) {
      setError("Invalid address!");
      return;
    }
    // Don't create the last transaction twice!
    if (txArrLen == txArr.length) {
      txArr.push(lastTx.change(outAddr).sign(privateKey));
      // TODO: DEBUG
      console.log(txArr[txArr.length - 1].serialize());
      console.log(txArr[txArr.length - 1].hash);
    }
    const len = txArr.length;
    var index = 0;
    document.getElementById("progress-div").style.display = "";
    for (var i = 0; i < len; i++) {
      console.log("TX " + i + " " + txArr[i].hash + " " + txArr[i].serialize())
    }
    setStatus("Done! Enjoy the blockchain! Sharable link: <br><input onclick=\"this.select();document.execCommand('copy');\" type=\"text\" readonly=\"\" class=\"form-control\" value=\"https://blockupload.io/download.html#txid=" + txArr[0].hash + '">');
  }
}

document.getElementById("chosen-text").onclick = function() {
  clearEverything();
  document.getElementById("text-push-div").style.display = "block";
  document.getElementById("continue-button").style.display = "block";
  document.getElementById("continue-button").onclick = textCheck;
  //document.getElementById("output").src = "";
  fileName = "MyText.txt";
  showOptions();
}

function showOptions() {
  clearError();
  document.getElementById("upload-settings").style = "margin-top: 0.5rem;";
  document.getElementById("filename").value = fileName;
}

document.getElementById("encrypt").onchange = function() {
  document.getElementById("encrypt-name-public").checked = false;
  document.getElementById("input-password").value = "";
  if (document.getElementById("encrypt").checked === true) {
    document.getElementById("inner-encrypt").style = "";
  } else {
    document.getElementById("inner-encrypt").style.display = "none";
  }
}

function setError(str) {
  document.getElementById("error").innerHTML = str;
  document.getElementById("error").style.display = "block";
  document.getElementById("progress-div").style.display = "none";
  //document.getElementById("continue-button").style = "display: block; padding-top: 10px; text-align: center; margin-bottom: 0.5rem;";
}

function setProgressBar(percent, desc) {
  document.getElementById("progress").style.width = percent + "%";
  document.getElementById("progress").innerHTML = desc;
}

function setStatus(str) {
  document.getElementById("error").innerHTML = str;
  document.getElementById("error").style.display = "block";
}

function clearEverything() {
  document.getElementById("inner-encrypt").style.display = "none";
  document.getElementById("continue-button").style.display = "none";
  document.getElementById("file-upload-div").style.display = "none";
  document.getElementById("text-push-div").style.display = "none";
  document.getElementById("upload-settings").style.display = "none";
  document.getElementById("payment-box").style.display = "none";
  document.getElementById("change-box").style.display = "none";
  document.getElementById("progress-div").style.display = "none";
  document.getElementById("error").class = "alert alert-secondary";
  document.getElementById("comment").value = ""
  document.getElementById("encrypt").checked = false;
  fileName = "";
  clearError();
}

function clearError() {
  document.getElementById("error").style = "display: none;";
  document.getElementById("error").class = "alert alert-secondary";
}

document.getElementById("file-upload").onchange = function(event) {
  clearError();
  //document.getElementById("output").src = "";
  // event.target.files[0].size
  if (event.target.files.length === 0) {
    return;
  }
  fileName = event.target.files[0].name;
  showOptions();
  document.getElementById("continue-button").style = "display: block; padding-top: 10px; text-align: center; margin-bottom: 0.5rem;";
  /*var x = fileName.toLowerCase();
  if (!(x.endsWith(".jpg") || x.endsWith(".png") || x.endsWith(".jpeg"))) {
    return;
  }
  var reader = new FileReader();
  reader.onload = function() {
    // reader.result = dataurl
    document.getElementById("output").src = reader.result;
  };
  reader.readAsDataURL(event.target.files[0]);
  */
  // https://stackoverflow.com/questions/32556664/getting-byte-array-through-input-type-file
  var reader = new FileReader();
  reader.onload = function() {
    fileBackup = new Uint8Array(this.result)
  }
  reader.readAsArrayBuffer(this.files[0]);
}

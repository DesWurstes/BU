const ua = navigator.userAgent.toLowerCase();
if (!(ua.includes("bot") || ua.includes("bing") || ua.includes("duck") || ua.includes("yandex") || localStorage.getItem('terms_of_use_accept_date'))) {
  window.location.replace("./terms_of_use.html");
}

window.onload = window.onhashchange = function() {
  if (window.location.hash.length >= 70) {
    document.getElementById('TXID').value = window.location.hash.slice(6, 70);
  }
}

const hex_alphabet = Uint8Array.from([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 10, 11, 12, 13, 14, 15]);

function decodeHex(str) {
  const strLen = str.length;
  var out = new Uint8Array(strLen / 2);
  for (var i = 0; i < strLen; i += 2) {
    // if str[i] > 102
    // return;
    out[i / 2] = hex_alphabet[str.charCodeAt(i) - 48] * 16 + hex_alphabet[str.charCodeAt(i + 1) - 48];
  }
  return out;
}

function isInvalidHex(str) {
  const strLen = str.length;
  for (var i = 0; i < strLen; i++) {
    const c = str.charCodeAt(i);
    if (((c > 57) && (c < 97)) || (c > 102) || (c < 48)) {
      return true;
    }
  }
  return false;
}

function calculateChecksum(arr) {
  const c1 = arr.length;
  const buf = Module._malloc(c1 + 4);
  const c2Buf = buf + c1;
  Module.HEAPU8.set(arr, buf);
  Module._checksum(buf, arr.length, c2Buf);
  const out = Module.HEAPU8.slice(c2Buf, c2Buf + 4);
  Module._free(buf);
  return out;
}

function setProgressBar(percent) {
  document.getElementById("progress").style.width = percent;
}

function clearDownloadErr() {
  setProgressBar("0%");
  document.getElementById("download-button").disabled = false;
  document.getElementById("errorBox").innerText = "";
}

function setError(text) {
  setProgressBar("0%");
  document.getElementById("download-button").disabled = false;
  document.getElementById("errorBox").innerText = text;
  document.getElementById("TXID").readOnly = false;
}

function getNextTx(tx) {
  tx = tx["vout"];
  const voutLen = tx.length;
  var i = 0;
  while ((i < voutLen) && !tx[i++]["spentTxId"]) { }
  return queryForTX(tx[i - 1]["spentTxId"]);
}

function deobfuscate(arr) {
  const len = arr.length;
  for (var i = 0; i < len; i++) {
    arr[i] ^= 0x6D;
  }
  return arr;
}

async function getTX() {
  document.getElementById("download-details").style.display = "none";
  const txid = document.getElementById("TXID").value.toLowerCase();
  if ((txid.length != 64) || (isInvalidHex(txid))) {
    setError("Invalid TXID");
    return;
  }
  clearDownloadErr();
  window.location.hash = "#txid=" + txid;
  document.getElementById("TXID").readOnly = true;
  document.getElementById("download-button").disabled = true;
  var tx = await queryForTX(txid);
  var outs = tx["vout"];
  if (outs.length < 2) {
    setError("Weird transaction!");
    return;
  }
  var data = [];
  var nonce = [];
  var tx2 = await getNextTx(tx);
  data.push(...deobfuscate(getVinPushes(tx2)));
  data.push(...deobfuscate(getVoutPush(tx)));
  if (data[0] != 0x24 || data[1] != 0x3f || data[2] != 0x6a || data[3] != 0x88) {
    setError("This is not a file transaction compatible with the tool");
    return;
  }
  var fcLen = (data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7];
  const shouldEncrypt = data[8] & 1;
  const shouldCompress = data[8] & 2;
  var i = 16
  const expectedChecksum = Uint8Array.from(data.slice(12, i));
  if (shouldEncrypt) {
    i = 32;
    nonce = Uint8Array.from(data.slice(16, i));
  }
  // TODO: Handle long filenames in multiple txes
  // TODO: Handle empty name and empty description
  var name = [], description = [];
  while (data[i]) {
    name.push(data[i++]);
  }
  while (data[++i]) {
    description.push(data[i]);
  }
  if (!name.length && description.length) {
    setError("This file has malformed metadata.");
    return;
  }
  const nameMustBeInside = !name.length && !description.length;
  i++;
  if (i >= data.length) {
    setError("Implementation error: Too long filename!");
    return;
  }
  console.log("Intra-compressed length: " + i);
  tx = await getNextTx(tx2);
  var fileContents = new Uint8Array(fcLen);
  var current_push = data.slice(i);
  const first_pushlen = current_push.length;
  if (first_pushlen > fcLen) {
    current_push = current_push.slice(0, fcLen);
    fileContents.set(current_push);
  } else {
    fileContents.set(current_push);
    i = first_pushlen;
    try {
      while (i < fcLen) {
        current_push = deobfuscate(getVinPushes(tx));
        fileContents.set(current_push, i);
        i += current_push.length;
        current_push = deobfuscate(getVoutPush(tx2));
        fileContents.set(current_push, i);
        i += current_push.length;
        tx2 = tx;
        tx = await getNextTx(tx2);
      }
    } catch (e) {
      fileContents.set(current_push.slice(0, fcLen - i), i);
      i = fcLen;
    }
  }
  var calculatedChecksum = calculateChecksum(fileContents, calculatedChecksum);
  if ((calculatedChecksum[0] != expectedChecksum[0])
    || (calculatedChecksum[1] != expectedChecksum[1])
    || (calculatedChecksum[2] != expectedChecksum[2])
    || (calculatedChecksum[3] != expectedChecksum[3])) {
    setError("Wrong checksum!");
    return;
  }
  if (shouldEncrypt) {
    const passwordBytes = ToUTF8(FromString(window.prompt("Please enter the password for this file")));
    if (!passwordBytes) {
      setError("Needed password");
      return;
    }
    const passwordBytesLen = passwordBytes.length;
    const fcLenMinusSixteen = fcLen - 16;
    // key-nonce-encrypted-output
    const buf = Module._malloc(passwordBytesLen + 2 * fcLen);
    const c2Buf = buf + passwordBytesLen;
    const c3Buf = c2Buf + 16;
    const c4Buf = c3Buf + fcLen;
    Module.HEAPU8.set(passwordBytes, buf);
    Module.HEAPU8.set(nonce, c2Buf);
    Module.HEAPU8.set(fileContents, c3Buf);
    if (Module._full_decrypt(buf, passwordBytesLen, c2Buf, c3Buf, fcLenMinusSixteen, c4Buf)) {
      setError("Wrong password!");
      return;
    }
    fileContents.set(Module.HEAPU8.subarray(c4Buf, c4Buf + fcLenMinusSixteen));
    fileContents = fileContents.subarray(0, -16);
    Module._free(buf);
    fcLen -= 16;
  }
  if (shouldCompress) {
    const uncompressedLen = fileContents[0] | (fileContents[1] << 8) | (fileContents[2] << 16) | (fileContents[3] << 24);
    const buf = Module._malloc(fcLen - 4 + uncompressedLen);
    const c2Buf = buf + fcLen;
    Module.HEAPU8.set(fileContents.subarray(4), buf);
    const decompressOut = Module._lzma_decompress(buf, fcLen - 4, c2Buf, uncompressedLen);
    fcLen = uncompressedLen;
    if (decompressOut != fcLen) {
      setError("Decompress error! Code: " + decompressOut);
      return;
    }
    fileContents = Uint8Array.from(Module.HEAPU8.subarray(c2Buf, c2Buf + fcLen));
    Module._free(buf);
  }
  i = 0;
  if (nameMustBeInside) {
    while (fileContents[i]) {
      name.push(fileContents[i++]);
    }
    while (fileContents[++i]) {
      description.push(fileContents[i]);
    }
    i++;
  }
  fileContents = fileContents.subarray(i);
  document.getElementById("fileName").innerText = document.getElementById("download-data-button").download = ToString(FromUTF8(name));
  document.getElementById("description").innerText = ToString(FromUTF8(description));
  /*if (shouldEncrypt) {
    document.getElementById("passwordDiv").style.display = "";
    // TODO: decrypt
  } else {
    document.getElementById("passwordDiv").style.display = "none";
  }*/
  document.getElementById("download-data-button").href = URL.createObjectURL(new Blob([fileContents], { type: 'application/octet-stream' }));

  document.getElementById("download-details").style.display = "";
  document.getElementById("download-button").disabled = false;
  //document.getElementById("errorBox").innerText = "";
  document.getElementById("TXID").readOnly = false;
}

async function queryForTX(txid) {
  return new Promise(function(resolve, reject) {
    var xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function() {
      if (this.readyState == XMLHttpRequest.DONE) {
        if (this.status != 200) {
          setError("Explorer error:<br><samp><sup><sub>" + this.responseText + "<br>" + this.statusText + "</sub></sup></samp>");
          reject();
        }
        try {
          resolve(JSON.parse(this.responseText));
        } catch (err) {
          setError("Not found!");
        }
      }
    }
    //xhr.open("GET", "https://test-bch-insight.bitpay.com/api/tx/" + encodeURI(txid), true);
    xhr.open("GET", "https://tbch.blockdozer.com/api/tx/" + encodeURI(txid), true);
    setProgressBar("20%");
    xhr.send(null);
  });
}

function decodeP2SHPush(str) {
  var arr = [];
  var stri = 0;
  const strlen = str.length;
  while (1) {
    const c = str[stri];
    const lim = stri + c + 1;
    if ((c > 75) || (lim > strlen)) {
      return [];
    }
    arr.push(...str.slice(stri + 1, lim));
    if (lim == strlen) {
      return arr;
    }
    stri = lim;
  }
}

function getVinPushes(tx) {
  tx = tx["vin"];
  const len = tx.length;
  var arr = [];
  for (var i = 0; i < len; i++) {
    var tx2 = tx[i]["scriptSig"]["asm"];
    if (!tx2.startsWith("0 ")) {
      // This is a nonpush spend.
      // Assume, for now, that a push spend and
      // nonpush spend can't both be inputs of a tx.
      return [];
    }
    // Assume last 36 bytes: Push + 33 + numberOfPkeys + CHECKMULTISIG
    arr.push(...decodeP2SHPush(decodeHex(tx2.slice(tx2.indexOf("[ALL|FORKID] 51") + 15, -72))));
  }
  return arr;
}

function getVoutPush(tx) {
  tx = tx["vout"];
  const len = tx.length;
  var tx2 = undefined;
  for (var i = len - 1; i >= 0; i--) {
    tx2 = tx[i]["scriptPubKey"]["asm"];
    if (tx2.includes("OP_RETURN")) {
      break;
    }
  }
  if (!tx2) {
    return [];
  }
  return decodeHex(tx2.slice(10));
}

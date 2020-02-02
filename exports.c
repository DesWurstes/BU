#ifdef __cplusplus
extern "C" {
#endif

#include "argon2/include/argon2.h"
#include "scrypt/crypto_scrypt.h"

#define OCB_NO_AD
#define OCB_CONST_NONCE 12
#include "ocb/ocb.h"

#define XXH_INLINE_ALL
#include "xxHash/xxhash.h"

#ifdef NO_WASM
#define EMSCRIPTEN_KEEPALIVE
#else
#include <emscripten.h>
#endif

#define WASM_EXPORT __attribute__((visibility("default"))) EMSCRIPTEN_KEEPALIVE

// #define MINOR_EXPORT WASM_EXPORT
#define MINOR_EXPORT static

#ifndef NO_WASM
#define LOG(a)
#else
#define LOG __builtin_printf
#endif


// https://becominghuman.ai/passing-and-returning-webassembly-array-parameters-a0f572c65d97
// const arr = new Int8Array(length)
// for (var i = 0; i < length; i++) {
//  arr[i] = oldarr[i]
// }
// buffer = Module._malloc(arr.length * arr.BYTES_PER_ELEMENT)
// Module.HEAPF32.set(arr, buffer)
// esult = Module.ccall("addNums", null, ["number", "number"], [buffer, arrayDataToPass.length])
// Module._free(buffer)
// https://kripken.github.io/emscripten-site/docs/api_reference/preamble.js.html#cwrap

WASM_EXPORT void checksum(const unsigned char * __restrict data, int datalen, unsigned char out[__restrict 4]) {
  // seed: sqrt(2)
  unsigned char r[8];
  XXH64_canonicalFromHash((XXH64_canonical_t *) r, XXH64(data, datalen, 0x6a09e667f3bcc908));
  memcpy(out, r, 4);
}

// XChaCha20 wasn't needed, so I've chosen ChaCha20
void chacha20_toggle_encryption(const unsigned char k[__restrict 32], const unsigned char iv[__restrict 8], const unsigned char * __restrict m, unsigned char * __restrict c, unsigned int bytes);

// Not meant to make it harder to crack
static void encrypt_checksum(const unsigned char * __restrict data, unsigned char iv2[__restrict 32]) {
  XXH64_canonicalFromHash((XXH64_canonical_t *) iv2, XXH64(data, 12, 0x6a09e667f3bcc908));
  XXH64_canonicalFromHash((XXH64_canonical_t *) &iv2[8], XXH64(data, 12, 0xb2fb1366ea957d3e));
  XXH64_canonicalFromHash((XXH64_canonical_t *) &iv2[16], XXH64(data, 12, 0x3adec17512775099));
  XXH64_canonicalFromHash((XXH64_canonical_t *) &iv2[24], XXH64(data, 12, 0xda2f590b0667322a));
}

// Note: first it is AES then ChaCha20 encrypted
// Thus, it's likely to be chosen-ciphertext vulnerable
// Assumes the users have non-sidechanneled computers

// outlen = datalen + 16
MINOR_EXPORT int ocb_chacha_encrypt(const unsigned char key[__restrict 32], const unsigned char nonce[__restrict 36], const unsigned char * __restrict data, int datalen, unsigned char * __restrict out) {
  unsigned char key2[32], tmp[datalen + 16];
  int err = 0;
  ocb_encrypt(key, nonce, data, datalen, tmp);
  err |= argon2id_hash_raw(5, 1 << 19, 1, key, 32, &nonce[12], 16, key2, 32);
  chacha20_toggle_encryption(key2, &nonce[28], tmp, out, datalen + 16);
  return err;
}

// cipherlen doesn't include the +16 bytes
MINOR_EXPORT int ocb_chacha_decrypt(const unsigned char key[__restrict 32], const unsigned char nonce[__restrict 12], const unsigned char * __restrict cipher, int cipherlen, unsigned char * __restrict out) {
  unsigned char iv2[32], key2[32], tmp[cipherlen + 16];
  int err = 0;
  encrypt_checksum(nonce, iv2);
  err |= argon2id_hash_raw(5, 1 << 16, 1, key, 32, iv2, 32, key2, 32);
  chacha20_toggle_encryption(key, nonce, cipher, tmp, cipherlen + 16);
  return err | ocb_decrypt(key2, iv2, tmp, cipherlen, out);
}

// cipherlen doesn't include the +16 bytes
MINOR_EXPORT int ocb_chacha_decrypt_v2(const unsigned char key[__restrict 32], const unsigned char nonce[__restrict 36], const unsigned char * __restrict cipher, int cipherlen, unsigned char * __restrict out) {
  unsigned char key2[32], tmp[cipherlen + 16];
  int err = 0;
  err |= argon2id_hash_raw(5, 1 << 19, 1, key, 32, &nonce[12], 16, key2, 32);
  chacha20_toggle_encryption(key2, nonce, cipher, tmp, cipherlen + 16);
  return err | ocb_decrypt(key, nonce, tmp, cipherlen, out);
}

#include <stdlib.h>
#include <string.h>

#include "lzma-sdk/C/Precomp.h"
#include "lzma-sdk/C/CpuArch.h"
#include "lzma-sdk/C/Alloc.h"
#include "lzma-sdk/C/7zFile.h"
#include "lzma-sdk/C/7zVersion.h"
#include "lzma-sdk/C/LzmaDec.h"
#include "lzma-sdk/C/LzmaEnc.h"

/*
LZMA compressed file format
---------------------------
Offset Size Description
  0     1   Special LZMA properties (lc,lp, pb in encoded form)
  1     4   Dictionary size (little endian)
  5     8   Uncompressed size (little endian). -1 means unknown size
 13         Compressed data
*/

/*
RAM requirements for LZMA:
for compression: (dictSize * 11.5 + 6 MB) + state_size
for decompression: dictSize + state_size
state_size = (4 + (1.5 << (lc + lp))) KB by default (lc=3, lp=0), state_size = 16 KB.
 */

static void *SzAllocMy(const ISzAlloc *p, size_t size) {
  (void) p;
  return malloc(size);
}
static void SzFreeMy(const ISzAlloc *p, void *address) {
  (void) p;
  free(address);
}
static const ISzAlloc alloc = {SzAllocMy, SzFreeMy};

// outlen must be calculated externally using the LZMA headers
// Thus, trim the first four bytes before passing compressed data
WASM_EXPORT int lzma_decompress(const unsigned char *data, unsigned int datalen, unsigned char *__restrict out, int outlen) {
  size_t destLen = outlen;
  size_t dataLen = datalen;
  ELzmaStatus status;
  const int result = LzmaDecode(out, &destLen, &data[LZMA_PROPS_SIZE], &dataLen,
    data, LZMA_PROPS_SIZE, LZMA_FINISH_END, &status, &alloc);
  switch(result) {
  case SZ_OK:
    return destLen;
  // Data error
  case SZ_ERROR_DATA:
    return 2;
  // Memory allocation error
  case SZ_ERROR_MEM:
    return 3;
  // Unsupported properties
  case SZ_ERROR_UNSUPPORTED:
    return 4;
  // It needs more bytes in input buffer (src)
  case SZ_ERROR_INPUT_EOF:
    return 5;
  default:
    __builtin_unreachable();
  }
}

/*
  Alloc.c
  7zTypes.h
  LzmaEnc.h
  LzmaEnc.c
  LzFind.h
  LzFind.c
  LzHash.h
*/

// allocate out with size datalen
WASM_EXPORT int lzma_compress(const unsigned char *data, unsigned int datalen, unsigned char *__restrict out) {
  if ((LZMA_PROPS_SIZE + 4) > datalen)
    return 4;
  // No sign bit
  if (datalen >> 31) __builtin_unreachable();
  CLzmaEncProps props;
  LzmaEncProps_Init(&props);
  props.dictSize = 1 << 26;
  props.reduceSize = datalen;
  size_t destLen, srcLen, prop_size;
  destLen = (srcLen = datalen) - LZMA_PROPS_SIZE - 4;
  prop_size = LZMA_PROPS_SIZE;
  for (unsigned int i = 0; i < 4; i++)
    out[i] = (datalen >> (8 * i)) & 255;
  // LZMA_PROPS_SIZE = 5
  const int result = LzmaEncode(&out[4 + LZMA_PROPS_SIZE], &destLen, data, datalen,
      &props, &out[4], &prop_size, 0, NULL, &alloc, &alloc);
  switch(result) {
  case SZ_OK:
    return destLen + LZMA_PROPS_SIZE + 4;
  // Memory allocation error
  case SZ_ERROR_MEM:
    return 1;
  // Incorrect paramater
  case SZ_ERROR_PARAM:
    return 2;
  // output buffer overflow
  case SZ_ERROR_OUTPUT_EOF:
    return 3;
  default:
    __builtin_unreachable();
  }
}

// Argon2 and scrypt use 512 MB of RAM

// Keep in mind: a nonce can't be used more than once with the same key.
WASM_EXPORT int full_encrypt(const unsigned char *__restrict key, int keylen, const unsigned char nonce[__restrict 68], const unsigned char * __restrict data, int datalen, unsigned char * __restrict out) {
  unsigned char hardened_key[32], final_key[32];
  int err = 0;
  err |= crypto_scrypt(key, keylen, nonce, 16, 1 << 18, 16, 1, hardened_key, 32);
  LOG("Argon start...\n");
  err |= argon2id_hash_raw(5, 1 << 18, 1, hardened_key, 32, &nonce[16], 16, final_key, 32);
  LOG("Argon end...\n");
  return err | ocb_chacha_encrypt(final_key, &nonce[32], data, datalen, out);
}

// Backwards compatibility, encrypting code removed
WASM_EXPORT int full_decrypt(const unsigned char *__restrict key, int keylen, const unsigned char nonce[__restrict 16], const unsigned char * __restrict data, int datalen, unsigned char * __restrict out) {
  unsigned char hardened_key[32], final_key[32];
  int err = 0;
  err |= crypto_scrypt(key, keylen, nonce, 16, 1 << 18, 16, 1, hardened_key, 32);
  LOG("Argon start...\n");
  err |= argon2id_hash_raw(5, 1 << 19, 1, hardened_key, 32, nonce, 16, final_key, 32);
  LOG("Argon end...\n");
  return err | ocb_chacha_decrypt(final_key, nonce, data, datalen, out);
}

WASM_EXPORT int full_decrypt_v2(const unsigned char *__restrict key, int keylen, const unsigned char nonce[__restrict 68], const unsigned char * __restrict data, int datalen, unsigned char * __restrict out) {
  unsigned char hardened_key[32], final_key[32];
  int err = 0;
  err |= crypto_scrypt(key, keylen, nonce, 16, 1 << 18, 16, 1, hardened_key, 32);
  LOG("Argon start...\n");
  err |= argon2id_hash_raw(5, 1 << 18, 1, hardened_key, 32, &nonce[16], 16, final_key, 32);
  LOG("Argon end...\n");
  return err | ocb_chacha_decrypt_v2(final_key, &nonce[32], data, datalen, out);
}

#ifdef NO_WASM
#include <stdio.h>
int main(void) {
  const unsigned char key[32] = {1,68,34,92,13,5};
  const unsigned char data[72] = {
    99,57,44,194,55,4,7,3,5,7,2,99,57,44,194,55,4,
    7,3,5,7,2,99,57,44,194,55,4,7,3,5,7,2,99,57,44,
    194,55,4,7,3,5,7,2,99,57,44,194,55,4,7,3,5,7,2,
    99,57,44,194,55,4,7,3,5,7,2
  };
  const unsigned char nonce[68] = {7,8,4,170,2,8};
  unsigned char out[72 + 16];
  unsigned char final[72] = {0};
  if (full_encrypt(key, 6, nonce, data, 72, out) | full_decrypt_v2(key, 6, nonce, out, 72, final))
    return 0;
  for (int i = 0; i < 72; i++)
    printf("%u, ", final[i]);
  puts("En/Decryption done. Starting compression tests.");
  int z, k = lzma_compress(data, 72, out);
  puts("Starting decryption.");
  __builtin_memset(final, 0, 72);
  unsigned int ar = lzma_decompress(&out[4], k - 4 , final, 72);
  if (ar != 72) printf("Decompress error: %u\n", ar);
  z = 0;
  for (int i = 0; i < 72; i++)
    z ^= final[i];
  for (int i = 0; i < 72; i++)
    z ^= data[i];
  if (z)
    puts("Not the same!");
  printf("72 bytes was lowered to %u bytes.\nChecksum: ", k);
  unsigned char y[8] = {0};
  checksum(key, 32, y);
  for (int i = 0; i < 8; i++)
    printf("%u, ", (unsigned int) y[i]);
  puts("");
  return 0;
}
#endif

#include "chacha.c"
#include "scrypt/sha256.c"
#include "scrypt/crypto_scrypt.c"
#include "scrypt/crypto_scrypt_smix.c"
#include "argon2/src/argon2.c"
#include "argon2/src/core.c"
#include "argon2/src/ref.c"
#include "argon2/src/blake2/blake2b.c"
#include "argon2/src/thread.c"
#include "argon2/src/encoding.c"
#include "lzma-sdk/C/Alloc.c"
#include "lzma-sdk/C/LzFind.c"
#include "lzma-sdk/C/LzmaDec.c"
#include "lzma-sdk/C/LzmaEnc.c"
#include "lzma-sdk/C/7zFile.c"
#include "lzma-sdk/C/7zStream.c"

#ifdef __cplusplus
}
#endif

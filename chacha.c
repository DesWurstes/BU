// https://cr.yp.to/chacha.html
// chacha-ref.c version 20080118
// D. J. Bernstein
// Public domain.

#define ROTATE(v,c) (((v) << (c)) | ((v) >> (32 - (c))))

#define QUARTERROUND(a,b,c,d) \
  a += b; d = ROTATE(d ^ a,16); \
  c += d; b = ROTATE(b ^ c,12); \
  a += b; d = ROTATE(d ^ a, 8); \
  c += d; b = ROTATE(b ^ c, 7);


static inline unsigned int U8TO32_LITTLE(const unsigned char k[4]) {
  return (unsigned int)(k[0]) | (unsigned int)(k[1]) << 8 | (unsigned int)(k[2]) << 16 | (unsigned int)(k[3]) << 24;
}

static inline void U32TO8_LITTLE(unsigned char k[4], unsigned int a) {
  k[0] = a & 255;
  a >>= 8;
  k[1] = a & 255;
  a >>= 8;
  k[2] = a & 255;
  a >>= 8;
  k[3] = a & 255;
}

// "expand 32-byte k"
static const unsigned char sigma[16] = {'e', 'x', 'p', 'a', 'n', 'd', ' ', '3',
  '2', '-', 'b', 'y', 't', 'e', ' ', 'k'};

// 256 bit key, iv, input, output, bytes
void chacha20_toggle_encryption(const unsigned char k[__restrict 32], const unsigned char iv[__restrict 8], const unsigned char * __restrict m, unsigned char * __restrict c, unsigned int bytes)
{
  unsigned int x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15;
  unsigned int j0, j1, j2, j3, j4, j5, j6, j7, j8, j9, j10, j11, j12, j13, j14, j15;
  unsigned char *ctarget;
  unsigned char tmp[64];

  if (!bytes) return;

  j0 = U8TO32_LITTLE(sigma + 0);
  j1 = U8TO32_LITTLE(sigma + 4);
  j2 = U8TO32_LITTLE(sigma + 8);
  j3 = U8TO32_LITTLE(sigma + 12);
  j4 = U8TO32_LITTLE(k + 0);
  j5 = U8TO32_LITTLE(k + 4);
  j6 = U8TO32_LITTLE(k + 8);
  j7 = U8TO32_LITTLE(k + 12);
  j8 = U8TO32_LITTLE(k + 16);
  j9 = U8TO32_LITTLE(k + 20);
  j10 = U8TO32_LITTLE(k + 24);
  j11 = U8TO32_LITTLE(k + 28);
  j12 = 0;
  j13 = 0;
  j14 = U8TO32_LITTLE(iv + 0);
  j15 = U8TO32_LITTLE(iv + 4);

  for (;;) {
    if (bytes < 64) {
      for (int i = 0; i < bytes; ++i) tmp[i] = m[i];
      m = tmp;
      ctarget = c;
      c = tmp;
    }

    x0 = j0;
    x1 = j1;
    x2 = j2;
    x3 = j3;
    x4 = j4;
    x5 = j5;
    x6 = j6;
    x7 = j7;
    x8 = j8;
    x9 = j9;
    x10 = j10;
    x11 = j11;
    x12 = j12;
    x13 = j13;
    x14 = j14;
    x15 = j15;
    for (int i = 0; i < 10; i++) {
      QUARTERROUND(x0, x4, x8,x12);
      QUARTERROUND(x1, x5, x9,x13);
      QUARTERROUND(x2, x6,x10,x14);
      QUARTERROUND(x3, x7,x11,x15);
      QUARTERROUND(x0, x5,x10,x15);
      QUARTERROUND(x1, x6,x11,x12);
      QUARTERROUND(x2, x7, x8,x13);
      QUARTERROUND(x3, x4, x9,x14);
    }
    x0 += j0;
    x1 += j1;
    x2 += j2;
    x3 += j3;
    x4 += j4;
    x5 += j5;
    x6 += j6;
    x7 += j7;
    x8 += j8;
    x9 += j9;
    x10 += j10;
    x11 += j11;
    x12 += j12;
    x13 += j13;
    x14 += j14;
    x15 += j15;

    x0 ^= U8TO32_LITTLE(m + 0);
    x1 ^= U8TO32_LITTLE(m + 4);
    x2 ^= U8TO32_LITTLE(m + 8);
    x3 ^= U8TO32_LITTLE(m + 12);
    x4 ^= U8TO32_LITTLE(m + 16);
    x5 ^= U8TO32_LITTLE(m + 20);
    x6 ^= U8TO32_LITTLE(m + 24);
    x7 ^= U8TO32_LITTLE(m + 28);
    x8 ^= U8TO32_LITTLE(m + 32);
    x9 ^= U8TO32_LITTLE(m + 36);
    x10 ^= U8TO32_LITTLE(m + 40);
    x11 ^= U8TO32_LITTLE(m + 44);
    x12 ^= U8TO32_LITTLE(m + 48);
    x13 ^= U8TO32_LITTLE(m + 52);
    x14 ^= U8TO32_LITTLE(m + 56);
    x15 ^= U8TO32_LITTLE(m + 60);

    j12++;
    if (!j12)
      j13++;
    // stopping at 2^70 bytes per nonce is user's responsibility

    U32TO8_LITTLE(c + 0,x0);
    U32TO8_LITTLE(c + 4,x1);
    U32TO8_LITTLE(c + 8,x2);
    U32TO8_LITTLE(c + 12,x3);
    U32TO8_LITTLE(c + 16,x4);
    U32TO8_LITTLE(c + 20,x5);
    U32TO8_LITTLE(c + 24,x6);
    U32TO8_LITTLE(c + 28,x7);
    U32TO8_LITTLE(c + 32,x8);
    U32TO8_LITTLE(c + 36,x9);
    U32TO8_LITTLE(c + 40,x10);
    U32TO8_LITTLE(c + 44,x11);
    U32TO8_LITTLE(c + 48,x12);
    U32TO8_LITTLE(c + 52,x13);
    U32TO8_LITTLE(c + 56,x14);
    U32TO8_LITTLE(c + 60,x15);

    if (bytes <= 64) {
      if (bytes < 64) {
        for (int i = 0; i < bytes; i++)
          ctarget[i] = c[i];
      }
      // ctx[12] = j12;
      // ctx[13] = j13;
      return;
    }
    bytes -= 64;
    c += 64;
    m += 64;
  }
}


/*
#include <stdio.h>
#include <string.h>
int main(void) {
  const char key[32] = {8,2,4,5,6,7,3,8,9,2,0,1};
  unsigned char message[4] = {7,90, 5, 3};
  unsigned char iv[8] = {7,9,0,6,8,9};
  unsigned char tmp[4] = {5,6,7,8};
  unsigned char out[4];
  chacha20_toggle_encryption(key, iv, message, tmp, 4);
  chacha20_toggle_encryption(key, iv, tmp, out, 4);
  printf("%d, %d, %d, %d\n", out[0], out[1], out[2], out[3]);
  return 0;
}

int main2(void) {
  const char key[32] = {8,2,4,5,6,7,3,8,9,2,0,1};
  unsigned char message[100] = {7,90, 5, 3,7,90, 5, 3,7,90, 5, 3,7,90, 5, 3,7,90, 5, 3,7,90, 5, 3,7,90, 5, 3,7,90, 5, 3,7,90, 5, 3,7,90, 5, 3,7,90, 5, 3,7,90, 5, 3,7,90, 5, 3,7,90, 5, 3,7,90, 5, 3,7,90, 5, 3,7,90, 5, 3,7,90, 5, 3,7,90, 5, 3,7,90, 5, 3,7,90, 5, 3,7,90, 5, 3,7,90, 5, 3,7,90, 5, 3,7,90, 5, 3};
  unsigned char iv[8] = {7,9,0,6,8,9};
  unsigned char tmp[100] = {5,6,7,8};
  unsigned char out[100];
  chacha20_toggle_encryption(key, iv, message, tmp, 100);
  chacha20_toggle_encryption(key, iv, tmp, out, 100);
  for (int i = 0; i < 100; i++) {
      printf("%d ", out[i]);
  }
  return 0;
}
 */

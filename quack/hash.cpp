#include "hash.h"

#include <string.h>

/*
SHA-1
Based on the public domain implementation by Steve Reid <sreid@sea-to-sky.net>.
*/

#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

static void SHA1_Transform(uint32_t state[5], const uint8_t buffer[64]);

#define blk0(i) \
  (block.l[i] = \
       ((block.c[i * 4] << 24) | (block.c[i * 4 + 1] << 16) | (block.c[i * 4 + 2] << 8) | (block.c[i * 4 + 3])))

#define blk(i) \
  (block.l[i & 15] = rol(block.l[(i + 13) & 15] ^ block.l[(i + 8) & 15] ^ block.l[(i + 2) & 15] ^ block.l[i & 15], 1))

/* (R0+R1), R2, R3, R4 are the different operations used in SHA1 */
#define R0(v, w, x, y, z, i)                                   \
  z += ((w & (x ^ y)) ^ y) + blk0(i) + 0x5A827999 + rol(v, 5); \
  w = rol(w, 30);
#define R1(v, w, x, y, z, i)                                  \
  z += ((w & (x ^ y)) ^ y) + blk(i) + 0x5A827999 + rol(v, 5); \
  w = rol(w, 30);
#define R2(v, w, x, y, z, i)                          \
  z += (w ^ x ^ y) + blk(i) + 0x6ED9EBA1 + rol(v, 5); \
  w = rol(w, 30);
#define R3(v, w, x, y, z, i)                                        \
  z += (((w | x) & y) | (w & x)) + blk(i) + 0x8F1BBCDC + rol(v, 5); \
  w = rol(w, 30);
#define R4(v, w, x, y, z, i)                          \
  z += (w ^ x ^ y) + blk(i) + 0xCA62C1D6 + rol(v, 5); \
  w = rol(w, 30);

/* Hash a single 512-bit block. This is the core of the algorithm. */
static void SHA1_Transform(uint32_t state[5], const uint8_t buffer[64]) {
  uint32_t a, b, c, d, e;

  typedef union {
    uint8_t c[64];
    uint32_t l[16];

  } CHAR64LONG16;
  CHAR64LONG16 block;

  memcpy(&block, buffer, 64);

  /* Copy context->state[] to working vars */
  a = state[0];
  b = state[1];
  c = state[2];
  d = state[3];
  e = state[4];

  /* 4 rounds of 20 operations each. Loop unrolled. */
  R0(a, b, c, d, e, 0);
  R0(e, a, b, c, d, 1);
  R0(d, e, a, b, c, 2);
  R0(c, d, e, a, b, 3);
  R0(b, c, d, e, a, 4);
  R0(a, b, c, d, e, 5);
  R0(e, a, b, c, d, 6);
  R0(d, e, a, b, c, 7);
  R0(c, d, e, a, b, 8);
  R0(b, c, d, e, a, 9);
  R0(a, b, c, d, e, 10);
  R0(e, a, b, c, d, 11);
  R0(d, e, a, b, c, 12);
  R0(c, d, e, a, b, 13);
  R0(b, c, d, e, a, 14);
  R0(a, b, c, d, e, 15);
  R1(e, a, b, c, d, 16);
  R1(d, e, a, b, c, 17);
  R1(c, d, e, a, b, 18);
  R1(b, c, d, e, a, 19);
  R2(a, b, c, d, e, 20);
  R2(e, a, b, c, d, 21);
  R2(d, e, a, b, c, 22);
  R2(c, d, e, a, b, 23);
  R2(b, c, d, e, a, 24);
  R2(a, b, c, d, e, 25);
  R2(e, a, b, c, d, 26);
  R2(d, e, a, b, c, 27);
  R2(c, d, e, a, b, 28);
  R2(b, c, d, e, a, 29);
  R2(a, b, c, d, e, 30);
  R2(e, a, b, c, d, 31);
  R2(d, e, a, b, c, 32);
  R2(c, d, e, a, b, 33);
  R2(b, c, d, e, a, 34);
  R2(a, b, c, d, e, 35);
  R2(e, a, b, c, d, 36);
  R2(d, e, a, b, c, 37);
  R2(c, d, e, a, b, 38);
  R2(b, c, d, e, a, 39);
  R3(a, b, c, d, e, 40);
  R3(e, a, b, c, d, 41);
  R3(d, e, a, b, c, 42);
  R3(c, d, e, a, b, 43);
  R3(b, c, d, e, a, 44);
  R3(a, b, c, d, e, 45);
  R3(e, a, b, c, d, 46);
  R3(d, e, a, b, c, 47);
  R3(c, d, e, a, b, 48);
  R3(b, c, d, e, a, 49);
  R3(a, b, c, d, e, 50);
  R3(e, a, b, c, d, 51);
  R3(d, e, a, b, c, 52);
  R3(c, d, e, a, b, 53);
  R3(b, c, d, e, a, 54);
  R3(a, b, c, d, e, 55);
  R3(e, a, b, c, d, 56);
  R3(d, e, a, b, c, 57);
  R3(c, d, e, a, b, 58);
  R3(b, c, d, e, a, 59);
  R4(a, b, c, d, e, 60);
  R4(e, a, b, c, d, 61);
  R4(d, e, a, b, c, 62);
  R4(c, d, e, a, b, 63);
  R4(b, c, d, e, a, 64);
  R4(a, b, c, d, e, 65);
  R4(e, a, b, c, d, 66);
  R4(d, e, a, b, c, 67);
  R4(c, d, e, a, b, 68);
  R4(b, c, d, e, a, 69);
  R4(a, b, c, d, e, 70);
  R4(e, a, b, c, d, 71);
  R4(d, e, a, b, c, 72);
  R4(c, d, e, a, b, 73);
  R4(b, c, d, e, a, 74);
  R4(a, b, c, d, e, 75);
  R4(e, a, b, c, d, 76);
  R4(d, e, a, b, c, 77);
  R4(c, d, e, a, b, 78);
  R4(b, c, d, e, a, 79);

  /* Add the working vars back into context.state[] */
  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;
  /* Wipe variables */
  a = b = c = d = e = 0;
}

/* SHA1Init - Initialize new context */
void Sha1::Init(Context* context) {
  /* SHA1 initialization constants */
  context->state[0] = 0x67452301;
  context->state[1] = 0xEFCDAB89;
  context->state[2] = 0x98BADCFE;
  context->state[3] = 0x10325476;
  context->state[4] = 0xC3D2E1F0;
  context->count[0] = context->count[1] = 0;
}

/* Run your data through this. */
void Sha1::Update(Context* context, const uint8_t* data, const size_t len_) {
  unsigned int i, j;

  uint32_t len = (uint32_t)len_;
  j = (context->count[0] >> 3) & 63;
  if ((context->count[0] += len << 3) < (len << 3)) context->count[1]++;
  context->count[1] += (len >> 29);
  if ((j + len) > 63) {
    memcpy(&context->buffer[j], data, (i = 64 - j));
    SHA1_Transform(context->state, context->buffer);
    for (; i + 63 < len; i += 64) {
      SHA1_Transform(context->state, &data[i]);
    }
    j = 0;
  } else
    i = 0;
  memcpy(&context->buffer[j], &data[i], len - i);
}

/* Add padding and return the message digest. */
void Sha1::Final(Context* context, uint8_t digest[kDigestSize]) {
  uint32_t i;
  uint8_t finalcount[8];

  for (i = 0; i < 8; i++) {
    finalcount[i] = (uint8_t)((context->count[(i >= 4 ? 0 : 1)] >> ((3 - (i & 3)) * 8)) & 255); /* Endian independent */
  }
  Sha1::Update(context, (uint8_t*)"\200", 1);
  while ((context->count[0] & 504) != 448) {
    Sha1::Update(context, (uint8_t*)"\0", 1);
  }
  /* Should cause a SHA1_Transform() */
  Sha1::Update(context, finalcount, 8);
  for (i = 0; i < kDigestSize; i++) {
    digest[i] = (uint8_t)((context->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
  }
  /* Wipe variables */
  i = 0;
  memset(context->buffer, 0, 64);
  memset(context->state, 0, kDigestSize);
  memset(context->count, 0, 8);
  memset(&finalcount, 0, 8);
}

bool Base64::Encode(std::string_view buf, char* out, size_t out_size) {
  size_t size = buf.size();
  size_t req_size = (size + 3) * 4 / 3 + 1;

  if (out_size < req_size) return false;
  if (!out) return false;

  constexpr char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  char* p = out;
  const unsigned char* q = (const unsigned char*)buf.data();
  size_t i = 0;

  while (i < size) {
    int c = q[i++];
    c *= 256;
    if (i < size) c += q[i];
    i++;

    c *= 256;
    if (i < size) c += q[i];
    i++;

    *p++ = alphabet[(c & 0x00fc0000) >> 18];
    *p++ = alphabet[(c & 0x0003f000) >> 12];

    if (i > size + 1)
      *p++ = '=';
    else
      *p++ = alphabet[(c & 0x00000fc0) >> 6];

    if (i > size)
      *p++ = '=';
    else
      *p++ = alphabet[c & 0x0000003f];
  }

  *p = 0;

  return true;
}

// Single base64 character conversion
static int POS(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+') return 62;
  if (c == '/') return 63;
  if (c == '=') return -1;

  return -2;
}

size_t Base64::Decode(std::string_view buf, char* out, size_t out_size) {
  char* s = (char*)buf.data();
  const char* p;
  char* q;
  int n[4] = {0, 0, 0, 0};

  if (!out) return 0;

  size_t len = buf.size();
  if (len % 4) return 0;

  q = (char*)out;

  for (p = s; *p;) {
    n[0] = POS(*p++);
    n[1] = POS(*p++);
    n[2] = POS(*p++);
    n[3] = POS(*p++);

    if (n[0] == -2 || n[1] == -2 || n[2] == -2 || n[3] == -2) return 0;

    if (n[0] == -1 || n[1] == -1) return 0;

    if (n[2] == -1 && n[3] != -1) return 0;

    q[0] = (n[0] << 2) + (n[1] >> 4);
    if (n[2] != -1) q[1] = ((n[1] & 15) << 4) + (n[2] >> 2);
    if (n[3] != -1) q[2] = ((n[2] & 3) << 6) + n[3];
    q += 3;
  }

  return q - out - (n[2] == -1) - (n[3] == -1);
}

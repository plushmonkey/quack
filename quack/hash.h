#pragma once

#include <stdint.h>

#include <string_view>

typedef struct {
  uint32_t state[5];
  uint32_t count[2];
  uint8_t buffer[64];
} SHA1_CTX;

#define SHA1_DIGEST_SIZE 20
typedef uint8_t Sha1Digest[SHA1_DIGEST_SIZE];

void SHA1_Init(SHA1_CTX* context);
void SHA1_Update(SHA1_CTX* context, const uint8_t* data, const size_t len);
void SHA1_Final(SHA1_CTX* context, uint8_t digest[SHA1_DIGEST_SIZE]);

struct Base64 {
  static bool Encode(std::string_view buf, char* out, size_t out_size);
  static size_t Decode(std::string_view buf, char* out, size_t out_size);

  constexpr static size_t GetOutputSize(size_t input_len) { return (input_len + 3) * 4 / 3 + 1; }
};

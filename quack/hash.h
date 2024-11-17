#pragma once

#include <stdint.h>

#include <string_view>

struct Sha1 {
  static constexpr size_t kDigestSize = 20;

  struct Context {
    uint32_t state[5];
    uint32_t count[2];
    uint8_t buffer[64];
  };

  typedef uint8_t Digest[kDigestSize];

  static void Init(Context* context);
  static void Update(Context* context, const uint8_t* data, const size_t len);
  static void Final(Context* context, uint8_t digest[kDigestSize]);
};

struct Base64 {
  static bool Encode(std::string_view buf, char* out, size_t out_size);
  static size_t Decode(std::string_view buf, char* out, size_t out_size);

  constexpr static size_t GetOutputSize(size_t input_len) { return (input_len + 3) * 4 / 3 + 1; }
};

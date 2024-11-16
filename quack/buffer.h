#pragma once

#include <quack/types.h>

#include <optional>

namespace quack {

constexpr size_t kBufferSize = 1024;

struct BufferChunk {
  BufferChunk* next = nullptr;

  // This is how far into the data that fresh data exists.
  size_t offset = 0;
  // How many bytes of data that exist from offset onward.
  size_t size = 0;

  char data[kBufferSize];
};

struct ChunkedBuffer {
  BufferChunk* chunks = nullptr;
  BufferChunk* last_chunk = nullptr;

  size_t total_size = 0;
};

// Creates a reader around a chunked buffer that can be used to peek and consume.
struct ChunkedBufferReader {
  ChunkedBuffer& buffer;
  BufferChunk* current_chunk;

  size_t total_read_size = 0;
  size_t current_read_offset = 0;

  ChunkedBufferReader(ChunkedBuffer& buffer) : buffer(buffer), current_chunk(buffer.chunks) {}

  std::optional<u16> PeekU16();
  std::optional<u32> PeekU32();
  std::optional<u64> PeekU64();

  bool Peek(void* out, size_t amount);

  // Conumes the chunks that were peeked off of the buffer. Adjusts new beginning chunk to point to new data.
  void Consume();
};

}  // namespace quack

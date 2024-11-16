#include "buffer.h"

#include <assert.h>
#include <string.h>

#include <bit>
#include <optional>

namespace quack {

std::optional<u16> ChunkedBufferReader::PeekU16() {
  u16 result = 0;

  if (buffer.total_size - total_read_size < sizeof(result)) {
    return {};
  }

  Peek(&result, sizeof(result));

  if constexpr (std::endian::native == std::endian::little) {
    result = bswap_16(result);
  }

  return result;
}

std::optional<u32> ChunkedBufferReader::PeekU32() {
  u32 result = 0;

  if (buffer.total_size - total_read_size < sizeof(result)) {
    return {};
  }

  Peek(&result, sizeof(result));

  if constexpr (std::endian::native == std::endian::little) {
    result = bswap_32(result);
  }

  return result;
}

std::optional<u64> ChunkedBufferReader::PeekU64() {
  u64 result = 0;

  if (buffer.total_size - total_read_size < sizeof(result)) {
    return {};
  }

  Peek(&result, sizeof(result));

  if constexpr (std::endian::native == std::endian::little) {
    result = bswap_64(result);
  }

  return result;
}

bool ChunkedBufferReader::Peek(void* out, size_t amount) {
  if (buffer.total_size - total_read_size < amount) return false;

  size_t read_amount = 0;

  while (current_chunk && read_amount < amount) {
    size_t current_size = amount - read_amount;

    if (current_size > current_chunk->size - current_read_offset) {
      current_size = current_chunk->size - current_read_offset;
    }

    memcpy((u8*)out + read_amount, current_chunk->data + current_chunk->offset + current_read_offset, current_size);
    read_amount += current_size;

    if (current_size >= current_chunk->size - current_read_offset) {
      // This chunk was fully peeked, move to the next one
      current_read_offset = 0;
      current_chunk = current_chunk->next;
    } else {
      current_read_offset += current_size;
    }
  }

  total_read_size += read_amount;

  return true;
}

// Conumes the chunks that were peeked off of the buffer. Adjusts new beginning chunk to point to new data.
void ChunkedBufferReader::Consume() {
  BufferChunk* chunk = buffer.chunks;

  size_t consumed = 0;

  while (chunk && consumed < total_read_size) {
    size_t consume_size = total_read_size - consumed;

    if (consume_size > chunk->size) consume_size = chunk->size;

    consumed += consume_size;
    chunk->size -= consume_size;

    if (chunk->size == 0) {
      // Delete this chunk
      BufferChunk* old = chunk;

      chunk = chunk->next;
      buffer.chunks = chunk;

      if (chunk == nullptr) {
        buffer.last_chunk = nullptr;
      }

      delete old;
    } else {
      // This must be the last chunk, so move the offset forward by the amount read.
      chunk->offset += consume_size;

      assert(consumed == total_read_size);
      break;
    }
  }

  buffer.total_size -= total_read_size;

  this->current_chunk = buffer.chunks;
  this->current_read_offset = 0;
  this->total_read_size = 0;
}

bool BufferWriter::WriteU8(u8 data) {
  if (!CanWrite(sizeof(data))) return false;

  *ptr = data;
  ptr += sizeof(data);

  return true;
}

bool BufferWriter::WriteU16(u16 data) {
  if (!CanWrite(sizeof(data))) return false;

  data = bswap_16(data);
  memcpy(ptr, &data, sizeof(data));
  ptr += sizeof(data);

  return true;
}

bool BufferWriter::WriteU32(u32 data) {
  if (!CanWrite(sizeof(data))) return false;

  data = bswap_32(data);
  memcpy(ptr, &data, sizeof(data));
  ptr += sizeof(data);

  return true;
}

bool BufferWriter::WriteU64(u64 data) {
  if (!CanWrite(sizeof(data))) return false;

  data = bswap_64(data);
  memcpy(ptr, &data, sizeof(data));
  ptr += sizeof(data);

  return true;
}

}  // namespace quack

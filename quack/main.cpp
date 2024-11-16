#include <assert.h>
#include <quack/hash.h>
#include <quack/http.h>
#include <quack/platform.h>
#include <quack/win32_event_processor_iocp.h>
#include <stdio.h>
#include <string.h>

#include <iostream>
#include <string_view>
#include <vector>

/*
TODO:
Unify event processor and chunked data so it doesn't have to be copied.
Track establishing connections so they can timeout.
*/

using namespace quack;

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

  std::optional<u16> PeekU16() {
    u16 result = 0;

    if (buffer.total_size - total_read_size < sizeof(result)) {
      return {};
    }

    Peek(&result, sizeof(result));

    return result;
  }

  std::optional<u32> PeekU32() {
    u32 result = 0;

    if (buffer.total_size - total_read_size < sizeof(result)) {
      return {};
    }

    Peek(&result, sizeof(result));

    return result;
  }

  std::optional<u64> PeekU64() {
    u64 result = 0;

    if (buffer.total_size - total_read_size < sizeof(result)) {
      return {};
    }

    Peek(&result, sizeof(result));

    return result;
  }

  bool Peek(void* out, size_t amount) {
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
  void Consume() {
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
};

enum class SessionState {
  Connecting,
  Upgraded,
};

enum class OpCode {
  Continuation = 0x00,
  Text = 0x01,
  Binary = 0x02,
  Close = 0x08,
  Ping = 0x09,
  Pong = 0x0A,
};

enum FrameHeaderFlag {
  FrameHeaderFlag_Parsed = (1 << 0),
  FrameHeaderFlag_Fin = (1 << 1),
  FrameHeaderFlag_Masked = (1 << 2),
};
using FrameHeaderFlags = u32;

struct FrameHeader {
  u64 payload_size = 0;
  OpCode opcode = OpCode::Continuation;
  FrameHeaderFlags flags = 0;
  u32 mask = 0;
};

struct Session {
  QuackSocket socket = kInvalidSocket;
  ChunkedBuffer buffer;
  SessionState state = SessionState::Connecting;

  std::string header_view;
  http::Header header;

  FrameHeader current_frame_header;

  void FormHeader(size_t size) {
    header_view.resize(size);

    ChunkedBufferReader reader(buffer);

    reader.Peek(&header_view[0], size);
    reader.Consume();
  }

  size_t ParseHeader() const {
    if (state != SessionState::Connecting) return 0;

    BufferChunk* chunk = buffer.chunks;

    constexpr const char* kSearch = "\r\n";
    constexpr size_t kSearchLength = 4;

    size_t end_pos = 0;
    size_t search_index = 0;
    size_t run_length = 0;

    while (chunk) {
      for (size_t i = 0; i < chunk->size; ++i) {
        if (chunk->data[i] == kSearch[search_index & 1]) {
          ++search_index;

          if (++run_length == kSearchLength) {
            // Header ended here
            end_pos += i;

            return end_pos + 1;
          }
        } else {
          search_index = 0;
          run_length = 0;
        }
      }

      end_pos += chunk->size;
      chunk = chunk->next;
    }

    return 0;
  }

  void AppendData(char* data, size_t size) {
    if (!buffer.last_chunk) {
      buffer.chunks = buffer.last_chunk = new BufferChunk;
    }

    // printf("Data: %.*s\n", (u32)size, data);

    size_t remaining_size = size;
    char* write_ptr = data;

    while (remaining_size > 0) {
      BufferChunk* chunk = buffer.last_chunk;

      if (chunk->size >= QUACK_ARRAY_SIZE(chunk->data)) {
        buffer.last_chunk->next = new BufferChunk;

        if (!buffer.last_chunk->next) {
          fprintf(stderr, "Session.AppendData: Failed to allocate BufferChunk.\n");
          return;
        }

        chunk = buffer.last_chunk = buffer.last_chunk->next;
      }

      size_t write_size = QUACK_ARRAY_SIZE(chunk->data) - chunk->size;
      if (write_size > remaining_size) write_size = remaining_size;

      buffer.total_size += write_size;

      memcpy(chunk->data + chunk->size, write_ptr, write_size);
      chunk->size += write_size;
      write_ptr += write_size;

      remaining_size -= write_size;
    }
  }

  bool ProcessData() {
    switch (state) {
      // This state deals with upgrading the connection, so it must parse http headers.
      case SessionState::Connecting: {
        size_t header_size = ParseHeader();

        if (header_size > 0) {
          FormHeader(header_size);
          // printf("Total header: %s", header_view.data());

          auto result = http::Header::Parse(header_view);

          if (!result) {
            fprintf(stderr, "Failed to parse header: %d\n", (s32)result.error());
            return false;
          }

          header = *result;
          http::Request& request = header.request;

          // std::cout << "Request: " << request.method << ", " << request.uri << ", " << request.version << std::endl;

          auto websocket_key = header.GetField("Sec-WebSocket-Key");

          // End connection because it's not valid.
          if (!websocket_key) return false;

          // std::cout << "Websocket key: " << *websocket_key << std::endl;

          Sha1Digest digest;

          constexpr uint8_t kWebsocketGuid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

          SHA1_CTX ctx;

          SHA1_Init(&ctx);
          SHA1_Update(&ctx, (uint8_t*)websocket_key->data(), websocket_key->size());
          SHA1_Update(&ctx, kWebsocketGuid, sizeof(kWebsocketGuid) - 1);
          SHA1_Final(&ctx, digest);

          char key_response[Base64::GetOutputSize(SHA1_DIGEST_SIZE)];

          if (!Base64::Encode(std::string_view((char*)digest, SHA1_DIGEST_SIZE), key_response, sizeof(key_response))) {
            fprintf(stderr, "Failed to Base64 encode websocket key.\n");
            return false;
          }

          char response[1024];
          int response_size = sprintf(response,
                                      "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: "
                                      "Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n",
                                      key_response);

          std::string_view response_view(response, response_size);

          // std::cout << "Sending: " << response_view << std::endl;
          send(this->socket, response, response_size, 0);

          state = SessionState::Upgraded;

          return true;
        }
      } break;
      case SessionState::Upgraded: {
        if (!(current_frame_header.flags & FrameHeaderFlag_Parsed)) {
          if (!ParseFrameHeader()) {
            return true;
          }
        }

        // If we have a fully parsed header, try to consume the entire payload.
        if (buffer.total_size < current_frame_header.payload_size) return true;

        if (current_frame_header.payload_size > 0) {
          // Grab data then unmask
          u8* payload = (u8*)malloc(current_frame_header.payload_size);
          if (!payload) return false;

          ChunkedBufferReader reader(buffer);

          if (!reader.Peek(payload, current_frame_header.payload_size)) {
            free(payload);
            return true;
          }

          reader.Consume();

          u8* mask = (u8*)&current_frame_header.mask;

          for (size_t i = 0; i < current_frame_header.payload_size; ++i) {
            payload[i] ^= mask[i % 4];
          }

          printf("Payload: %.*s\n", (u32)current_frame_header.payload_size, payload);

          free(payload);
        }

        if (current_frame_header.opcode == OpCode::Close) {
          // TODO: Server is supposed to send its own close frame before closing connection.
          return false;
        }

        // Clear parsed flag so we read a new frame header.
        current_frame_header.flags = 0;
      } break;
      default: {
        fprintf(stderr, "Invalid session state. Closing connection.\n");
        return false;
      } break;
    }

    return true;
  }

  bool ParseFrameHeader() {
    // Parse frame header
    ChunkedBufferReader reader(buffer);
    auto frame_header = reader.PeekU16();

    if (!frame_header) return false;

    u8 opcode_value = *frame_header & 0xFF;
    u8 payload_len = *frame_header >> 8;

    bool fin = opcode_value & (1 << 7);
    bool masked = payload_len & (1 << 7);

    payload_len &= 0x7F;
    opcode_value &= 0x0F;

    OpCode opcode = (OpCode)opcode_value;

    u64 total_len = payload_len;

    if (payload_len == 126) {
      auto opt_ext_payload = reader.PeekU16();
      if (!opt_ext_payload) return false;

      total_len = *opt_ext_payload;
    } else if (payload_len == 127) {
      auto opt_ext_payload = reader.PeekU64();
      if (!opt_ext_payload) return false;

      total_len = *opt_ext_payload;
    }

    u32 mask = 0;

    if (masked) {
      auto opt_mask = reader.PeekU32();
      if (!opt_mask) return false;

      mask = *opt_mask;
    }

    current_frame_header.opcode = opcode;
    current_frame_header.payload_size = total_len;
    current_frame_header.flags = FrameHeaderFlag_Parsed;

    if (masked) {
      current_frame_header.flags |= FrameHeaderFlag_Masked;
      current_frame_header.mask = mask;
    }

    if (fin) {
      current_frame_header.flags |= FrameHeaderFlag_Fin;
    }

    // Consume entire frame header.
    reader.Consume();
    return true;
  }
};

static bool OnRecv(ConnectionUserData user, char* data, size_t size) {
  Session* session = (Session*)user;

  if (session->state != SessionState::Connecting) {
    printf("Data: ");
    for (size_t i = 0; i < size; ++i) {
      printf("%02X ", (u8)data[i]);
    }
    printf("\n");
    //printf("Data: %.*s\n", (u32)size, data);
  }
  session->AppendData(data, size);

  return session->ProcessData();
}

static ConnectionUserData OnAccept(ServerUserData user, QuackSocket socket) {
  printf("New user connection %d\n", (s32)socket);

  Session* session = new Session;
  session->socket = socket;

  return session;
}

int main(int argc, char* argv[]) {
  QuackEventProcessorIocp iocp;

  iocp.accept_callback = OnAccept;
  iocp.recv_callback = OnRecv;
  iocp.buffer_size = kBufferSize;

  if (!iocp.Start(8080)) {
    fprintf(stderr, "Failed to start iocp processor.\n");
    return 1;
  }

  while (1) {
    Sleep(1000);
  }

  return 0;
}

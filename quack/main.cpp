#include <assert.h>
#include <quack/buffer.h>
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
  u8 mask[4];
};

struct Session {
  QuackSocket socket = kInvalidSocket;
  ChunkedBuffer buffer;
  SessionState state = SessionState::Connecting;

  std::string header_view;
  http::Header header;

  FrameHeader current_frame_header;

  std::string payload;

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

      if (chunk->offset + chunk->size >= QUACK_ARRAY_SIZE(chunk->data)) {
        buffer.last_chunk->next = new BufferChunk;

        if (!buffer.last_chunk->next) {
          fprintf(stderr, "Session.AppendData: Failed to allocate BufferChunk.\n");
          return;
        }

        chunk = buffer.last_chunk = buffer.last_chunk->next;
      }

      size_t write_size = QUACK_ARRAY_SIZE(chunk->data) - chunk->size - chunk->offset;
      if (write_size > remaining_size) write_size = remaining_size;

      buffer.total_size += write_size;

      memcpy(chunk->data + chunk->offset + chunk->size, write_ptr, write_size);
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
          ChunkedBufferReader reader(buffer);

          size_t frame_offset = payload.size();
          payload.resize(frame_offset + current_frame_header.payload_size);

          char* frame_payload = &payload[frame_offset];

          // Read the frame payload into the end of the full payload buffer.
          // This cannot fail the buffer was checked to have the entire payload size.
          reader.Peek(frame_payload, current_frame_header.payload_size);
          reader.Consume();

          if (current_frame_header.flags & FrameHeaderFlag_Masked) {
            for (size_t i = 0; i < current_frame_header.payload_size; ++i) {
              frame_payload[i] ^= current_frame_header.mask[i % 4];
            }
          }

          if (current_frame_header.flags & FrameHeaderFlag_Fin) {
            std::cout << "Payload: " << payload << std::endl;
            payload.clear();
          }
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

    u16 frame_header;

    if (!reader.Peek(&frame_header, sizeof(frame_header))) return false;

    u8 opcode_value = frame_header & 0xFF;
    u8 payload_len = frame_header >> 8;

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

    if (masked && !reader.Peek(current_frame_header.mask, sizeof(current_frame_header.mask))) {
      return false;
    }

    if (opcode != OpCode::Continuation) {
      current_frame_header.opcode = opcode;
    }
    current_frame_header.payload_size = total_len;
    current_frame_header.flags = FrameHeaderFlag_Parsed;

    if (masked) {
      current_frame_header.flags |= FrameHeaderFlag_Masked;
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

#if 0
  if (session->state != SessionState::Connecting) {
    printf("Data: ");
    for (size_t i = 0; i < size; ++i) {
      printf("%02X ", (u8)data[i]);
    }
    printf("\n");
  }
#endif
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

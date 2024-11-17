#include <assert.h>
#include <quack/buffer.h>
#include <quack/hash.h>
#include <quack/http.h>
#include <quack/platform.h>
#include <quack/win32_event_processor_iocp.h>
#include <stdio.h>
#include <string.h>

#include <iostream>
#include <string>
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
  u8 mask[4] = {};
};

struct Session {
  QuackSocket socket = kInvalidSocket;
  ChunkedBuffer buffer;
  SessionState state = SessionState::Connecting;

  std::string header_view;
  http::Header header;

  FrameHeader current_frame_header;

  std::string payload;

  enum class ProcessResult {
    Pending,
    Consumed,
    Disconnect,
  };

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
        if (chunk->data[chunk->offset + i] == kSearch[search_index & 1]) {
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

  ProcessResult ProcessData() {
    switch (state) {
      // This state deals with upgrading the connection, so it must parse http headers.
      case SessionState::Connecting: {
        size_t header_size = ParseHeader();

        if (header_size > 0) {
          FormHeader(header_size);

          auto result = http::Header::Parse(header_view);

          if (!result) {
            fprintf(stderr, "Failed to parse header: %d\n", (s32)result.error());
            return ProcessResult::Disconnect;
          }

          header = *result;
          http::Request& request = header.request;

          auto websocket_key = header.GetField("Sec-WebSocket-Key");

          // End connection because it's not valid.
          if (!websocket_key) return ProcessResult::Disconnect;

          Sha1::Digest digest;

          constexpr uint8_t kWebsocketGuid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

          Sha1::Context ctx;

          Sha1::Init(&ctx);
          Sha1::Update(&ctx, (uint8_t*)websocket_key->data(), websocket_key->size());
          Sha1::Update(&ctx, kWebsocketGuid, sizeof(kWebsocketGuid) - 1);
          Sha1::Final(&ctx, digest);

          char key_response[Base64::GetOutputSize(Sha1::kDigestSize)];

          if (!Base64::Encode(std::string_view((char*)digest, Sha1::kDigestSize), key_response, sizeof(key_response))) {
            fprintf(stderr, "Failed to Base64 encode websocket key.\n");
            return ProcessResult::Disconnect;
          }

          char response[1024];
          int response_size = sprintf(response,
                                      "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: "
                                      "Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n",
                                      key_response);

          std::string_view response_view(response, response_size);

          send(this->socket, response, response_size, 0);

          state = SessionState::Upgraded;

          return ProcessResult::Pending;
        }
      } break;
      case SessionState::Upgraded: {
        if (!(current_frame_header.flags & FrameHeaderFlag_Parsed)) {
          ProcessResult parse_result = ParseFrameHeader();

          if (parse_result != ProcessResult::Consumed) {
            return parse_result;
          }
        }

        // If we have a fully parsed header, try to consume the entire payload.
        if (buffer.total_size < current_frame_header.payload_size) return ProcessResult::Pending;

        if (current_frame_header.payload_size > 0) {
          ChunkedBufferReader reader(buffer);

          size_t frame_offset = payload.size();
          payload.resize(frame_offset + current_frame_header.payload_size);

          char* frame_payload = &payload[frame_offset];

          // Read the frame payload into the end of the full payload buffer.
          // This cannot fail because the buffer was checked to have the entire payload size.
          reader.Peek(frame_payload, current_frame_header.payload_size);
          reader.Consume();

          if (current_frame_header.flags & FrameHeaderFlag_Masked) {
            for (size_t i = 0; i < current_frame_header.payload_size; ++i) {
              frame_payload[i] ^= current_frame_header.mask[i % 4];
            }
          }
        }

        if (current_frame_header.flags & FrameHeaderFlag_Fin) {
          switch (current_frame_header.opcode) {
            case OpCode::Text:
            case OpCode::Binary: {
              //  Echo back
              SendFrame(current_frame_header.opcode, payload);
            } break;
            case OpCode::Close: {
              // Server is supposed to send a close opcode in response to a close request.
              // Write it out using a BufferWriter so it has the correct endianness.
              constexpr u16 kNormalCloseCode = 1000;

              u16 close_code = 0;
              BufferWriter writer((u8*)&close_code, sizeof(close_code));

              writer.WriteU16(kNormalCloseCode);

              SendFrame(OpCode::Close, std::string_view((char*)&close_code, sizeof(close_code)));

              return ProcessResult::Disconnect;
            } break;
            case OpCode::Ping: {
              SendFrame(OpCode::Pong, payload);
            } break;
            case OpCode::Pong: {
            } break;
            default: {
              fprintf(stderr, "Invalid OpCode received: %d\n", (s32)current_frame_header.opcode);
            } break;
          }

          payload.clear();
        }

        // Clear parsed flag so we read a new frame header.
        current_frame_header.flags = 0;
      } break;
      default: {
        fprintf(stderr, "Invalid session state. Closing connection.\n");
        return ProcessResult::Disconnect;
      } break;
    }

    return ProcessResult::Consumed;
  }

  void SendFrame(OpCode opcode, std::string_view data) {
    constexpr size_t kMaxHeaderSize = 10;

    u8 header_data[kMaxHeaderSize];
    BufferWriter writer(header_data, sizeof(header_data));

    writer.WriteU8((u8)opcode | (1 << 7));

    if (data.size() > 0xFFFF) {
      // Data size exceeds ushort, write as u32
      writer.WriteU8(127);
      writer.WriteU64((u64)data.size());
    } else if (data.size() > 125) {
      // Data size exceeds 7 bits, write as u16
      writer.WriteU8(126);
      writer.WriteU16((u16)data.size());
    } else {
      writer.WriteU8((u8)data.size());
    }

    send(socket, (char*)header_data, (int)writer.GetWrittenSize(), 0);
    // TODO: This won't work for very large payloads because of the truncation.
    // But it doesn't really matter because the entire sending would need to be written differently for large payloads.
    send(socket, data.data(), (int)data.size(), 0);
  }

  // This tries to read the entire frame header from the buffer.
  // If the entire frame header hasn't been received yet, it will return and wait for more data.
  // The buffer will consume the entire frame header once the entire header has been received.
  ProcessResult ParseFrameHeader() {
    ChunkedBufferReader reader(buffer);
    u16 frame_header;

    if (!reader.Peek(&frame_header, sizeof(frame_header))) return ProcessResult::Pending;

    u8 opcode_value = frame_header & 0xFF;
    u8 payload_len = frame_header >> 8;

    bool fin = opcode_value & (1 << 7);
    bool masked = payload_len & (1 << 7);

    payload_len &= 0x7F;
    opcode_value &= 0x0F;

    // These opcodes are reserved, so using them is illegal.
    if (opcode_value > 2 && opcode_value < 8) {
      fprintf(stderr, "Bad opcode: %d\n", (int)opcode_value);
      return ProcessResult::Disconnect;
    }

    OpCode opcode = (OpCode)opcode_value;
    u64 total_len = payload_len;

    // The frame header reserves 126 and 127 payload lengths as indicators of larger sizes that need to be parsed.
    if (payload_len == 126) {
      auto opt_ext_payload = reader.PeekU16();
      if (!opt_ext_payload) return ProcessResult::Pending;

      total_len = *opt_ext_payload;
    } else if (payload_len == 127) {
      auto opt_ext_payload = reader.PeekU64();
      if (!opt_ext_payload) return ProcessResult::Pending;

      total_len = *opt_ext_payload;
    }

    if (masked && !reader.Peek(current_frame_header.mask, sizeof(current_frame_header.mask))) {
      return ProcessResult::Pending;
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

    reader.Consume();

    return ProcessResult::Consumed;
  }
};

static bool OnRecv(ConnectionUserData user, char* data, size_t size) {
  Session* session = (Session*)user;

  session->AppendData(data, size);

  Session::ProcessResult result = Session::ProcessResult::Consumed;

  // Continue processing the buffer until new data is necessary.
  while (result == Session::ProcessResult::Consumed) {
    result = session->ProcessData();
  }

  return result == Session::ProcessResult::Pending;
}

static ConnectionUserData OnAccept(ServerUserData user, QuackSocket socket) {
  Session* session = new Session;

  session->socket = socket;

  return session;
}

static void OnClose(ConnectionUserData user) {
  Session* session = (Session*)user;
  delete session;
}

int main(int argc, char* argv[]) {
  QuackEventProcessorIocp iocp;

  iocp.accept_callback = OnAccept;
  iocp.recv_callback = OnRecv;
  iocp.close_callback = OnClose;
  iocp.buffer_size = kBufferSize;
  iocp.concurrency = 4;

  if (!iocp.Start(8080)) {
    fprintf(stderr, "Failed to start iocp processor.\n");
    return 1;
  }

  while (1) {
    Sleep(1000);
  }

  return 0;
}

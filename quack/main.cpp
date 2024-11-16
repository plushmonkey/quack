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

  size_t size = 0;
  char data[kBufferSize];
};

struct ChunkedBuffer {
  BufferChunk* chunks = nullptr;
  BufferChunk* last_chunk = nullptr;

  size_t total_size = 0;
};

enum class SessionState {
  Connecting,
  Upgraded,
};

struct Session {
  QuackSocket socket = kInvalidSocket;
  ChunkedBuffer buffer;
  SessionState state = SessionState::Connecting;

  std::string header_view;
  http::Header header;

  void FormHeader(size_t size) {
    header_view.resize(size);

    BufferChunk* chunk = buffer.chunks;
    size_t written = 0;

    // Form contiguous buffer for header
    while (chunk && written < size) {
      size_t write_size = size - written;

      if (write_size > chunk->size) write_size = chunk->size;

      memcpy(&header_view[written], chunk->data, write_size);

      written += write_size;

      if (write_size == chunk->size) {
        // discard chunk
        BufferChunk* old = chunk;
        chunk = chunk->next;
        buffer.chunks = chunk;

        if (chunk == nullptr) {
          buffer.last_chunk = nullptr;
        }

        delete old;
      } else {
        // We are on the last chunk now, so we need to move the remaining data to the front and adjust the size.
        memmove(chunk->data, chunk->data + write_size, chunk->size - write_size);
        chunk->size -= write_size;
        assert(written == size);
        break;
      }
    }
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
      } break;
      default: {
        fprintf(stderr, "Invalid session state. Closing connection.\n");
        return false;
      } break;
    }

    return true;
  }
};

static bool OnRecv(ConnectionUserData user, char* data, size_t size) {
  Session* session = (Session*)user;

  if (session->state != SessionState::Connecting) {
    printf("Data: %.*s\n", (u32)size, data);
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

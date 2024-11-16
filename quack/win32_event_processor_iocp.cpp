#include "win32_event_processor_iocp.h"

#include <assert.h>
#include <quack/platform.h>
#include <stdio.h>
#include <stdlib.h>

#include <string_view>

namespace quack {

typedef BOOL(PASCAL FAR* LPFN_ACCEPTEX)(_In_ SOCKET sListenSocket, _In_ SOCKET sAcceptSocket,
                                        _Out_writes_bytes_(dwReceiveDataLength + dwLocalAddressLength +
                                                           dwRemoteAddressLength) PVOID lpOutputBuffer,
                                        _In_ DWORD dwReceiveDataLength, _In_ DWORD dwLocalAddressLength,
                                        _In_ DWORD dwRemoteAddressLength, _Out_ LPDWORD lpdwBytesReceived,
                                        _Inout_ LPOVERLAPPED lpOverlapped);

#define WSAID_ACCEPTEX                               \
  {                                                  \
    0xb5367df1, 0xcbac, 0x11cf, {                    \
      0x95, 0xca, 0x00, 0x80, 0x5f, 0x48, 0xa1, 0x92 \
    }                                                \
  }

typedef VOID(PASCAL FAR* LPFN_GETACCEPTEXSOCKADDRS)(IN PVOID lpOutputBuffer, IN DWORD dwReceiveDataLength,
                                                    IN DWORD dwLocalAddressLength, IN DWORD dwRemoteAddressLength,
                                                    OUT struct sockaddr** LocalSockaddr, OUT LPINT LocalSockaddrLength,
                                                    OUT struct sockaddr** RemoteSockaddr,
                                                    OUT LPINT RemoteSockaddrLength);

#define WSAID_GETACCEPTEXSOCKADDRS                   \
  {                                                  \
    0xb5367df2, 0xcbac, 0x11cf, {                    \
      0x95, 0xca, 0x00, 0x80, 0x5f, 0x48, 0xa1, 0x92 \
    }                                                \
  }

#define SO_UPDATE_ACCEPT_CONTEXT 0x700B

static LPFN_ACCEPTEX quack_acceptex;
static LPFN_GETACCEPTEXSOCKADDRS quack_get_acceptex_sockaddrs;

enum class IoOperation { Accept, Read, Write };

struct QuackAcceptCtx {
  QuackSocket listen_fd;
  QuackSocket client_fd;

  DWORD bytes_recv;
};

struct QuackReadCtx {
  QuackSocket fd;
};

struct QuackIocpContext {
  // Must be first in struct
  WSAOVERLAPPED overlapped;

  struct ThreadContext* owner;

  IoOperation operation;

  union {
    QuackAcceptCtx accept;
    QuackReadCtx read;
  };

  ConnectionUserData user;
  struct QuackIocpContext* next;

  WSABUF wsa_buf_read;
  WSABUF wsa_buf_write;

  char* read_buffer;
  char* write_buffer;
};

struct ThreadContext {
  size_t thread_id;
  HANDLE handle;
  HANDLE iocp;

  QuackIocpContext* free_ctx;

  size_t total_alloc = 0;

  size_t GetFreeCount() {
    auto* ctx = free_ctx;
    size_t count = 0;
    while (ctx) {
      ++count;
      ctx = ctx->next;
    }
    return count;
  }

  inline QuackIocpContext* AllocateIoContext(size_t buffer_size) {
    QuackIocpContext* result = free_ctx;

    if (!result) {
      free_ctx = (QuackIocpContext*)malloc(sizeof(QuackIocpContext));

      if (!free_ctx) return nullptr;

      free_ctx->next = nullptr;
      result = free_ctx;

      ++total_alloc;
      // printf("Alloc new %zu. Total: %zu. In free: %zu\n", thread_id, total_alloc, GetFreeCount());
    } else {
      // printf("Got from free list %zu. Total: %zu. In free: %zu\n", thread_id, total_alloc, GetFreeCount());
    }

    free_ctx = free_ctx->next;

    result->overlapped = {};
    result->operation = IoOperation::Read;

    result->owner = this;

    result->user = nullptr;
    result->next = nullptr;

    result->read_buffer = (char*)malloc(buffer_size);
    result->write_buffer = (char*)malloc(buffer_size);

    result->wsa_buf_read.buf = result->read_buffer;
    result->wsa_buf_read.len = (ULONG)buffer_size;

    result->wsa_buf_write.buf = result->write_buffer;
    result->wsa_buf_write.len = (ULONG)buffer_size;

    return result;
  }

  inline void FreeIoReadContext(QuackIocpContext* ctx) {
    QuackIocpContext* target = free_ctx;

    do {
      target = free_ctx;
      ctx->next = target;
    } while (InterlockedExchangePointer((PVOID*)&free_ctx, ctx) != target);

    // printf("Performing free %zu. Total: %zu. In free: %zu\n", thread_id, total_alloc, GetFreeCount());
  }
};

DWORD WINAPI QuackIocpThread(void* thread_data);

struct Win32IocpServer {
  QuackIocpContext listen_ctx = {};
  ThreadContext* threads = nullptr;
  HANDLE io_handle = INVALID_HANDLE_VALUE;

  bool initialize(DWORD concurrency) {
    printf("Creating io completion port\n");

    io_handle = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, (ULONG_PTR)0, concurrency);

    if (io_handle == NULL || io_handle == INVALID_HANDLE_VALUE) return false;

    printf("Creating thread pool\n");

    threads = new ThreadContext[concurrency * 2];

    // Create a pool of threads to handle io events. Double the concurrency value so some threads will be waiting to
    // dequeue while others are processing.
    for (DWORD i = 0; i < concurrency * 2; ++i) {
      threads[i].thread_id = i;
      threads[i].iocp = io_handle;
      threads[i].free_ctx = 0;
      _ReadWriteBarrier();
      threads[i].handle = CreateThread(NULL, 0, QuackIocpThread, threads + i, 0, 0);
    }

    SOCKET fd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (fd == kInvalidSocket) {
      fprintf(stderr, "Failed to create socket for getting extension functions.\n");
      CloseHandle(io_handle);
      io_handle = INVALID_HANDLE_VALUE;
      return false;
    }

    DWORD bytes;
    GUID acceptex_guid = WSAID_ACCEPTEX;

    if (WSAIoctl(fd, SIO_GET_EXTENSION_FUNCTION_POINTER, &acceptex_guid, sizeof(GUID), &quack_acceptex,
                 sizeof(LPFN_ACCEPTEX), &bytes, NULL, NULL) == -1) {
      fprintf(stderr, "Failed to get AcceptEx\n");
      closesocket(fd);
      CloseHandle(io_handle);
      io_handle = INVALID_HANDLE_VALUE;
      return false;
    }

    GUID getacceptexsockaddrs_guid = WSAID_GETACCEPTEXSOCKADDRS;

    if (WSAIoctl(fd, SIO_GET_EXTENSION_FUNCTION_POINTER, &getacceptexsockaddrs_guid, sizeof(GUID),
                 &quack_get_acceptex_sockaddrs, sizeof(LPFN_GETACCEPTEXSOCKADDRS), &bytes, NULL, NULL) == -1) {
      fprintf(stderr, "Failed to get GetAcceptExSockaddrs\n");
      closesocket(fd);
      CloseHandle(io_handle);
      io_handle = INVALID_HANDLE_VALUE;
      return false;
    }

    closesocket(fd);

    return true;
  }
};

static QuackSocket CreateListener(u16 port) {
  addrinfo hints = {}, *res = nullptr;

  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;

  char port_str[6];
  sprintf(port_str, "%hd", port);
  if (getaddrinfo(nullptr, port_str, &hints, &res) != 0) {
    PrintNetworkError("getaddrinfo: %s\n");
    return kInvalidSocket;
  }

  QuackSocket sockfd = WSASocketW(res->ai_family, res->ai_socktype, res->ai_protocol, nullptr, 0, WSA_FLAG_OVERLAPPED);
  if (sockfd < 0) {
    PrintNetworkError("socket: %s\n");
    return kInvalidSocket;
  }

  if (bind(sockfd, res->ai_addr, (int)res->ai_addrlen) < 0) {
    PrintNetworkError("bind: %s\n");
    return kInvalidSocket;
  }

  freeaddrinfo(res);

  if (listen(sockfd, 10) != 0) {
    PrintNetworkError("listen: %s\n");
    return kInvalidSocket;
  }

  return sockfd;
}

bool QuackEventProcessorIocp::Start(u16 port) {
  Win32IocpServer* server = new Win32IocpServer;
  if (!server) return false;

  this->internal = server;

  printf("Starting iocp\n");

  if (!server->initialize(concurrency)) {
    fprintf(stderr, "Failed to initialize iocp.\n");
    return false;
  }

  QuackSocket listener = CreateListener(port);
  if (listener == kInvalidSocket) {
    return false;
  }

  server->listen_ctx.operation = IoOperation::Accept;
  server->listen_ctx.accept.listen_fd = listener;
  server->listen_ctx.accept.client_fd = WSASocketW(AF_INET, SOCK_STREAM, 0, nullptr, 0, WSA_FLAG_OVERLAPPED);

  if (server->listen_ctx.accept.client_fd < 0) {
    fprintf(stderr, "Failed to create accept socket.\n");
    return false;
  }

  server->listen_ctx.read_buffer = (char*)malloc(buffer_size);
  server->listen_ctx.write_buffer = (char*)malloc(buffer_size);

  server->listen_ctx.wsa_buf_read.buf = server->listen_ctx.read_buffer;
  server->listen_ctx.wsa_buf_read.len = (ULONG)buffer_size;

  server->listen_ctx.wsa_buf_write.buf = server->listen_ctx.write_buffer;
  server->listen_ctx.wsa_buf_write.len = (ULONG)buffer_size;

  if (!server->listen_ctx.wsa_buf_read.buf || !server->listen_ctx.wsa_buf_write.buf) {
    fprintf(stderr, "Failed to allocate accept buffers.\n");
    return false;
  }

  CreateIoCompletionPort((HANDLE)listener, server->io_handle, (ULONG_PTR)this, 0);

  BOOL accepted = quack_acceptex(server->listen_ctx.accept.listen_fd, server->listen_ctx.accept.client_fd,
                                 server->listen_ctx.wsa_buf_read.buf, 0, sizeof(struct sockaddr_in) + 16,
                                 sizeof(struct sockaddr_in) + 16, &server->listen_ctx.accept.bytes_recv,
                                 &server->listen_ctx.overlapped);

  if (!accepted && WSAGetLastError() != ERROR_IO_PENDING) {
    printf("Failed to accept: %d\n", WSAGetLastError());
    return false;
  }

  printf("Listening for connections\n");

  this->running = true;
  return true;
}

DWORD WINAPI QuackIocpThread(void* thread_data) {
  ThreadContext* thread_ctx = (ThreadContext*)thread_data;

  _ReadWriteBarrier();

  while (1) {
    LPOVERLAPPED overlapped;
    DWORD io_size;

    QuackEventProcessorIocp* processor = nullptr;

    BOOL status = GetQueuedCompletionStatus(thread_ctx->iocp, &io_size, (PULONG_PTR)&processor, &overlapped, INFINITE);

    QuackIocpContext* io = (QuackIocpContext*)overlapped;

    if (!status) {
      fprintf(stderr, "Status was false: %d\n", GetLastError());

      if (io->operation == IoOperation::Accept) {
        close(io->accept.client_fd);

        io->accept.client_fd = WSASocketW(AF_INET, SOCK_STREAM, 0, nullptr, 0, WSA_FLAG_OVERLAPPED);

        quack_acceptex(io->accept.listen_fd, io->accept.client_fd, io->wsa_buf_read.buf, 0,
                       sizeof(struct sockaddr_in) + 16, sizeof(struct sockaddr_in) + 16, &io->accept.bytes_recv,
                       &io->overlapped);
      }
      continue;
    }

    Win32IocpServer* server = (Win32IocpServer*)processor->internal;
    // printf("Processing io (thread: %zu)\n", thread_ctx->thread_id);

    switch (io->operation) {
      case IoOperation::Accept: {
        bool perform_recv = true;

        // printf("Processing accept (thread: %zu)\n", thread_ctx->thread_id);
        // fflush(stdout);

        // Process new accept
        int result = setsockopt(io->accept.client_fd, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT,
                                (const char*)&io->accept.listen_fd, sizeof(io->accept.listen_fd));

        if (result == SOCKET_ERROR) {
          fprintf(stderr, "Failed to setsockopt.\n");
          continue;
        }

        // printf("Accepting %zd\n", io->accept.client_fd);

        struct sockaddr* local_addr = NULL;
        struct sockaddr* remote_addr = NULL;
        int local_bytes = 0;
        int remote_bytes = 0;

        quack_get_acceptex_sockaddrs(io->wsa_buf_read.buf, 0, sizeof(struct sockaddr_in) + 16,
                                     sizeof(struct sockaddr_in) + 16, &local_addr, &local_bytes, &remote_addr,
                                     &remote_bytes);

        ConnectionUserData client_user_data = nullptr;

        if (processor->accept_callback) {
          client_user_data = processor->accept_callback(processor->server_user_data, io->accept.client_fd);
        }

        if (io_size > 0 && processor->recv_callback) {
          perform_recv = processor->recv_callback(io->user, io->wsa_buf_read.buf, io_size);
        }

        if (perform_recv) {
          // Begin reading data on the new client.
          DWORD flags = 0;

          QuackIocpContext* client_ctx = thread_ctx->AllocateIoContext(processor->buffer_size);

          client_ctx->read.fd = io->accept.client_fd;
          client_ctx->user = client_user_data;

          // Add the new client to the io completion port
          if (CreateIoCompletionPort((HANDLE)io->accept.client_fd, thread_ctx->iocp, (ULONG_PTR)processor, 0) == NULL) {
            fprintf(stderr, "Failed to add accepted socket to io port\n");
          }

          // printf("Kicking off wsarecv for %d from accept\n", (int)io->accept.client_fd);
          // fflush(stdout);

          int recv_result =
              WSARecv(client_ctx->read.fd, &client_ctx->wsa_buf_read, 1, NULL, &flags, &client_ctx->overlapped, NULL);
          if (recv_result != 0 && WSAGetLastError() != ERROR_IO_PENDING) {
            PrintNetworkError("WSARecv (accept): %s\n");
          }
        } else {
          // printf("Closing %d from initial recv\n", (int)io->accept.client_fd);
          // fflush(stdout);
          close(io->accept.client_fd);
        }

        io->accept.client_fd = WSASocketW(AF_INET, SOCK_STREAM, 0, nullptr, 0, WSA_FLAG_OVERLAPPED);

        // printf("Beginning new accept (%d)\n", (int)io->accept.client_fd);
        // fflush(stdout);
        bool accept_result = quack_acceptex(io->accept.listen_fd, io->accept.client_fd, io->wsa_buf_read.buf, 0,
                                            sizeof(struct sockaddr_in) + 16, sizeof(struct sockaddr_in) + 16,
                                            &io->accept.bytes_recv, &io->overlapped);

        if (!accept_result) {
          int last_err = WSAGetLastError();

          if (last_err != ERROR_IO_PENDING) {
            printf("AcceptEx err: %d\n", last_err);
          }
        } else {
          printf("acceptex immediate return\n");
        }
      } break;
      case IoOperation::Read: {
        if (io_size > 0) {
          DWORD flags = 0;
          DWORD bytes_recv = 0;
          bool recv_more = false;

          // printf("IoOperation::Read\n");

          if (WSAGetOverlappedResult(io->read.fd, &io->overlapped, &bytes_recv, FALSE, &flags)) {
            if (processor->recv_callback) {
              recv_more = processor->recv_callback(io->user, io->wsa_buf_read.buf, bytes_recv);
            }
          } else {
            PrintNetworkError("WSAGetOverlappedResult: %s\n");
          }

          if (recv_more) {
            int recv_result = WSARecv(io->read.fd, &io->wsa_buf_read, 1, NULL, &flags, &io->overlapped, NULL);
            if (recv_result != 0 && WSAGetLastError() != ERROR_IO_PENDING) {
              PrintNetworkError("WSARecv (read): %s\n");
            }
          } else {
            fprintf(stderr, "----------- Connection force closed on socket %u.\n\n", (unsigned int)io->read.fd);
            if (processor->close_callback) {
              processor->close_callback(io->user);
            }
            close(io->read.fd);
            io->owner->FreeIoReadContext(io);
          }
        } else {
          QuackSocket fd = io->read.fd;

          if (processor->close_callback) {
            processor->close_callback(io->user);
          }

          fprintf(stderr, "--------- Connection closed on socket %u.\n\n", (unsigned int)fd);
          close(fd);

          io->owner->FreeIoReadContext(io);
        }
      } break;
      default: {
      } break;
    }
  }
}

#if 0
static inline quack_socket GetSocket(quack_iocp_context* ctx) {
  quack_socket fd = kInvalidSocket;

  switch (ctx->operation) {
    case IoOperation::Accept: {
      fd = ctx->accept.client_fd;
    } break;
    case IoOperation::Read: {
      fd = ctx->read.fd;
    } break;
    default: {
    }
  }

  return fd;
}


static std::string_view CreateResponse() {
  const char* status_code = "200 OK";
  const char* response = "<h1>gggggg</h1>";

  int content_length = (int)strlen(response);
  char* output_buf = (char*)malloc(2048);

  if (!output_buf) {
    fprintf(stderr, "Failed to allocate response.\n");
    exit(1);
  }

  int n = snprintf(output_buf, 2048,
    "HTTP/1.1 %s\r\nAccess-Control-Allow-Origin: "
    "*\r\nConnection: Keep-Alive\r\nContent-Type: "
    "%s\r\nContent-Length: %d\r\n\n%s",
    status_code, "text/html", content_length, response);

  return std::string_view(output_buf, n);
}

// TLS
inline static bool ProcessRecvData(thread_ctx*, quack_iocp_context* ctx, DWORD size) {
  u8* data = (u8*)ctx->wsa_buf_read.buf;
  std::string_view view((char*)data, size);

  static std::string_view response = CreateResponse();

  enum class HandshakeType {
    ClientHello = 1,
    ServerHello = 2,
    NewSessionTicket = 4,
    EndOfEarlyData = 5,
    EncryptedExtension = 8,
    Certificate = 11,
    CertificateRequest = 13,
    CertificateVerify = 15,
    Finished = 20,
    KeyUpdate = 24,
    MessageHash = 254,
  };

  enum class ContentType : u8 {
    Invalid = 0,
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
  };
#pragma pack(push, 1)

  struct RecordPacket {
    ContentType type;
    u16 legacy_record_version;
    u16 length;
    const u8* data;

    static RecordPacket From(const u8* data) {
      RecordPacket result = *(RecordPacket*)data;

      result.length = ((result.length & 0xFF) << 8) | (result.length >> 8);
      result.data = data + sizeof(type) + sizeof(legacy_record_version) + sizeof(length);
      return result;
    }

  private:
    RecordPacket() = default;
  };

  struct HandshakePacket {
    u32 type : 8;
    u32 length : 24;
    const u8* data;

    static HandshakePacket From(const u8* data) {
      HandshakePacket result = {};

      result.type = *data;
      result.length = (data[1] << 16) | (data[2] << 8) | (data[3]);
      result.data = data + sizeof(u32);

      return result;
    }

  private:
    HandshakePacket() = default;
  };

  struct ClientHello {
    u16 version;
    u8 random[32];
    u8 legacy_session_id[32];
    u16 cipher_suite_size;
    const u8* cipher_suites_data;

    static ClientHello From(const u8* data, size_t size) {
      ClientHello result = {};

      result.version = *(u16*)data;
      memcpy(result.random, data + 1, 32);
      data += 34;

      u8 session_size = *data;
      if (session_size > 32) return result;

      if (session_size > 0) {
        memcpy(result.legacy_session_id, data + 1, session_size);
      }

      data += session_size + 1;
      result.cipher_suite_size = *(u16*)data;
      result.cipher_suite_size = ((result.cipher_suite_size & 0xFF) << 8) | (result.cipher_suite_size >> 8);
      result.cipher_suites_data = data + 2;

      return result;
    }

  private:
    ClientHello() = default;
  };
#pragma pack(pop)

  if (size < 4) {
    fprintf(stderr, "Got tls record packet without header.\n");
    return false;
  }

  RecordPacket record_pkt = RecordPacket::From(data);

  switch (record_pkt.type) {
    case ContentType::Handshake: {
      if (record_pkt.length < 4) {
        fprintf(stderr, "Got tls handshake data without header.\n");
        return false;
      }

      HandshakePacket handshake_pkt = HandshakePacket::From(record_pkt.data);

      HandshakeType type = (HandshakeType)handshake_pkt.type;
      switch (type) {
        case HandshakeType::ClientHello: {
          ClientHello client_hello = ClientHello::From(handshake_pkt.data, handshake_pkt.length);
          size_t suite_count = client_hello.cipher_suite_size / 2;

          // TLS ciphersuite registrations: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml

          if (suite_count == 0) {
            fprintf(stderr, "Client doesn't support any cipher suites.\n");
            return false;
          }

          bool has_TLS_AES_256_GCM_SHA384 = false;

          for (size_t i = 0; i < suite_count; ++i) {
            u16 identifier = *(u16*)(client_hello.cipher_suites_data + i * 2);

            printf("id: %02x, %02x\n", identifier & 0xFF, identifier >> 8);
            if (identifier == 0x0113) {
              has_TLS_AES_256_GCM_SHA384 = true;
              // break;
            }
          }

          if (!has_TLS_AES_256_GCM_SHA384) {
            fprintf(stderr, "Client doesn't support TLS_AES_256_GCM_SHA384\n");
            return false;
          }

          // protocol, key exchange, authentication, session, session key size, type of encryption, hash, hash digest
          // size 0xC0,0x2C	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
          int a = 0;
        } break;
        default: {
          fprintf(stderr, "Got tls handshake type: %d\n", (s32)type);
          return false;
        } break;
      }
    } break;
    case ContentType::ApplicationData: {
    } break;
    default: {
      fprintf(stderr, "Got tls record packet type: %d\n", (s32)record_pkt.type);
      return false;
    } break;
  }

  // printf("Recv: %.*s\n", size, data);

  quack_socket fd = GetSocket(ctx);

  if (view.starts_with("GET ")) {
    send(fd, response.data(), (int)response.size(), 0);

    return false;
  }

  return true;
}
#endif

}  // namespace quack

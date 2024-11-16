#pragma once

#include <quack/platform.h>
#include <quack/types.h>

namespace quack {

typedef void* ConnectionUserData;
typedef void* ServerUserData;

// Return true to continue receiving data, false to close connection.
// TODO: Server could pass off ownership of the buffer so it doesn't have to copy memory. It can grab a new buffer from
// thread-local storage.
typedef bool (*QuackRecvCallback)(ConnectionUserData user, char* data, size_t size);
typedef ConnectionUserData (*QuackAcceptCallback)(ServerUserData user, QuackSocket socket);
typedef void (*QuackCloseCallback)(ConnectionUserData user);

struct QuackEventProcessorIocp {
  QuackRecvCallback recv_callback = nullptr;
  QuackAcceptCallback accept_callback = nullptr;
  QuackCloseCallback close_callback = nullptr;

  ServerUserData server_user_data = nullptr;

  void* internal = nullptr;

  size_t buffer_size = 1024;
  u32 concurrency = 4;
  bool running = false;

  bool Start(u16 port);
};

}  // namespace quack

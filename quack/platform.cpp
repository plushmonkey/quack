#include "platform.h"

#include <stdio.h>
#include <stdlib.h>

#ifdef _WIN32

#pragma comment(lib, "ws2_32.lib")

namespace quack {

int PrintNetworkError(const char* format) {
  char* buffer = nullptr;

  int last_error = WSAGetLastError();
  FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr,
                 last_error, 0, (LPSTR)&buffer, 0, nullptr);

  fprintf(stderr, "[%d] ", last_error);
  fprintf(stderr, format, buffer);

  return last_error;
}

struct NetworkInitializer {
  NetworkInitializer() {
    WSADATA wsa;

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
      PrintNetworkError("WSAStartup: %s\n");
      exit(1);
    }
  }
};

NetworkInitializer _net_init;

}  // namespace quack

#else

namespace quack {

static inline int PrintNetworkError(const char* format) {
  int e = errno;
  fprintf(stderr, format, strerror(e));
  return e;
}

}  // namespace quack

#endif

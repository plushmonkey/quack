#include "platform.h"

#include <stdio.h>
#include <stdlib.h>

#ifdef _WIN32

#pragma comment(lib, "ws2_32.lib")

namespace quack {

void PrintNetworkError(const char* format) {
  char* buffer = nullptr;

  FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr,
                 WSAGetLastError(), 0, (LPSTR)&buffer, 0, nullptr);

  fprintf(stderr, format, buffer);
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

static inline void PrintNetworkError(const char* format) {
  fprintf(stderr, format, strerror(errno));
}

}  // namespace quack

#endif

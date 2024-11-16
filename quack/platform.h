#pragma once

#include <quack/types.h>

#ifdef _WIN32

#include <WS2tcpip.h>
#include <WinSock2.h>

#define close closesocket

#include <Windows.h>

namespace quack {

using QuackSocket = SOCKET;

}  // namespace quack

#else

namespace quack {

using QuackSocket = int;

}  // namespace quack

#endif

namespace quack {

constexpr QuackSocket kInvalidSocket = ~0;

void PrintNetworkError(const char* format);

}  // namespace quack

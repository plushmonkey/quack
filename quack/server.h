#pragma once

#include <quack/win32_event_processor_iocp.h>

#include <string_view>

namespace quack {

struct Server {
  Server();

  // This spins up threads that begin processing data.
  bool Start(int concurrency, int buffer_size, u16 port) {
    processor.concurrency = concurrency;
    processor.buffer_size = buffer_size;

    return processor.Start(port);
  }

  void Stop() { processor.Stop(); }

  void Send(QuackSocket socket, std::string_view data);

  // Return true to keep the connection, false to force it to be closed.
  virtual bool OnMessage(quack::QuackSocket socket, std::string_view data) { return true; }
  // Return true to keep the connection, false to force it to be closed.
  virtual bool OnOpen(quack::QuackSocket socket) { return true; }
  virtual void OnClose(quack::QuackSocket socket) {}

  QuackEventProcessorIocp processor;
};

}  // namespace quack

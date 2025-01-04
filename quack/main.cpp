#include <quack/server.h>

struct EchoServer : public quack::Server {
  // Return true to keep the connection, false to force it to be closed.
  virtual bool OnMessage(quack::QuackSocket socket, std::string_view data) {
    Send(socket, data);
    return true;
  }

  // Return true to keep the connection, false to force it to be closed.
  virtual bool OnOpen(quack::QuackSocket socket) { return true; }

  virtual void OnClose(quack::QuackSocket socket) {}
};

int main(int argc, char* argv[]) {
  EchoServer server;

  if (!server.Start(4, 1024, 8080)) {
    fprintf(stderr, "Failed to start quack server.\n");
    return 1;
  }

  while (1) {
    Sleep(1000);
  }

  server.Stop();

  return 0;
}

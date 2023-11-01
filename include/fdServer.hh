#include <iostream>
#include <stdio.h>

extern "C"
{
#include "fdcore-internal.h"
#include "fdproto-internal.h"
}

using namespace std;

class FdServer
{

private:
  struct cnxctx *listener, *server;
  uint8_t *cer_buf;
  size_t cer_sz;
  uint8_t *rcv_buf;
  size_t rcv_sz;
  struct msg *msg = NULL;
  int checkMsg(struct msg **cer, unsigned char **buffer, size_t buflen);
  struct msg *initializeCEA();
  void print(struct msg **msg);
  struct avp *initializeAVP(const void *what, uint8_t *data);

public:
  FdServer();
  void
  startServer(uint16_t port,
              int family); // Start the server using the given port and family
};
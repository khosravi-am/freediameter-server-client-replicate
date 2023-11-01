#include <arpa/inet.h>
#include <iostream>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>

extern "C"
{
#include <fdcore-internal.h>
#include <fdproto-internal.h>
}

using namespace std;

class FdClient
{

private:
  struct cnxctx *listener, *client;
  sSA *socka = NULL;
  uint8_t *cer_buf;
  size_t cer_sz;
  uint8_t *rcv_buf;
  struct msg *msg = NULL;
  size_t rcv_sz;
  int checkMsg(struct msg **cer, unsigned char **buffer, size_t buflen);
  struct msg *initializeCER();
  void print(struct msg *msg);
  struct avp *initializeAVP(const void *what, uint8_t *data);

public:
  FdClient(uint16_t port, int family);
  void startClient();
};
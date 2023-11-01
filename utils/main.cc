#include "fdServer.hh"

struct student* emp = NULL;
int main(int argc, char const* argv[]) {

    FdServer s;

    s.startServer(3868, 2);
}

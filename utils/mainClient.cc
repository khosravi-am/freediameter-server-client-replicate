#include "fdClient.hh"

int main(int argc, char const* argv[]) {
    FdClient cli(3868, 2);
    cli.startClient();
}



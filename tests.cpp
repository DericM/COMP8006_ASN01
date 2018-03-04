#include "tests.h"
#include "settings.h"
#include <string>

using namespace std;

Tests::Tests()
{

}


void Firewall::iptables(string rule){
    system(string(SUDO + "iptables " + rule).c_str());
}

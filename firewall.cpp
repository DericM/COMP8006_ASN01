#include "firewall.h"
#include "settings.h"
#include "constants.h"
#include "helpers.h"
#include <string>

using namespace std;

Firewall::Firewall()
{

}

string Firewall::getActiveRules(){
    return Helpers::execForResult(string("-L"));
}


void Firewall::clearAllNetFilterRules(){
    //Reset Default Policies
    iptables(string("-P INPUT ACCEPT"));
    iptables(string("-P FORWARD ACCEPT"));
    iptables(string("-P OUTPUT ACCEPT"));
    iptables(string("-t nat -P PREROUTING ACCEPT"));
    iptables(string("-t nat -P POSTROUTING ACCEPT"));
    iptables(string("-t nat -P OUTPUT ACCEPT"));
    iptables(string("-t mangle -P PREROUTING ACCEPT"));
    iptables(string("-t mangle -P OUTPUT ACCEPT"));

    //Flush all rules
    iptables(string("-F"));
    iptables(string("-t nat -F"));
    iptables(string("-t mangle -F"));

    //Erase all non-default chains
    iptables(string("-X"));
    iptables(string("-t nat -X"));
    iptables(string("-t mangle -X"));
}


void Firewall::setNetFilterRules(){
    //Load modules
    iptables(string("/sbin/modprobe ip_tables"));
    iptables(string("/sbin/modprobe ip_conntrack"));

    //DEFAULT CHAIN POLICIES
    iptables(string("-P INPUT DROP"));
    iptables(string("-P OUTPUT DROP"));
    iptables(string("-P FORWARD DROP"));

    //CREATE CUSTOM CHAINS
    iptables(string("-N " + IN_ACCT));
    iptables(string("-N " + OUT_ACCT));

    setInputChain();
    setForwardChain();
    setOutputChain();
    setInboundAccountingChain();
    setOutboundAccountingChain();
}


void Firewall::setInputChain(){
    //Allow all on localhost interface
    iptables(string("-A INPUT -p ALL -i " + LO_IFACE + " -j ACCEPT"));

    //Drop inbound to and from reserved port 0
    iptables(string("-A INPUT -j DROP -p tcp --sport 0"));
    iptables(string("-A INPUT -j DROP -p udp --sport 0"));
    iptables(string("-A INPUT -j DROP -p tcp --dport 0"));
    iptables(string("-A INPUT -j DROP -p udp --dport 0"));

    //Drop bad packets
    iptables(string("-A INPUT -j DROP -p ALL -m state --state INVALID"));
    iptables(string("-A INPUT -j DROP -p tcp ! --syn -m state --state NEW"));
    iptables(string("-A INPUT -j DROP -p tcp --tcp-flags ALL NONE"));
    iptables(string("-A INPUT -j DROP -p tcp --tcp-flags ALL ALL"));
    iptables(string("-A INPUT -j DROP -p tcp --tcp-flags ALL FIN,URG,PSH"));
    iptables(string("-A INPUT -j DROP -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG"));
    iptables(string("-A INPUT -j DROP -p tcp --tcp-flags SYN,RST SYN,RST"));
    iptables(string("-A INPUT -j DROP -p tcp --tcp-flags SYN,FIN SYN,FIN"));

    //Drop HTTP source port 0-1024
    iptables(string("-A INPUT -j DROP -p TCP -s 0/0 --dport 80 --sport 0:1024"));

    //DHCP
    iptables(string("-A INPUT -j ACCEPT -p UDP -s 0/0 --sport 67 --dport 68"));

    //Drop broadcasts that get this far
    iptables(string("-A INPUT -j DROP -m pkttype --pkt-type broadcast"));

    //Route the remainder to the accounting rules
    iptables(string("-A INPUT -j " + IN_ACCT + " -p TCP -i " + INET_IFACE));

    //Allow established connections
    iptables(string("-A INPUT -j ACCEPT -p ALL -i " + INET_IFACE + " -m state --state ESTABLISHED,RELATED"));
}


void Firewall::setForwardChain(){
    for(auto &n: OPENPORTS) {
        //Inbound accounting
        iptables(string("-A FORWARD -i " + INET_IFACE + " -m tcp -p TCP --dport " + to_string(n) + " -j " + IN_ACCT));
        iptables(string("-A FORWARD -i " + INET_IFACE + " -m tcp -p TCP --sport " + to_string(n) + " -j " + IN_ACCT));

        //Outbound accounting
        iptables(string("-A FORWARD -s 0/0 -m tcp -p TCP --dport " + to_string(n) + " -j " + OUT_ACCT));
        iptables(string("-A FORWARD -s 0/0 -m tcp -p TCP --sport " + to_string(n) + " -j " + OUT_ACCT));
    }
}


void Firewall::setOutputChain(){
    //Localhost
    iptables(string("-A OUTPUT -j ACCEPT -p ALL -s " + LO_IP));
    iptables(string("-A OUTPUT -j ACCEPT -p ALL -o " + LO_IFACE));

    //DHCP
    iptables(string("-A OUTPUT -j ACCEPT -p UDP --dport 68 -m state --state NEW"));

    //DNS
    iptables(string("-A OUTPUT -j ACCEPT -p TCP --dport 53 -m state --state NEW"));
    iptables(string("-A OUTPUT -j ACCEPT -p UDP --dport 53 -m state --state NEW"));

    //Route the remainder to the accounting rules
    //iptables(string("-A OUTPUT -p TCP -s 0/0 -j " + OUT_ACCT));
}


void Firewall::setInboundAccountingChain(){
    for(auto &n: OPENPORTS) {
        iptables(string("-A " + IN_ACCT + " -p TCP -s 0/0 --dport " + to_string(n) + " -j ACCEPT"));
    }
}


void Firewall::setOutboundAccountingChain(){
    for(auto &n: OPENPORTS) {
        iptables(string("-A " + OUT_ACCT + " -p TCP --sport " + to_string(n) + " -j ACCEPT"));
        iptables(string("-A " + OUT_ACCT + " -p TCP --dport " + to_string(n) + " -j ACCEPT"));
    }
}


void Firewall::iptables(string rule){
    system(string(SUDO + "iptables " + rule).c_str());
}


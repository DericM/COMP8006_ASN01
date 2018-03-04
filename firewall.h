#ifndef FIREWALL_H
#define FIREWALL_H

#include <list>
#include <array>

class Firewall
{
public:
    Firewall();

    static std::string getActiveRules();
    static void clearAllNetFilterRules();
    static void setNetFilterRules();



private:

    static void setInputChain();
    static void setForwardChain();
    static void setOutputChain();
    static void setInboundAccountingChain();
    static void setOutboundAccountingChain();

    static void iptables(std::string rule);




    //settings
    static const std::string ROOT_PASS;
    static const std::string SUDO;

    static const std::string INET_IFACE;
    static const std::string LO_IFACE;
    static const std::string LO_IP;

    static std::list<int> OPENPORTS;


    //constants
    static const std::string IN_ACCT;
    static const std::string OUT_ACCT;

};

#endif // FIREWALL_H

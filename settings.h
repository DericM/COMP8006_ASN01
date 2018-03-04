#ifndef SETTINGS_H
#define SETTINGS_H
#include "firewall.h"
#include <string>
#include <list>

const std::string Firewall::ROOT_PASS = "daboom37";
const std::string Firewall::SUDO = "echo " + Firewall::ROOT_PASS + " | sudo -S ";

const std::string Firewall::INET_IFACE = "enp3s7";
const std::string Firewall::LO_IFACE = "lo";
const std::string Firewall::LO_IP = "127.0.0.1";



std::list<int> Firewall::OPENPORTS = {22, 80};





#endif // SETTINGS_H

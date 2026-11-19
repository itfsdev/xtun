#include "killswitch_windows.h"
#include "net/wfp.h"
#include "util/config.h"
#include "util/killswitch_env.h"
#include "util/os.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <windows.h>

#include <iphlpapi.h>
#include <netioapi.h>

#include <algorithm>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace libxtun::test
{
    namespace
    {
        std::vector<wfp::FilterInfo> installedFilters()
        {
            auto engine = wfp::WfpEngine::open(makeWfpConfig(false));
            if (!engine) {
                return {};
            }

            auto filters = engine.value()->getInstalledFilters();
            return filters ? std::move(filters).value() : std::vector<wfp::FilterInfo> {};
        }

        std::optional<NET_IFINDEX> ifindexFromAddr(const char *address)
        {
            in_addr wanted {};
            PMIB_UNICASTIPADDRESS_TABLE table = nullptr;
            if (::inet_pton(AF_INET, address, &wanted) != 1
                || ::GetUnicastIpAddressTable(AF_INET, &table) != NO_ERROR) {
                return std::nullopt;
            }

            std::optional<NET_IFINDEX> found;
            for (ULONG entry = 0; entry < table->NumEntries; ++entry) {
                if (table->Table[entry].Address.Ipv4.sin_addr.s_addr == wanted.s_addr) {
                    found = table->Table[entry].InterfaceIndex;
                    break;
                }
            }
            ::FreeMibTable(table);
            return found;
        }

        void cleanup()
        {
            // HARD filters stay after the tunnel is freed. With excluded apps they are in the driver's sublayer,
            // so clean both the regular (false) and the driver's (true) sublayer.
            for (const bool splitTunnel : { false, true }) {
                auto engine = wfp::WfpEngine::open(makeWfpConfig(true, splitTunnel));
                if (!engine) {
                    ADD_FAILURE() << "could not open a WFP session to clean up the killswitch";
                    return;
                }
                if (const libxtun_error rc = engine.value()->cleanup(); rc != LIBXTUN_OK) {
                    ADD_FAILURE() << "could not remove the killswitch's WFP objects: " << rc;
                }
            }
        }
    }

    KillswitchEnv::KillswitchEnv()
    {
        if (!privileged()) {
            m_skipReason = "installing WFP filters requires Administrator";
            return;
        }

        const std::optional<unsigned long> loopback = bestInterface(LOOPBACK_V4);
        if (!loopback) {
            m_skipReason = "no interface to exempt from the killswitch";
            return;
        }

        m_ifIndex = static_cast<int>(*loopback);
        m_ifName = "xtun";
        cleanup();
    }

    KillswitchEnv::~KillswitchEnv()
    {
        if (m_ifIndex != 0) {
            cleanup();
        }
    }

    int KillswitchEnv::ruleCount() const
    {
        return static_cast<int>(installedFilters().size());
    }

    bool KillswitchEnv::removeTunnelRoutes(const std::vector<std::string> &routes) const
    {
        const std::optional<NET_IFINDEX> tunnel = ifindexFromAddr(DEFAULT_IFADDR);
        if (!tunnel) {
            return false;
        }

        const std::string index = std::to_string(*tunnel);
        return std::ranges::all_of(routes, [&index](const std::string &route) {
            return internal::netsh({ "interface", "ipv4", "delete", "route", "prefix=" + route, "interface=" + index,
                                     "store=active" });
        });
    }
}

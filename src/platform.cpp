#include "app_split_tunnel.h"
#include "dns.h"
#include "killswitch.h"
#include "router.h"
#include "tun_device.h"

#if defined(_WIN32)
    #include "dns_windows.cpp"
    #include "dns_windows.h"
    #include "killswitch_windows.cpp"
    #include "killswitch_windows.h"
    #include "net/uplink_windows.cpp"
    #include "net/wfp.cpp"
    #include "router_windows.cpp"
    #include "router_windows.h"
    #include "split_tunnel_windows.cpp"
    #include "split_tunnel_windows_data.cpp"
    #include "tun_device_windows.cpp"
    #include "tun_device_windows.h"
    #include "util/process.cpp"
#elif defined(__APPLE__)
    #include "tun_device_macos.cpp"
    #include "tun_device_macos.h"
    #include <TargetConditionals.h>
    #if TARGET_OS_OSX
        #include "dns_macos.cpp"
        #include "dns_macos.h"
        #include "killswitch_macos.cpp"
        #include "killswitch_macos.h"
        #include "net/pf.cpp"
        #include "router_macos.cpp"
        #include "router_macos.h"
        #include "util/spawn.cpp"
    #endif
#elif defined(__ANDROID__)
    #include "tun_device_linux.cpp"
    #include "tun_device_linux.h"
#elif defined(__linux__)
    #include "dns_linux.cpp"
    #include "dns_linux.h"
    #include "killswitch_linux.cpp"
    #include "killswitch_linux.h"
    #include "net/iptables.cpp"
    #include "router_linux.cpp"
    #include "router_linux.h"
    #include "tun_device_linux.cpp"
    #include "tun_device_linux.h"
    #include "util/spawn.cpp"
#else
    #error Unsupported platform
#endif

namespace libxtun
{

    std::unique_ptr<Router> Router::create(RouterListener &listener)
    {
#if defined(__linux__) && !defined(__ANDROID__)
        return std::make_unique<LinuxRouter>(listener);
#elif defined(__APPLE__) && TARGET_OS_OSX
        return std::make_unique<MacosRouter>(listener);
#elif defined(_WIN32)
        return std::make_unique<WindowsRouter>(listener);
#else
        return nullptr;
#endif
    }

    std::unique_ptr<Dns> Dns::create(int ifIndex, const std::string &ifName)
    {
#if defined(__linux__) && !defined(__ANDROID__)
        (void)ifName;
        return LinuxDns::open(ifIndex);
#elif defined(__APPLE__) && TARGET_OS_OSX
        (void)ifIndex;
        return MacosDns::open(ifName);
#elif defined(_WIN32)
        (void)ifName;
        return WindowsDns::open(ifIndex);
#else
        (void)ifIndex;
        (void)ifName;
        return nullptr;
#endif
    }

    std::unique_ptr<TunDevice> createTunDevice()
    {
#if defined(_WIN32)
        return std::make_unique<WindowsTunDevice>();
#elif defined(__APPLE__)
        return std::make_unique<MacosTunDevice>();
#elif defined(__linux__) || defined(__ANDROID__)
        return std::make_unique<LinuxTunDevice>();
#endif
    }

    std::unique_ptr<Killswitch> Killswitch::create(libxtun_killswitch_mode mode, int macosGroup,
                                                   std::vector<net::IpAddress> dnsExceptions, bool splitTunnel)
    {
#if defined(__linux__) && !defined(__ANDROID__)
        (void)macosGroup;
        (void)splitTunnel;
        return std::make_unique<LinuxKillswitch>(mode, std::move(dnsExceptions));
#elif defined(__APPLE__) && TARGET_OS_OSX
        (void)splitTunnel;
        return std::make_unique<MacosKillswitch>(mode, macosGroup, std::move(dnsExceptions));
#elif defined(_WIN32)
        (void)macosGroup;
        return std::make_unique<WindowsKillswitch>(mode, std::move(dnsExceptions), splitTunnel);
#else
        (void)mode;
        (void)macosGroup;
        (void)dnsExceptions;
        (void)splitTunnel;
        return nullptr;
#endif
    }

    namespace
    {
        class NoAppSplitTunnel final : public AppSplitTunnel
        {
        public:
            libxtun_error activate(int) override
            {
                return LIBXTUN_OK;
            }
            libxtun_error deactivate() override
            {
                return LIBXTUN_OK;
            }
            libxtun_error updateAddresses() override
            {
                return LIBXTUN_OK;
            }
            libxtun_error setTrafficBlocked(bool) override
            {
                return LIBXTUN_OK;
            }
        };
    }

    ResultXtun<std::unique_ptr<AppSplitTunnel>> AppSplitTunnel::create(const char *const *apps)
    {
        if (apps == nullptr || *apps == nullptr) {
            return std::unique_ptr<AppSplitTunnel>(std::make_unique<NoAppSplitTunnel>());
        }
#if defined(_WIN32) && !defined(_M_ARM64EC) && (defined(_M_X64) || defined(__x86_64__))
        auto paths = split::executablePaths(apps);
        if (!paths) {
            return fail(paths.error());
        }
        return WindowsSplitTunnel::open(std::move(paths).value());
#else
        return fail(LIBXTUN_ERR_UNSUPPORTED);
#endif
    }

}

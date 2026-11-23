#ifndef LIBXTUN_TUNNEL_H
#define LIBXTUN_TUNNEL_H

#include "app_split_tunnel.h"
#include "dns.h"
#include "killswitch.h"
#include "net/ip.h"
#include "proxy.h"
#include "router.h"
#include "tun_device.h"
#include "tunnel_io.h"
#include "util/result.h"
#include "xtun.h"

#include <cstddef>
#include <functional>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <vector>

namespace libxtun
{
    class Tunnel : public TunnelIo, public TunDeviceListener, public RouterListener
    {
    public:
        using TunfactoryFunc = std::function<int(const std::vector<net::IpAddress> &, const std::vector<net::IpPrefix> &,
                                                 const std::vector<net::IpPrefix> &, int)>;

        enum class Event {
            Up,
            Down,
            MtuUpdate,
            UplinkUpdate
        };

        static ResultXtun<std::unique_ptr<Tunnel>> fromOpts(const libxtun_tunnel_opts &opts);
        static ResultXtun<std::unique_ptr<Tunnel>> fromTunfactory(TunfactoryFunc tunfactory,
                                                                  std::vector<net::IpPrefix> ifaddrs,
                                                                  std::vector<net::IpAddress> defaultDns);

        ~Tunnel();

        int attachProxy(Proxy *proxy);
        void detachProxy(Proxy *proxy);
        void networkChanged();

        int start();

        int read(std::span<std::byte> buf) override;
        int write(std::span<const std::byte> packet) override;
        void protectSocket(int fd) override;
        void wake() override;
        void halt() override;
        int mtu() const override;
        std::vector<net::IpPrefix> addresses() override;

        const std::string &name() const
        {
            return m_device->name();
        }

        void onLinkStateChanged(bool up) override;
        void onMtuChanged(int) override;
        void onRouteChanged() override;
        void onAddressChanged() override;

        void onUplinkChanged() override;

    private:
        Tunnel() = default;

        void emit(Event ev);
        void detachProxyLocked(Proxy *proxy);

        std::unique_ptr<TunDevice> m_device;
        std::unique_ptr<Router> m_router;
        std::unique_ptr<Dns> m_dns;
        // Declared before m_killswitch, so it is destroyed after it: KillSwitch filters
        // must leave the driver's WFP sublayer before this object removes the sublayer.
        // It is set before the network monitor starts, so callbacks may read it without m_mutex.
        std::unique_ptr<AppSplitTunnel> m_splitTunnel;
        std::unique_ptr<Killswitch> m_killswitch;

        std::mutex m_mutex;
        bool m_started = false;
        TunfactoryFunc m_tunfactory;
        Proxy *m_proxy = nullptr;
        std::vector<net::IpPrefix> m_addrs;
        std::vector<net::IpAddress> m_dnsDefaults;
    };
}

#endif // TUNNEL_H

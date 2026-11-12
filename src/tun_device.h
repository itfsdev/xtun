#ifndef LIBXTUN_TUN_DEVICE_H
#define LIBXTUN_TUN_DEVICE_H

#include "tunnel_io.h" // IWYU pragma: keep
#include "xtun.h"

#include <cstddef>
#include <memory>
#include <span>
#include <string>

namespace libxtun
{
    class TunDeviceListener
    {
    public:
        virtual ~TunDeviceListener() = default;

        virtual void onLinkStateChanged(bool up) = 0;
        virtual void onMtuChanged(int mtu) = 0;
        virtual void onRouteChanged() = 0;
        // A local IP address was added, removed, or became usable. Only Windows reports it.
        virtual void onAddressChanged() = 0;
    };

    class TunDevice
    {
    public:
        virtual ~TunDevice() = default;

        virtual libxtun_error open() = 0;
        virtual libxtun_error adoptFd(int fd) = 0;
        virtual libxtun_error adoptName(const char *name) = 0;

        virtual int read(std::span<std::byte> buf) noexcept = 0;
        virtual int write(std::span<const std::byte> buf) noexcept = 0;
        virtual int mtu() const noexcept = 0;

        virtual const std::string &name() const noexcept = 0;
        virtual int ifIndex() const noexcept = 0;
        virtual bool up() const noexcept = 0;

        virtual void resetReadCancellation() noexcept = 0;
        virtual void wakeRead() noexcept = 0;
        virtual void cancelRead() noexcept = 0;

        virtual void startMonitor(TunDeviceListener &listener) = 0;
        virtual void stopMonitor() noexcept = 0;
    };

    std::unique_ptr<TunDevice> createTunDevice();
}

#endif // LIBXTUN_TUN_DEVICE_H

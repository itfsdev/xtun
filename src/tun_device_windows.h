#ifndef LIBXTUN_TUN_DEVICE_WINDOWS_H
#define LIBXTUN_TUN_DEVICE_WINDOWS_H

#include "tun_device.h"
#include <winsock2.h>
#include <wintun.h>
#include <ws2tcpip.h>

// iphlpapi.h MUST NOT be included before winsock2.h to avoid redefinition errors.
#include <iphlpapi.h>

#include <atomic>

namespace libxtun
{
    class WindowsTunDevice final : public TunDevice
    {
    public:
        libxtun_error open() override;
        libxtun_error adoptFd(int fd) override;
        libxtun_error adoptName(const char *name) override;

        int read(std::span<std::byte> buf) noexcept override;
        int write(std::span<const std::byte> buf) noexcept override;
        int mtu() const noexcept override;

        const std::string &name() const noexcept override;
        int ifIndex() const noexcept override;
        bool up() const noexcept override;

        void resetReadCancellation() noexcept override;
        void wakeRead() noexcept override;
        void cancelRead() noexcept override;
        void startMonitor(TunDeviceListener &listener) override;
        void stopMonitor() noexcept override;

        ~WindowsTunDevice() override;

    private:
        libxtun_error loadWintun(WINTUN_CREATE_ADAPTER_FUNC *&createAdapter, WINTUN_OPEN_ADAPTER_FUNC *&openAdapter,
                       WINTUN_START_SESSION_FUNC *&startSession, WINTUN_GET_READ_WAIT_EVENT_FUNC *&getReadWaitEvent);
        libxtun_error startWintunSession(WINTUN_START_SESSION_FUNC *startSession,
                               WINTUN_GET_READ_WAIT_EVENT_FUNC *getReadWaitEvent);
        libxtun_error finishOpen();

        static void CALLBACK onRouteChangeCb(void *ctx, MIB_IPFORWARD_ROW2 *row, MIB_NOTIFICATION_TYPE type);
        static void CALLBACK onAddressChangeCb(void *ctx, MIB_UNICASTIPADDRESS_ROW *row, MIB_NOTIFICATION_TYPE type);

        HMODULE m_wintun = nullptr;
        WINTUN_ADAPTER_HANDLE m_adapter = nullptr;
        WINTUN_SESSION_HANDLE m_session = nullptr;
        HANDLE m_readWait = nullptr;
        std::atomic<bool> m_closing { false };
        std::atomic<bool> m_injectPending { false };
        std::atomic<int> m_running { 0 };
        int m_forcedMtu = 1420;
        std::string m_name;
        int m_ifIndex = -1;

        WINTUN_CLOSE_ADAPTER_FUNC *m_closeAdapter = nullptr;
        WINTUN_END_SESSION_FUNC *m_endSession = nullptr;
        WINTUN_RECEIVE_PACKET_FUNC *m_receivePacket = nullptr;
        WINTUN_RELEASE_RECEIVE_PACKET_FUNC *m_releaseReceivePacket = nullptr;
        WINTUN_ALLOCATE_SEND_PACKET_FUNC *m_allocateSendPacket = nullptr;
        WINTUN_SEND_PACKET_FUNC *m_sendPacket = nullptr;
        WINTUN_GET_ADAPTER_LUID_FUNC *m_getAdapterLuid = nullptr;
        HANDLE m_routeNotify = nullptr;
        HANDLE m_addressNotify = nullptr;
        TunDeviceListener *m_listener = nullptr;
    };
}

#endif // LIBXTUN_TUN_DEVICE_WINDOWS_H

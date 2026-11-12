#include "tun_device_windows.h"
#include "xtun.h"

#include <cstring>
#include <thread>

namespace libxtun
{
    namespace
    {
        class RunGuard
        {
        public:
            explicit RunGuard(std::atomic<int> &counter) : m_counter(counter)
            {
                m_counter.fetch_add(1);
            }

            ~RunGuard()
            {
                m_counter.fetch_sub(1);
            }

        private:
            std::atomic<int> &m_counter;
        };
    }

    libxtun_error WindowsTunDevice::open()
    {
        WINTUN_CREATE_ADAPTER_FUNC *createAdapter;
        WINTUN_OPEN_ADAPTER_FUNC *openAdapter;
        WINTUN_START_SESSION_FUNC *startSession;
        WINTUN_GET_READ_WAIT_EVENT_FUNC *getReadWaitEvent;
        if (auto rc = loadWintun(createAdapter, openAdapter, startSession, getReadWaitEvent); rc != LIBXTUN_OK) {
            return rc;
        }
        (void)openAdapter;

        m_adapter = createAdapter(L"xtun", L"WireGuard", nullptr);
        if (m_adapter == nullptr) {
            FreeLibrary(m_wintun);
            m_wintun = nullptr;
            return LIBXTUN_ERR_DEVICE_CREATE;
        }

        m_name = "xtun";
        if (auto rc = startWintunSession(startSession, getReadWaitEvent); rc != LIBXTUN_OK) {
            return rc;
        }

        return finishOpen();
    }

    libxtun_error WindowsTunDevice::adoptFd(int fd)
    {
        (void)fd;
        return LIBXTUN_ERR_UNSUPPORTED;
    }

    libxtun_error WindowsTunDevice::adoptName(const char *name)
    {
        WINTUN_CREATE_ADAPTER_FUNC *createAdapter;
        WINTUN_OPEN_ADAPTER_FUNC *openAdapter;
        WINTUN_START_SESSION_FUNC *startSession;
        WINTUN_GET_READ_WAIT_EVENT_FUNC *getReadWaitEvent;
        if (auto rc = loadWintun(createAdapter, openAdapter, startSession, getReadWaitEvent); rc != LIBXTUN_OK) {
            return rc;
        }
        (void)createAdapter;

        WCHAR wname[256];
        if (MultiByteToWideChar(CP_UTF8, 0, name, -1, wname, 256) == 0) {
            FreeLibrary(m_wintun);
            m_wintun = nullptr;
            return LIBXTUN_ERR_INVALID_ARGS;
        }

        m_adapter = openAdapter(wname);
        if (m_adapter == nullptr) {
            FreeLibrary(m_wintun);
            m_wintun = nullptr;
            return LIBXTUN_ERR_DEVICE_CREATE;
        }

        m_name = name;
        if (auto rc = startWintunSession(startSession, getReadWaitEvent); rc != LIBXTUN_OK) {
            return rc;
        }

        return LIBXTUN_OK;
    }

    int WindowsTunDevice::read(std::span<std::byte> buf) noexcept
    {
        RunGuard guard(m_running);

        if (m_session == nullptr) {
            return IO_FATAL;
        }

        for (;;) {
            if (m_closing.load(std::memory_order_acquire)) {
                return IO_FATAL;
            }
            if (m_injectPending.exchange(false, std::memory_order_acquire)) {
                return READ_WAKE;
            }
            DWORD packetSize = 0;
            BYTE *packet = m_receivePacket(m_session, &packetSize);
            if (packet != nullptr) {
                DWORD n = packetSize < buf.size() ? packetSize : static_cast<DWORD>(buf.size());
                std::memcpy(buf.data(), packet, n);
                m_releaseReceivePacket(m_session, packet);
                return static_cast<int>(n);
            }
            if (GetLastError() == ERROR_NO_MORE_ITEMS) {
                WaitForSingleObject(m_readWait, INFINITE);
                continue;
            }
            return IO_FATAL;
        }
    }

    int WindowsTunDevice::write(std::span<const std::byte> buf) noexcept
    {
        RunGuard guard(m_running);

        if (m_session == nullptr || m_closing.load() || buf.empty()) {
            return -1;
        }
        BYTE *packet = m_allocateSendPacket(m_session, static_cast<DWORD>(buf.size()));
        if (packet == nullptr) {
            return -1; // ring full => packet dropped
        }
        std::memcpy(packet, buf.data(), buf.size());
        m_sendPacket(m_session, packet);
        return static_cast<int>(buf.size());
    }

    int WindowsTunDevice::mtu() const noexcept
    {
        return m_forcedMtu;
    }

    const std::string &WindowsTunDevice::name() const noexcept
    {
        return m_name;
    }

    int WindowsTunDevice::ifIndex() const noexcept
    {
        return m_ifIndex;
    }

    bool WindowsTunDevice::up() const noexcept
    {
        return true;
    }

    void WindowsTunDevice::resetReadCancellation() noexcept
    {
        m_closing.store(false, std::memory_order_release);
        m_injectPending.store(false, std::memory_order_release);
    }

    void WindowsTunDevice::wakeRead() noexcept
    {
        m_injectPending.store(true, std::memory_order_release);
        if (m_readWait != nullptr) {
            SetEvent(m_readWait);
        }
    }

    void WindowsTunDevice::cancelRead() noexcept
    {
        m_closing.store(true, std::memory_order_release);
        if (m_readWait != nullptr) {
            SetEvent(m_readWait);
        }
    }

    void WindowsTunDevice::startMonitor(TunDeviceListener &listener)
    {
        m_listener = &listener;
        NotifyRouteChange2(AF_UNSPEC, &WindowsTunDevice::onRouteChangeCb, this, FALSE, &m_routeNotify);
        // An address can change without a route change, for example when a new IPv6 address becomes usable.
        NotifyUnicastIpAddressChange(AF_UNSPEC, &WindowsTunDevice::onAddressChangeCb, this, FALSE, &m_addressNotify);
    }

    void WindowsTunDevice::stopMonitor() noexcept
    {
        // Cancellation waits for callbacks. The listener's lock must stay free here.
        if (m_routeNotify != nullptr) {
            CancelMibChangeNotify2(m_routeNotify);
            m_routeNotify = nullptr;
        }
        if (m_addressNotify != nullptr) {
            CancelMibChangeNotify2(m_addressNotify);
            m_addressNotify = nullptr;
        }
        m_listener = nullptr;
    }

    WindowsTunDevice::~WindowsTunDevice()
    {
        stopMonitor();
        cancelRead();

        while (m_running.load() != 0) {
            std::this_thread::yield();
        }
        if (m_session != nullptr) {
            m_endSession(m_session);
        }
        if (m_adapter != nullptr) {
            m_closeAdapter(m_adapter);
        }
        if (m_wintun != nullptr) {
            FreeLibrary(m_wintun);
        }
    }

    libxtun_error WindowsTunDevice::loadWintun(WINTUN_CREATE_ADAPTER_FUNC *&createAdapter,
                                               WINTUN_OPEN_ADAPTER_FUNC *&openAdapter,
                                               WINTUN_START_SESSION_FUNC *&startSession,
                                               WINTUN_GET_READ_WAIT_EVENT_FUNC *&getReadWaitEvent)
    {
        m_wintun = LoadLibraryExW(L"wintun.dll", nullptr,
                                  LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (m_wintun == nullptr) {
            return LIBXTUN_ERR_DRIVER_UNAVAILABLE;
        }

        createAdapter = reinterpret_cast<WINTUN_CREATE_ADAPTER_FUNC *>(GetProcAddress(m_wintun, "WintunCreateAdapter"));
        openAdapter = reinterpret_cast<WINTUN_OPEN_ADAPTER_FUNC *>(GetProcAddress(m_wintun, "WintunOpenAdapter"));
        startSession = reinterpret_cast<WINTUN_START_SESSION_FUNC *>(GetProcAddress(m_wintun, "WintunStartSession"));
        getReadWaitEvent =
                reinterpret_cast<WINTUN_GET_READ_WAIT_EVENT_FUNC *>(GetProcAddress(m_wintun, "WintunGetReadWaitEvent"));

        m_closeAdapter = reinterpret_cast<WINTUN_CLOSE_ADAPTER_FUNC *>(GetProcAddress(m_wintun, "WintunCloseAdapter"));
        m_endSession = reinterpret_cast<WINTUN_END_SESSION_FUNC *>(GetProcAddress(m_wintun, "WintunEndSession"));
        m_receivePacket = reinterpret_cast<WINTUN_RECEIVE_PACKET_FUNC *>(GetProcAddress(m_wintun, "WintunReceivePacket"));
        m_releaseReceivePacket = reinterpret_cast<WINTUN_RELEASE_RECEIVE_PACKET_FUNC *>(
                GetProcAddress(m_wintun, "WintunReleaseReceivePacket"));
        m_allocateSendPacket = reinterpret_cast<WINTUN_ALLOCATE_SEND_PACKET_FUNC *>(
                GetProcAddress(m_wintun, "WintunAllocateSendPacket"));
        m_sendPacket = reinterpret_cast<WINTUN_SEND_PACKET_FUNC *>(GetProcAddress(m_wintun, "WintunSendPacket"));
        m_getAdapterLuid =
                reinterpret_cast<WINTUN_GET_ADAPTER_LUID_FUNC *>(GetProcAddress(m_wintun, "WintunGetAdapterLUID"));

        if (createAdapter == nullptr || openAdapter == nullptr || startSession == nullptr || getReadWaitEvent == nullptr
            || m_closeAdapter == nullptr || m_endSession == nullptr || m_receivePacket == nullptr
            || m_releaseReceivePacket == nullptr || m_allocateSendPacket == nullptr || m_sendPacket == nullptr
            || m_getAdapterLuid == nullptr) {
            FreeLibrary(m_wintun);
            m_wintun = nullptr;
            return LIBXTUN_ERR_DRIVER_UNAVAILABLE;
        }

        return LIBXTUN_OK;
    }

    libxtun_error WindowsTunDevice::startWintunSession(WINTUN_START_SESSION_FUNC *startSession,
                                                       WINTUN_GET_READ_WAIT_EVENT_FUNC *getReadWaitEvent)
    {
        m_session = startSession(m_adapter, 0x800000); // 8 MiB ring
        if (m_session == nullptr) {
            m_closeAdapter(m_adapter);
            m_adapter = nullptr;
            FreeLibrary(m_wintun);
            m_wintun = nullptr;
            return LIBXTUN_ERR_DEVICE_CREATE;
        }

        m_readWait = getReadWaitEvent(m_session);
        return LIBXTUN_OK;
    }

    libxtun_error WindowsTunDevice::finishOpen()
    {
        NET_LUID luid;
        m_getAdapterLuid(m_adapter, &luid);
        NET_IFINDEX ifindex = 0;
        if (ConvertInterfaceLuidToIndex(&luid, &ifindex) != NO_ERROR) {
            return LIBXTUN_ERR_SYSTEM;
        }
        m_ifIndex = static_cast<int>(ifindex);
        return LIBXTUN_OK;
    }

    void CALLBACK WindowsTunDevice::onRouteChangeCb(void *ctx, MIB_IPFORWARD_ROW2 *row, MIB_NOTIFICATION_TYPE type)
    {
        (void)row;
        (void)type;
        auto *device = static_cast<WindowsTunDevice *>(ctx);
        if (device->m_listener != nullptr) {
            device->m_listener->onRouteChanged();
        }
    }

    void CALLBACK WindowsTunDevice::onAddressChangeCb(void *ctx, MIB_UNICASTIPADDRESS_ROW *row, MIB_NOTIFICATION_TYPE type)
    {
        (void)row;
        (void)type;
        auto *device = static_cast<WindowsTunDevice *>(ctx);
        if (device->m_listener != nullptr) {
            device->m_listener->onAddressChanged();
        }
    }
}

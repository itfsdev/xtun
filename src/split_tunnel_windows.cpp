#include "split_tunnel_windows.h"

#include <winioctl.h>
#include <winsvc.h>

#include <array>
#include <limits>
#include <utility>

namespace libxtun
{
    namespace
    {
        constexpr GUID XTUN_SPLIT_PROVIDER_KEY {
            0xae83f983, 0x9247, 0x49f0, { 0xba, 0x8f, 0x8f, 0x74, 0x79, 0x01, 0x71, 0xc6 }
        };
        constexpr GUID GUARD_PROVIDER_KEY { 0x63408ca2, 0xac35, 0x4629, { 0x83, 0x11, 0x0a, 0x48, 0x0b, 0xdc, 0x21, 0x3e } };
        constexpr GUID GUARD_SUBLAYER_KEY { 0x5c12b3ee, 0xf854, 0x4a28, { 0x92, 0x29, 0xb3, 0xf5, 0x55, 0x85, 0x96, 0x07 } };
        // These two keys are fixed in win-split-tunnel 1.2.5.0, src/firewall/identifiers.h.
        constexpr GUID BASELINE_SUBLAYER_KEY {
            0xc78056ff, 0x2bc1, 0x4211, { 0xaa, 0xdd, 0x7f, 0x35, 0x8d, 0xef, 0x20, 0x2d }
        };
        constexpr GUID DNS_SUBLAYER_KEY { 0x60090787, 0xcca1, 0x4937, { 0xaa, 0xce, 0x51, 0x25, 0x6e, 0xf4, 0x81, 0xf3 } };

        wfp::WfpConfig dnsWfpConfig() noexcept
        {
            auto config = split::baselineWfpConfig();
            config.sublayer = DNS_SUBLAYER_KEY;
            config.sublayerName = L"xtun-split-dns-sublayer";
            config.sublayerDesc = L"xtun Split Tunnel DNS Sublayer";
            // Not the baseline weight: Windows moves a sublayer to another weight when its weight is taken.
            config.sublayerWeight = 0xFFFD;
            return config;
        }

        wfp::WfpConfig guardWfpConfig() noexcept
        {
            wfp::WfpConfig config {};
            config.provider = GUARD_PROVIDER_KEY;
            config.providerName = L"xtun-split-guard-provider";
            config.providerDesc = L"xtun Split Tunnel Guard Provider";
            config.sublayer = GUARD_SUBLAYER_KEY;
            config.sublayerName = L"xtun-split-guard-sublayer";
            config.sublayerDesc = L"xtun Split Tunnel Guard Sublayer";
            config.sublayerWeight = 0xFFFF;
            return config;
        }

        constexpr DWORD GET_SPLIT_STATE = CTL_CODE(0x8000, 9, METHOD_BUFFERED, FILE_ANY_ACCESS);

        struct ServiceCloser
        {
            using pointer = SC_HANDLE;

            void operator()(SC_HANDLE handle) const noexcept
            {
                ::CloseServiceHandle(handle);
            }
        };
        using Service = std::unique_ptr<void, ServiceCloser>;

        libxtun_error splitError(DWORD error)
        {
            switch (error) {
            case ERROR_ACCESS_DENIED:
            case ERROR_PRIVILEGE_NOT_HELD: return LIBXTUN_ERR_ACCESS_DENIED;
            case ERROR_SHARING_VIOLATION:
            case ERROR_BUSY: return LIBXTUN_ERR_SPLIT_BUSY;
            default: return LIBXTUN_ERR_SPLIT_DRIVER;
            }
        }

        libxtun_error checkService(SC_HANDLE service)
        {
            // QueryServiceConfigW needs at most 8 KiB.
            alignas(QUERY_SERVICE_CONFIGW) std::array<std::byte, 8192> buffer {};
            auto *config = reinterpret_cast<QUERY_SERVICE_CONFIGW *>(buffer.data());
            DWORD needed = 0;
            if (!::QueryServiceConfigW(service, config, static_cast<DWORD>(buffer.size()), &needed)) {
                return splitError(::GetLastError());
            }
            if (config->dwServiceType != SERVICE_KERNEL_DRIVER || config->dwStartType != SERVICE_DEMAND_START) {
                return LIBXTUN_ERR_SPLIT_DRIVER;
            }
            return LIBXTUN_OK;
        }
    }

    wfp::WfpConfig split::baselineWfpConfig() noexcept
    {
        wfp::WfpConfig config {};
        config.provider = XTUN_SPLIT_PROVIDER_KEY;
        config.providerName = L"xtun-split-provider";
        config.providerDesc = L"xtun Split Tunnel Provider";
        config.sublayer = BASELINE_SUBLAYER_KEY;
        config.sublayerName = L"xtun-split-baseline-sublayer";
        config.sublayerDesc = L"xtun Split Tunnel Baseline Sublayer";
        // The guard (0xFFFF) should run before the driver's filters in these sublayers.
        // This order is not guaranteed: if another program already uses a weight, Windows stores another one.
        config.sublayerWeight = 0xFFFE;
        // Driver and HARD filters need sublayers from a non-dynamic session.
        config.persistent = true;
        return config;
    }

    ResultXtun<std::unique_ptr<WindowsSplitTunnel>> WindowsSplitTunnel::open()
    {
#if defined(_M_ARM64EC) || (!defined(_M_X64) && !defined(__x86_64__))
        return fail(LIBXTUN_ERR_UNSUPPORTED);
#else
        auto component = std::unique_ptr<WindowsSplitTunnel>(new WindowsSplitTunnel);
        // Keep this named object alive to block a second owner.
        // Do not lock it: another thread may destroy this component.
        component->m_driverOwnerMutex = ::CreateMutexW(nullptr, FALSE, L"Global\\XtunSplitTunnel");
        if (!component->m_driverOwnerMutex) {
            return fail(splitError(::GetLastError()));
        }
        if (::GetLastError() == ERROR_ALREADY_EXISTS) {
            return fail(LIBXTUN_ERR_SPLIT_BUSY);
        }

        Service manager(::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
        if (!manager) {
            return fail(splitError(::GetLastError()));
        }
        Service service(::OpenServiceW(manager.get(), L"XtunSplitTunnel",
                                       SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_START));
        if (!service) {
            return fail(splitError(::GetLastError()));
        }
        const auto configError = checkService(service.get());
        if (configError != LIBXTUN_OK) {
            return fail(configError);
        }

        SERVICE_STATUS status {};
        if (!::QueryServiceStatus(service.get(), &status)) {
            return fail(splitError(::GetLastError()));
        }
        if (status.dwCurrentState == SERVICE_STOPPED) {
            if (!::StartServiceW(service.get(), 0, nullptr)) {
                const DWORD error = ::GetLastError();
                if (error != ERROR_SERVICE_ALREADY_RUNNING) {
                    return fail(splitError(error));
                }
            }
            if (!::QueryServiceStatus(service.get(), &status)) {
                return fail(splitError(::GetLastError()));
            }
        }
        if (status.dwCurrentState != SERVICE_RUNNING) {
            return fail(LIBXTUN_ERR_SPLIT_BUSY);
        }

        component->m_device = ::CreateFileW(L"\\\\.\\MULLVADSPLITTUNNEL", GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (component->m_device == INVALID_HANDLE_VALUE) {
            return fail(splitError(::GetLastError()));
        }
        const auto state = component->state();
        if (!state) {
            return fail(state.error());
        }
        if (state.value() == State::Zombie) {
            return fail(LIBXTUN_ERR_SPLIT_DRIVER);
        }
        if (state.value() != State::Started) {
            return fail(LIBXTUN_ERR_SPLIT_BUSY);
        }
        if (const auto error = component->prepareDriverSublayers(); error != LIBXTUN_OK) {
            return fail(error);
        }
        return component;
#endif
    }

    WindowsSplitTunnel::~WindowsSplitTunnel()
    {
        if (m_device != INVALID_HANDLE_VALUE) {
            ::CloseHandle(m_device);
        }
        for (auto &engine : m_sharedWfpSessions) {
            if (engine) {
                engine->cleanup();
                engine.reset();
            }
        }
        m_guardWfpSession.reset();
        if (m_driverOwnerMutex) {
            ::CloseHandle(m_driverOwnerMutex);
        }
    }

    libxtun_error WindowsSplitTunnel::prepareDriverSublayers()
    {
        const std::array configs { split::baselineWfpConfig(), dnsWfpConfig() };

        for (size_t i = 0; i < configs.size(); ++i) {
            auto result = wfp::WfpEngine::open(configs[i]);
            if (!result) {
                return result.error();
            }
            auto session = std::move(result).value();
            wfp::WfpEngine::Transaction transaction(*session);
            if (transaction.status() != LIBXTUN_OK) {
                return transaction.status();
            }
            if (const auto error = session->addProvider(); error != LIBXTUN_OK) {
                return error;
            }
            if (const auto error = session->addSublayer(); error != LIBXTUN_OK) {
                return error;
            }
            if (const auto error = transaction.commit(); error != LIBXTUN_OK) {
                return error;
            }
            m_sharedWfpSessions[i] = std::move(session);
        }
        return LIBXTUN_OK;
    }

    libxtun_error WindowsSplitTunnel::setTrafficBlocked(bool blocked)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!blocked) {
            if (!m_guardWfpSession) {
                return LIBXTUN_OK;
            }
            const auto error = m_guardWfpSession->cleanup();
            if (error == LIBXTUN_OK) {
                m_guardWfpSession.reset();
            }
            return error;
        }
        if (m_guardWfpSession) {
            return LIBXTUN_OK;
        }

        auto result = wfp::WfpEngine::open(guardWfpConfig());
        if (!result) {
            return result.error();
        }
        auto session = std::move(result).value();
        wfp::WfpEngine::Transaction transaction(*session);
        if (transaction.status() != LIBXTUN_OK) {
            return transaction.status();
        }
        if (const auto error = session->addProvider(); error != LIBXTUN_OK) {
            return error;
        }
        if (const auto error = session->addSublayer(); error != LIBXTUN_OK) {
            return error;
        }
        // Keep loopback allowed: it is not a leak, and many apps need it.
        // For example, curl on Windows connects to itself over 127.0.0.1.
        FWPM_FILTER_CONDITION loopback {};
        loopback.fieldKey = FWPM_CONDITION_FLAGS;
        loopback.matchType = FWP_MATCH_FLAGS_ANY_SET;
        loopback.conditionValue.type = FWP_UINT32;
        loopback.conditionValue.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;
        for (const GUID &layer : { FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
                                   FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6 }) {
            // The higher weight wins in this sublayer, so loopback passes and the rest is blocked.
            if (const auto error = session->addFilter(layer, FWP_ACTION_PERMIT, 1, std::span(&loopback, 1),
                                                      L"xtun Split Tunnel Guard Loopback");
                error != LIBXTUN_OK) {
                return error;
            }
            if (const auto error = session->addFilter(layer, FWP_ACTION_BLOCK, 0, {}, L"xtun Split Tunnel Guard");
                error != LIBXTUN_OK) {
                return error;
            }
        }
        if (const auto error = transaction.commit(); error != LIBXTUN_OK) {
            return error;
        }
        m_guardWfpSession = std::move(session);
        return LIBXTUN_OK;
    }

    libxtun_error WindowsSplitTunnel::control(DWORD code, std::span<const std::byte> input, std::span<std::byte> output)
    {
        if (input.size() > std::numeric_limits<DWORD>::max() || output.size() > std::numeric_limits<DWORD>::max()) {
            return LIBXTUN_ERR_INVALID_ARGS;
        }
        std::lock_guard<std::mutex> lock(m_mutex);
        DWORD bytes = 0;
        if (!::DeviceIoControl(m_device, code, const_cast<std::byte *>(input.data()), static_cast<DWORD>(input.size()),
                               output.data(), static_cast<DWORD>(output.size()), &bytes, nullptr)) {
            return splitError(::GetLastError());
        }
        return bytes == output.size() ? LIBXTUN_OK : LIBXTUN_ERR_SPLIT_DRIVER;
    }

    ResultXtun<WindowsSplitTunnel::State> WindowsSplitTunnel::state()
    {
        // The driver writes SIZE_T: 8 bytes on Windows x64. A smaller buffer fails the request.
        SIZE_T value = 0;
        const auto error = control(GET_SPLIT_STATE, {}, std::as_writable_bytes(std::span(&value, 1)));
        if (error != LIBXTUN_OK) {
            return fail(error);
        }
        if (value < static_cast<SIZE_T>(State::Started) || value > static_cast<SIZE_T>(State::Zombie)) {
            return fail(LIBXTUN_ERR_SPLIT_DRIVER);
        }
        return static_cast<State>(value);
    }
}

#include "split_tunnel_windows.h"

#include <winioctl.h>
#include <winsvc.h>

#include <array>
#include <limits>

namespace libxtun
{
    namespace
    {
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
        return component;
#endif
    }

    WindowsSplitTunnel::~WindowsSplitTunnel()
    {
        if (m_device != INVALID_HANDLE_VALUE) {
            ::CloseHandle(m_device);
        }
        if (m_driverOwnerMutex) {
            ::CloseHandle(m_driverOwnerMutex);
        }
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

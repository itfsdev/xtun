#ifndef LIBXTUN_SPLIT_TUNNEL_WINDOWS_H
#define LIBXTUN_SPLIT_TUNNEL_WINDOWS_H

#include "util/noncopyable.h"
#include "util/result.h"

#include <windows.h>

#include <cstddef>
#include <memory>
#include <mutex>
#include <span>

namespace libxtun
{
    class WindowsSplitTunnel final : private NonCopyable
    {
    public:
        // State values from win-split-tunnel 1.2.5.0.
        enum class State : DWORD {
            Started = 1,     // Driver is loaded; control device is created.
            Initialized = 2, // Driver subsystems are ready.
            Ready = 3,       // Initial process list is registered.
            Engaged = 4,     // IP addresses and app rules are set.
            Zombie = 5,      // Driver cleanup failed.
        };

        // Open the driver for one owner, starting its service if needed.
        static ResultXtun<std::unique_ptr<WindowsSplitTunnel>> open();
        ~WindowsSplitTunnel();

        ResultXtun<State> state();

    private:
        WindowsSplitTunnel() = default;

        // Send a command to the driver, wait for it, and check the reply size.
        libxtun_error control(DWORD code, std::span<const std::byte> input, std::span<std::byte> output);

        HANDLE m_driverOwnerMutex = nullptr;
        HANDLE m_device = INVALID_HANDLE_VALUE;
        std::mutex m_mutex;
    };
}

#endif // LIBXTUN_SPLIT_TUNNEL_WINDOWS_H

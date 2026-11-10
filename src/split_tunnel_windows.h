#ifndef LIBXTUN_SPLIT_TUNNEL_WINDOWS_H
#define LIBXTUN_SPLIT_TUNNEL_WINDOWS_H

#include "net/wfp.h"
#include "util/noncopyable.h"
#include "util/result.h"

#include <windows.h>

#include <array>
#include <cstddef>
#include <memory>
#include <mutex>
#include <span>

namespace libxtun
{
    namespace split
    {
        wfp::WfpConfig baselineWfpConfig() noexcept;
    }

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

        // Open the driver for one owner and prepare its WFP sublayers.
        // Start the driver service if needed.
        static ResultXtun<std::unique_ptr<WindowsSplitTunnel>> open();
        ~WindowsSplitTunnel();

        ResultXtun<State> state();

        // Block connections for all apps while the driver settings are being changed.
        // Existing connections can also be blocked when WFP checks them again.
        libxtun_error setTrafficBlocked(bool blocked);

    private:
        WindowsSplitTunnel() = default;

        // Create the xtun WFP provider and the two sublayers needed by the driver.
        // Check the owner and priority of existing sublayers.
        libxtun_error prepareDriverSublayers();

        // Send a command to the driver, wait for it, and check the reply size.
        libxtun_error control(DWORD code, std::span<const std::byte> input, std::span<std::byte> output);

        HANDLE m_driverOwnerMutex = nullptr;
        HANDLE m_device = INVALID_HANDLE_VALUE;
        std::array<std::unique_ptr<wfp::WfpEngine>, 2> m_sharedWfpSessions;
        std::unique_ptr<wfp::WfpEngine> m_guardWfpSession;
        std::mutex m_mutex;
    };
}

#endif // LIBXTUN_SPLIT_TUNNEL_WINDOWS_H

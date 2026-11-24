#ifndef LIBXTUN_SPLIT_TUNNEL_WINDOWS_H
#define LIBXTUN_SPLIT_TUNNEL_WINDOWS_H

#include "app_split_tunnel.h"
#include "net/wfp.h"
#include "split_tunnel_windows_data.h"
#include "util/result.h"

#include <windows.h>

#include <array>
#include <cstddef>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <vector>

namespace libxtun
{
    namespace split
    {
        wfp::WfpConfig baselineWfpConfig() noexcept;
    }

    class WindowsSplitTunnel final : public AppSplitTunnel
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
        // Start the driver service if needed. Reset settings left by an owner that crashed.
        static ResultXtun<std::unique_ptr<WindowsSplitTunnel>> open(std::vector<std::wstring> paths,
                                                                    const std::wstring &serviceName);
        ~WindowsSplitTunnel();

        ResultXtun<State> state();

        // Set the process list, current IP addresses, and native EXE paths.
        // Remove the temporary block only after the driver is engaged.
        libxtun_error activate(int ifIndex) override;

        // Stop splitting and reset the driver. Keep the temporary block until
        // Tunnel finishes removing routes and calls setTrafficBlocked(false).
        libxtun_error deactivate() override;

        // Send the current TUN addresses and the addresses of the physical Internet interface
        // (IPv4 and IPv6) to the driver if they changed, for example after switching from Wi-Fi to Ethernet.
        // An error keeps traffic blocked; the next network event retries the update.
        libxtun_error updateAddresses() override;

        // Block connections for all apps while the driver settings are being changed.
        // Existing connections can also be blocked when WFP checks them again.
        libxtun_error setTrafficBlocked(bool blocked) override;

    private:
        WindowsSplitTunnel() = default;

        // Create the xtun WFP provider and the two sublayers needed by the driver.
        // Check the owner and priority of existing sublayers.
        libxtun_error prepareDriverSublayers();

        // Read the TUN addresses and the addresses of the current Internet interfaces.
        static ResultXtun<split::IpAddresses> readAddresses(int ifIndex);
        ResultXtun<State> stateLocked();
        libxtun_error setTrafficBlockedLocked(bool blocked);
        // Remove all driver settings and check that the driver is back in the Started state.
        libxtun_error resetLocked();

        // Send a command to the driver, wait for it, and check the reply size.
        // The caller holds m_mutex.
        libxtun_error control(DWORD code, std::span<const std::byte> input, std::span<std::byte> output);

        std::vector<std::wstring> m_paths;
        HANDLE m_driverOwnerMutex = nullptr;
        HANDLE m_device = INVALID_HANDLE_VALUE;
        std::array<std::unique_ptr<wfp::WfpEngine>, 2> m_sharedWfpSessions;
        std::unique_ptr<wfp::WfpEngine> m_guardWfpSession;
        std::mutex m_mutex;
        bool m_initialized = false;
        int m_ifIndex = 0;
        split::IpAddresses m_addresses;
        bool m_addressesValid = false;
    };
}

#endif // LIBXTUN_SPLIT_TUNNEL_WINDOWS_H

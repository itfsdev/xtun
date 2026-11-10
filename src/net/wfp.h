#ifndef LIBXTUN_NET_WFP_H
#define LIBXTUN_NET_WFP_H

#include "util/noncopyable.h"
#include "util/result.h"
#include "xtun.h"

#include <windows.h>

#include <fwpmu.h>
#include <fwptypes.h>

#include <memory>
#include <span>
#include <vector>

namespace libxtun::wfp
{
    struct WfpConfig {
        GUID provider;
        const wchar_t *providerName;
        const wchar_t *providerDesc;
        GUID sublayer;
        const wchar_t *sublayerName;
        const wchar_t *sublayerDesc;
        UINT16 sublayerWeight;
        bool persistent;
        // If true, create the sublayer and try to remove it during cleanup.
        // If false, use the existing sublayer and leave it as is during cleanup.
        bool ownsSublayer = true;
    };

    struct FilterInfo
    {
        UINT64 id;
        GUID layer;
        FWP_ACTION_TYPE action;
    };

    struct FwpmMemoryDeleter
    {
        void operator()(void *memory) const noexcept
        {
            ::FwpmFreeMemory(&memory);
        }
    };

    class WfpEngine final : private NonCopyable
    {
    public:
        ~WfpEngine();

        class Transaction final : private NonCopyable
        {
        public:
            explicit Transaction(WfpEngine &engine) noexcept;
            ~Transaction();

            [[nodiscard]] libxtun_error status() const noexcept { return m_status; }
            libxtun_error commit() noexcept;

        private:
            HANDLE m_engine = nullptr;
            libxtun_error m_status = LIBXTUN_OK;
        };

        static ResultXtun<std::unique_ptr<WfpEngine>> open(WfpConfig config);

        libxtun_error addProvider() noexcept;
        libxtun_error addSublayer() noexcept;
        libxtun_error addFilter(const GUID &layer, const FWP_ACTION_TYPE action, const UINT8 weight,
                                std::span<FWPM_FILTER_CONDITION> conditions, const wchar_t *name) noexcept;
        // Only return or delete filters that have provider's key.
        ResultXtun<std::vector<FilterInfo>> getInstalledFilters();
        libxtun_error deleteFilters();
        libxtun_error deleteFilters(const GUID &sublayer);
        libxtun_error cleanup();

    private:
        explicit WfpEngine(const WfpConfig config) : m_config(config) {}

        libxtun_error checkSublayer(bool allowMissing = false) noexcept;
        ResultXtun<std::vector<FilterInfo>> getInstalledFilters(const GUID &sublayer);

        HANDLE m_engine = nullptr;
        WfpConfig m_config;
    };
}
#endif


#include "wfp.h"
#include "util/result.h"
#include "xtun.h"

#include <fwpmtypes.h>
#include <winerror.h>

#include <memory>
#include <span>
#include <utility>
#include <vector>

namespace libxtun::wfp
{
    constexpr UINT32 ENUM_BATCH = 32;

    WfpEngine::Transaction::Transaction(WfpEngine &engine) noexcept : m_engine(engine.m_engine)
    {
        if (::FwpmTransactionBegin(m_engine, 0) != ERROR_SUCCESS) {
            m_engine = nullptr;
            m_status = LIBXTUN_ERR_SYSTEM;
        }
    }

    WfpEngine::Transaction::~Transaction()
    {
        if (m_engine != nullptr) {
            ::FwpmTransactionAbort(m_engine);
        }
    }

    libxtun_error WfpEngine::Transaction::commit() noexcept
    {
        if (m_engine == nullptr) {
            return LIBXTUN_ERR_SYSTEM;
        }

        HANDLE engine = std::exchange(m_engine, nullptr);
        if (::FwpmTransactionCommit(engine) != ERROR_SUCCESS) {
            ::FwpmTransactionAbort(engine);
            return LIBXTUN_ERR_SYSTEM;
        }

        return LIBXTUN_OK;
    }

    WfpEngine::~WfpEngine()
    {
        if (m_engine != nullptr) {
            ::FwpmEngineClose(m_engine);
        }
    }

    ResultXtun<std::unique_ptr<WfpEngine>> WfpEngine::open(const WfpConfig config)
    {
        std::unique_ptr<WfpEngine> self(new WfpEngine(config));
        FWPM_SESSION session {};
        session.flags = config.persistent ? 0 : FWPM_SESSION_FLAG_DYNAMIC;
        if (::FwpmEngineOpen(nullptr, RPC_C_AUTHN_WINNT, nullptr, &session, &self->m_engine) != ERROR_SUCCESS) {
            return fail(LIBXTUN_ERR_SYSTEM);
        }

        return std::move(self);
    }

    libxtun_error WfpEngine::addProvider() noexcept
    {
        FWPM_PROVIDER provider {};
        provider.providerKey = m_config.provider;
        provider.displayData.name = const_cast<wchar_t *>(m_config.providerName);
        provider.displayData.description = const_cast<wchar_t *>(m_config.providerDesc);

        const DWORD result = ::FwpmProviderAdd(m_engine, &provider, nullptr);
        if (result == FWP_E_ALREADY_EXISTS) {
            return LIBXTUN_OK;
        }
        if (result != ERROR_SUCCESS) {
            return LIBXTUN_ERR_SYSTEM;
        }

        return LIBXTUN_OK;
    }

    libxtun_error WfpEngine::addSublayer() noexcept
    {
        if (!m_config.ownsSublayer) {
            return LIBXTUN_OK;
        }

        FWPM_SUBLAYER sublayer {};
        sublayer.subLayerKey = m_config.sublayer;
        sublayer.providerKey = &m_config.provider;
        sublayer.displayData.name = const_cast<wchar_t *>(m_config.sublayerName);
        sublayer.displayData.description = const_cast<wchar_t *>(m_config.sublayerDesc);
        sublayer.weight = m_config.sublayerWeight;

        const DWORD result = ::FwpmSubLayerAdd(m_engine, &sublayer, nullptr);
        if (result == FWP_E_ALREADY_EXISTS) {
            return checkSublayer();
        }
        if (result != ERROR_SUCCESS) {
            return LIBXTUN_ERR_SYSTEM;
        }

        return LIBXTUN_OK;
    }

    libxtun_error WfpEngine::checkSublayer(bool allowMissing) noexcept
    {
        FWPM_SUBLAYER *rawSublayer = nullptr;
        const DWORD result = ::FwpmSubLayerGetByKey(m_engine, &m_config.sublayer, &rawSublayer);
        if (result == FWP_E_SUBLAYER_NOT_FOUND && allowMissing) {
            return LIBXTUN_OK;
        }
        if (result != ERROR_SUCCESS) {
            return LIBXTUN_ERR_SYSTEM;
        }
        const std::unique_ptr<FWPM_SUBLAYER, FwpmMemoryDeleter> sublayer(rawSublayer);

        // Check only the owner. The weight is not compared: when the requested weight is taken,
        // Windows stores another one, for example 0xFFFE instead of 0xFFFF.
        if (!sublayer->providerKey || !::IsEqualGUID(*sublayer->providerKey, m_config.provider)) {
            return LIBXTUN_ERR_SYSTEM;
        }
        return LIBXTUN_OK;
    }

    libxtun_error WfpEngine::addFilter(const GUID &layer, const FWP_ACTION_TYPE action, const UINT8 weight,
                                       std::span<FWPM_FILTER_CONDITION> conditions, const wchar_t *name) noexcept
    {
        FWPM_FILTER filter {};
        filter.layerKey = layer;
        filter.subLayerKey = m_config.sublayer;
        filter.providerKey = &m_config.provider;
        filter.displayData.name = const_cast<wchar_t *>(name);
        filter.action.type = action;
        filter.weight.type = FWP_UINT8;
        filter.weight.uint8 = weight;
        filter.numFilterConditions = static_cast<UINT32>(conditions.size());
        filter.filterCondition = conditions.data();

        if (::FwpmFilterAdd(m_engine, &filter, nullptr, nullptr) != ERROR_SUCCESS) {
            return LIBXTUN_ERR_SYSTEM;
        }

        return LIBXTUN_OK;
    }

    ResultXtun<std::vector<FilterInfo>> WfpEngine::getInstalledFilters()
    {
        return getInstalledFilters(m_config.sublayer);
    }

    ResultXtun<std::vector<FilterInfo>> WfpEngine::getInstalledFilters(const GUID &sublayer)
    {
        HANDLE enumHandle = nullptr;
        if (::FwpmFilterCreateEnumHandle(m_engine, nullptr, &enumHandle) != ERROR_SUCCESS) {
            return fail(LIBXTUN_ERR_SYSTEM);
        }

        std::vector<FilterInfo> filters;
        while (true) {
            FWPM_FILTER **rawEntries = nullptr;
            UINT32 returned = 0;
            if (::FwpmFilterEnum(m_engine, enumHandle, ENUM_BATCH, &rawEntries, &returned) != ERROR_SUCCESS) {
                ::FwpmFilterDestroyEnumHandle(m_engine, enumHandle);
                return fail(LIBXTUN_ERR_SYSTEM);
            }
            const std::unique_ptr<FWPM_FILTER *[], FwpmMemoryDeleter> entries(rawEntries);
            for (UINT32 at = 0; at < returned; ++at) {
                if (::IsEqualGUID(entries[at]->subLayerKey, sublayer) && entries[at]->providerKey
                    && ::IsEqualGUID(*entries[at]->providerKey, m_config.provider)) {
                    filters.push_back({ entries[at]->filterId, entries[at]->layerKey, entries[at]->action.type });
                }
            }
            if (returned < ENUM_BATCH) {
                break;
            }
        }
        ::FwpmFilterDestroyEnumHandle(m_engine, enumHandle);

        return filters;
    }

    libxtun_error WfpEngine::deleteFilters()
    {
        return deleteFilters(m_config.sublayer);
    }

    libxtun_error WfpEngine::deleteFilters(const GUID &sublayer)
    {
        const auto filters = getInstalledFilters(sublayer);
        if (!filters) {
            return filters.error();
        }

        for (const FilterInfo &filter : filters.value()) {
            const DWORD result = ::FwpmFilterDeleteById(m_engine, filter.id);
            if (result != ERROR_SUCCESS && result != FWP_E_FILTER_NOT_FOUND) {
                return LIBXTUN_ERR_SYSTEM;
            }
        }
        return LIBXTUN_OK;
    }

    libxtun_error WfpEngine::cleanup()
    {
        Transaction transaction(*this);
        if (transaction.status() != LIBXTUN_OK) {
            return transaction.status();
        }
        if (m_config.ownsSublayer) {
            if (const auto result = checkSublayer(true); result != LIBXTUN_OK) {
                return result;
            }
        }
        if (const auto result = deleteFilters(); result != LIBXTUN_OK) {
            return result;
        }
        if (m_config.ownsSublayer) {
            const DWORD result = ::FwpmSubLayerDeleteByKey(m_engine, &m_config.sublayer);
            // HARD filters or driver filters may still need this sublayer.
            if (result != ERROR_SUCCESS && result != FWP_E_SUBLAYER_NOT_FOUND && result != FWP_E_IN_USE) {
                return LIBXTUN_ERR_SYSTEM;
            }
        }
        const DWORD providerResult = ::FwpmProviderDeleteByKey(m_engine, &m_config.provider);
        if (providerResult != ERROR_SUCCESS && providerResult != FWP_E_PROVIDER_NOT_FOUND
            && providerResult != FWP_E_IN_USE) {
            return LIBXTUN_ERR_SYSTEM;
        }
        return transaction.commit();
    }
}

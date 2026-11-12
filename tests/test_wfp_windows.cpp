#include "net/wfp.h"
#include "util/os.h"
#include "util/random.h"

#include <gtest/gtest.h>

#include <memory>
#include <utility>

namespace
{
    using namespace libxtun;

    GUID nextGuid()
    {
        GUID key { libxtun::rand::next32(), libxtun::rand::next16(), libxtun::rand::next16(), {} };
        for (auto &byte : key.Data4) {
            byte = static_cast<BYTE>(libxtun::rand::next16());
        }
        return key;
    }

    class WfpOwnership : public testing::Test
    {
    protected:
        void SetUp() override
        {
            if (!test::privileged()) {
                GTEST_SKIP() << "WFP changes require Administrator";
            }

            // Use private keys so the tests do not touch xtun or driver rules.
            m_ownerConfig.provider = nextGuid();
            m_ownerConfig.providerName = L"xtun-test-owner";
            m_ownerConfig.providerDesc = L"xtun Test Owner";
            m_ownerConfig.sublayer = nextGuid();
            m_ownerConfig.sublayerName = L"xtun-test-sublayer";
            m_ownerConfig.sublayerDesc = L"xtun Test Sublayer";
            m_ownerConfig.sublayerWeight = 1;
            m_ownerConfig.persistent = true;

            auto ownerEngine = wfp::WfpEngine::open(m_ownerConfig);
            ASSERT_TRUE(ownerEngine);
            m_owner = std::move(ownerEngine).value();
            ASSERT_EQ(m_owner->addProvider(), LIBXTUN_OK);
            ASSERT_EQ(m_owner->addSublayer(), LIBXTUN_OK);

            m_borrowerConfig = m_ownerConfig;
            m_borrowerConfig.provider = nextGuid();
            m_borrowerConfig.providerName = L"xtun-test-borrower";
            m_borrowerConfig.providerDesc = L"xtun Test Borrower";
            m_borrowerConfig.persistent = true;
            m_borrowerConfig.ownsSublayer = false;
            auto borrowerEngine = wfp::WfpEngine::open(m_borrowerConfig);
            ASSERT_TRUE(borrowerEngine);
            m_borrower = std::move(borrowerEngine).value();
            ASSERT_EQ(m_borrower->addProvider(), LIBXTUN_OK);
            ASSERT_EQ(m_borrower->addSublayer(), LIBXTUN_OK);
        }

        void TearDown() override
        {
            if (m_borrower) {
                EXPECT_EQ(m_borrower->cleanup(), LIBXTUN_OK);
            }
            m_borrower.reset();
            if (m_owner) {
                EXPECT_EQ(m_owner->cleanup(), LIBXTUN_OK);
            }
        }

        wfp::WfpConfig m_ownerConfig {};
        wfp::WfpConfig m_borrowerConfig {};
        std::unique_ptr<wfp::WfpEngine> m_owner;
        std::unique_ptr<wfp::WfpEngine> m_borrower;
    };
}

TEST_F(WfpOwnership, DeleteFiltersKeepsAnotherProvidersFilters)
{
    ASSERT_EQ(m_owner->addFilter(FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWP_ACTION_PERMIT, 0, {}, L"Owner"), LIBXTUN_OK);
    ASSERT_EQ(m_borrower->addFilter(FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWP_ACTION_PERMIT, 0, {}, L"Borrower"), LIBXTUN_OK);
    ASSERT_EQ(m_owner->deleteFilters(), LIBXTUN_OK);

    const auto ownFilters = m_owner->getInstalledFilters();
    ASSERT_TRUE(ownFilters);
    EXPECT_TRUE(ownFilters.value().empty());
    const auto borrowedFilters = m_borrower->getInstalledFilters();
    ASSERT_TRUE(borrowedFilters);
    EXPECT_EQ(borrowedFilters.value().size(), 1u);
}

TEST_F(WfpOwnership, SharedSublayerSurvivesCleanup)
{
    ASSERT_EQ(m_borrower->cleanup(), LIBXTUN_OK);
    ASSERT_EQ(m_borrower->addProvider(), LIBXTUN_OK);
    EXPECT_EQ(m_borrower->addFilter(FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWP_ACTION_PERMIT, 0, {}, L"Borrower"), LIBXTUN_OK);
}

TEST_F(WfpOwnership, OwnerCleanupKeepsStaticFiltersAfterSessionClose)
{
    ASSERT_EQ(m_owner->addFilter(FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWP_ACTION_PERMIT, 0, {}, L"Owner"), LIBXTUN_OK);
    ASSERT_EQ(m_borrower->addFilter(FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWP_ACTION_PERMIT, 0, {}, L"Borrower"), LIBXTUN_OK);
    auto reopened = wfp::WfpEngine::open(m_borrowerConfig);
    ASSERT_TRUE(reopened);
    // Static filters stay after the session closes, as they do in HARD mode.
    m_borrower.reset();
    m_borrower = std::move(reopened).value();
    ASSERT_EQ(m_owner->cleanup(), LIBXTUN_OK);

    const auto ownFilters = m_owner->getInstalledFilters();
    ASSERT_TRUE(ownFilters);
    EXPECT_TRUE(ownFilters.value().empty());
    const auto borrowedFilters = m_borrower->getInstalledFilters();
    ASSERT_TRUE(borrowedFilters);
    EXPECT_EQ(borrowedFilters.value().size(), 1u);

    ASSERT_EQ(m_borrower->deleteFilters(), LIBXTUN_OK);
    ASSERT_EQ(m_owner->cleanup(), LIBXTUN_OK);
    EXPECT_NE(m_borrower->addFilter(FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWP_ACTION_PERMIT, 0, {}, L"Borrower"), LIBXTUN_OK);
}

TEST_F(WfpOwnership, ChecksSublayerOwnerNotWeight)
{
    auto config = m_ownerConfig;
    config.provider = m_borrowerConfig.provider;
    auto wrongOwner = wfp::WfpEngine::open(config);
    ASSERT_TRUE(wrongOwner);
    EXPECT_NE(wrongOwner.value()->addSublayer(), LIBXTUN_OK);

    // Windows can store another weight than the requested one, for example when that weight is taken.
    // So the same owner with another weight still owns the sublayer.
    config = m_ownerConfig;
    ++config.sublayerWeight;
    auto otherWeight = wfp::WfpEngine::open(config);
    ASSERT_TRUE(otherWeight);
    EXPECT_EQ(otherWeight.value()->addSublayer(), LIBXTUN_OK);
}

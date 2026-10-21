// Copyright (c) 2015-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <pow.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(pow_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(regtest_genesis_has_valid_scrypt_proof)
{
    const auto params = CreateChainParams(CBaseChainParams::REGTEST);
    const CBlock& genesis = params->GenesisBlock();
    BOOST_CHECK(CheckProofOfWork(genesis.GetPoWHash(), genesis.nBits, params->GetConsensus()));
    BOOST_CHECK(genesis.GetHash() == params->GetConsensus().hashGenesisBlock);
    BOOST_CHECK(params->Checkpoints().mapCheckpoints.at(0) == genesis.GetHash());
}

// These vectors exercise ScooterCoin's exponential retarget, not Bitcoin's
// historical linear 2016-block retarget. The compact targets below were also
// calculated independently with high-precision exp(p/q), including /16 truncation.
BOOST_AUTO_TEST_CASE(get_next_work)
{
    const auto params = CreateChainParams(CBaseChainParams::MAIN);
    CBlockIndex last;
    last.nHeight = 32255;
    last.nTime = 1000150;
    last.nBits = 0x1d00ffff;
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&last, 1000000, params->GetConsensus()), last.nBits);
}

BOOST_AUTO_TEST_CASE(get_next_work_pow_limit)
{
    const auto params = CreateChainParams(CBaseChainParams::MAIN);
    CBlockIndex last;
    last.nHeight = 2015;
    last.nTime = 1003000;
    last.nBits = UintToArith256(params->GetConsensus().powLimit).GetCompact();
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&last, 1000000, params->GetConsensus()), last.nBits);
}

BOOST_AUTO_TEST_CASE(get_next_work_lower_limit_actual)
{
    const auto params = CreateChainParams(CBaseChainParams::MAIN);
    CBlockIndex last;
    last.nHeight = 68543;
    last.nTime = 1000000;
    last.nBits = 0x1c05a3f4;
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&last, 1000000, params->GetConsensus()), 0x1c05a294U);
    // A negative interval falls back to nominal spacing, leaving work unchanged.
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&last, 1000001, params->GetConsensus()), last.nBits);
}

BOOST_AUTO_TEST_CASE(get_next_work_upper_limit_actual)
{
    const auto params = CreateChainParams(CBaseChainParams::MAIN);
    CBlockIndex last;
    last.nHeight = 46367;
    last.nBits = 0x1c387f6f;
    last.nTime = 1003000;
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&last, 1000000, params->GetConsensus()), 0x1c399250U);
    last.nTime = 2000000;
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&last, 1000000, params->GetConsensus()), 0x1c399250U);
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_negative_target)
{
    const auto consensus = CreateChainParams(CBaseChainParams::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    nBits = UintToArith256(consensus.powLimit).GetCompact(true);
    hash.SetHex("0x1");
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_overflow_target)
{
    const auto consensus = CreateChainParams(CBaseChainParams::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits = ~0x00800000;
    hash.SetHex("0x1");
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_too_easy_target)
{
    const auto consensus = CreateChainParams(CBaseChainParams::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    arith_uint256 nBits_arith = UintToArith256(consensus.powLimit);
    nBits_arith *= 2;
    nBits = nBits_arith.GetCompact();
    hash.SetHex("0x1");
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_biger_hash_than_target)
{
    const auto consensus = CreateChainParams(CBaseChainParams::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    arith_uint256 hash_arith = UintToArith256(consensus.powLimit);
    nBits = hash_arith.GetCompact();
    hash_arith *= 2; // hash > nBits
    hash = ArithToUint256(hash_arith);
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_zero_target)
{
    const auto consensus = CreateChainParams(CBaseChainParams::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    arith_uint256 hash_arith{0};
    nBits = hash_arith.GetCompact();
    hash = ArithToUint256(hash_arith);
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(GetBlockProofEquivalentTime_test)
{
    const auto chainParams = CreateChainParams(CBaseChainParams::MAIN);
    std::vector<CBlockIndex> blocks(10000);
    for (int i = 0; i < 10000; i++) {
        blocks[i].pprev = i ? &blocks[i - 1] : nullptr;
        blocks[i].nHeight = i;
        blocks[i].nTime = 1269211443 + i * chainParams->GetConsensus().nPowTargetSpacing;
        blocks[i].nBits = 0x207fffff; /* target 0x7fffff000... */
        blocks[i].nChainWork = i ? blocks[i - 1].nChainWork + GetBlockProof(blocks[i - 1]) : arith_uint256(0);
    }

    for (int j = 0; j < 1000; j++) {
        CBlockIndex *p1 = &blocks[InsecureRandRange(10000)];
        CBlockIndex *p2 = &blocks[InsecureRandRange(10000)];
        CBlockIndex *p3 = &blocks[InsecureRandRange(10000)];

        int64_t tdiff = GetBlockProofEquivalentTime(*p1, *p2, *p3, chainParams->GetConsensus());
        BOOST_CHECK_EQUAL(tdiff, p1->GetBlockTime() - p2->GetBlockTime());
    }
}

BOOST_AUTO_TEST_SUITE_END()

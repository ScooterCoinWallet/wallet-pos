// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>

#include <chainparamsseeds.h>
#include <consensus/merkle.h>
#include <consensus/consensus.h>
#include <tinyformat.h>
#include <util/system.h>
#include <util/strencodings.h>
#include <versionbitsinfo.h>

#include <assert.h>
#include <arith_uint256.h>


#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>


static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "CNN Money 20/Oct/2016 U.S. to Swiss banks: Please let Americans open accounts";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = CBaseChainParams::MAIN;
        consensus.nSubsidyHalvingInterval = 840000;
        consensus.BIP16Exception = uint256S("0x000002a62d284b34a40e18f27fc770bf26f7a61560ae6a072a2c95aabc60a129");
        consensus.BIP34Height = 100000;
        consensus.BIP34Hash = uint256S("0x50b182ccfd32f5797bfb4189dd478deddad7c5c2a90e85905749253bdd489212");
        consensus.BIP65Height = 100000;
        consensus.BIP66Height = 100000;
        consensus.CSVHeight = 1;
        consensus.SegwitHeight = 1;
        consensus.MinBIP9WarningHeight = consensus.SegwitHeight + consensus.nMinerConfirmationWindow;
        
        consensus.powLimit = uint256S("000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.posLimit = uint256S("000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 3.5 * 24 * 60 * 60; // 3.5 days (302400)
        consensus.nPowTargetSpacing = 2.5 * 60; // 2.5 minutes (150)
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.fPoSNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 432; // 75% of 576
        consensus.nMinerConfirmationWindow = 576; // 24*60/2,5
        consensus.nLastPOWBlock = 385021;
        consensus.nMPoSRewardRecipients = 10;
        consensus.nFirstMPoSBlock = consensus.nLastPOWBlock + 
                                    consensus.nMPoSRewardRecipients + 
                                    COINBASE_MATURITY;
        consensus.nEnableHeaderSignatureHeight = 0;
        consensus.nCheckpointSpan = COINBASE_MATURITY;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        consensus.SCOOTRewardMatchStep = 40000;
        consensus.SCOOTRewardMatchHeight = 3 * consensus.SCOOTRewardMatchStep;
        consensus.SCOOTDiffAdjHeight = 130000;


        // The best chain should have at least this much work.      
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000696b212c0ae1f46");      
        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x50b182ccfd32f5797bfb4189dd478deddad7c5c2a90e85905749253bdd489212"); //1683528

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xfb;
        pchMessageStart[1] = 0xc0;
        pchMessageStart[2] = 0xb6;
        pchMessageStart[3] = 0xdb;
        nDefaultPort = 25333;
        nPruneAfterHeight = 100000;
        m_assumed_blockchain_size = 22;
        m_assumed_chain_state_size = 3;


        genesis = CreateGenesisBlock(1477265354, 595800, 0x1e0ffff0, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0xd9bf94a4fa2d53855b3eb082446cda22c6f69f85895491b95dff7140ad3e621f"));
        assert(genesis.hashMerkleRoot == uint256S("0x4db42f7b571df82cc049231f8ac54100e0ba40b7dc9815e4870f52020975ba30"));

        // Note that of those which support the service bits prefix, most only support a subset of
        // possible options.
        // This is fine at runtime as we'll fall back to using them as a oneshot if they don't support the
        // service bits we want, but we should get them updated to support all service bits wanted by any
        // release ASAP to avoid it where possible.
        vSeeds.emplace_back("node01.scootercoin.org");
        vSeeds.emplace_back("node02.scootercoin.org");
        vSeeds.emplace_back("node03.scootercoin.org");
        vSeeds.emplace_back("node04.scootercoin.org");
        vSeeds.emplace_back("node05.scootercoin.org");
        vSeeds.emplace_back("node06.scootercoin.org");
        vSeeds.emplace_back("node07.scootercoin.org");
        vSeeds.emplace_back("node08.scootercoin.org");
        vSeeds.emplace_back("node09.scootercoin.org");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,48);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,176);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        bech32_hrp = "scoot";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        m_is_test_chain = false;
        m_is_mockable_chain = false;

        checkpointData = {
            {
                {     2, uint256S("0x8f51144692817d211813fe68844cde62cc1b1b4507d271549afd50db5c8f3347")},
                { 10000, uint256S("0xb0bf17503abdf0a1208b57bde9af93b978d8c26509742d25de099f2ecd247b88")},
                { 16150, uint256S("0x33eab32c1b4c6288094dd0c658129881c83184f51b66a5cb5c32c4830e1c2232")},
                { 22000, uint256S("0x81116ba5cbd399550169dbac5652893b3aa17fe2c2933b8f171ec0447524d067")},
                { 44000, uint256S("0x80d9b1c02b8721d1034a56d256610a6a6d783b51999ec85b6695a98a9c9fc9f0")},
                { 80000, uint256S("0xb6fe3b37a9725769619cabc5fa9111e0b0131046f9fc026d1cce174cecec6436")},
                {100000, uint256S("0x50b182ccfd32f5797bfb4189dd478deddad7c5c2a90e85905749253bdd489212")},
                {150000, uint256S("0x9fb2ea74f7ce5398f664a4936c8da72bc4f85c66f2cc3287ca4ab732d6fe29ed")},
                {200000, uint256S("0x0f3038be17422c0c25fbcbf79ca64adc7037e744bbd3410f92fd4e4bec0b24c0")},
                {250000, uint256S("0x79d7d7e2f6d5bf0875e083807f063c2ca0c4c42cbf1425fde4049524b8fe206f")},
                {300000, uint256S("0x8bb38b9a0f90c52f1eba0ecccf9dcd1834feefbc9c5fd114deb535fa8786c40e")},
                {320000, uint256S("0xd0b1b4d8af0045cf7baa1dae1d233a1b4bc1131b61f39aa482a69bd2e3fa2c19")},
                {330000, uint256S("0x94dee6208616969394ec5af3f5a7aec6990c9d95df04e1c734074878adfd2a2c")},
                {340000, uint256S("0xbc81582e434d0bf2360ab35abcccbcd0172bdb09a9e5aa5ec3fd6469fa3193c5")},
                {360000, uint256S("0xca3e15d6b371d5c1dcd4b5f59a2cd69788127c2227ddc0d0a8481de232285004")},
                {380000, uint256S("0x8a90991fc02d11f3fb0d18970848d7c58dd4cccd60592e926d643dafad6b0fe7")},
				{385000, uint256S("0x2cda800ab53f0f1ec8cf4ddc37ce548d62198e6910d349126f9125a19ccfba43")}
            }
        };

        chainTxData = ChainTxData{
            // Data from rpc: getchaintxstats 4096 8a90991fc02d11f3fb0d18970848d7c58dd4cccd60592e926d643dafad6b0fe7
            /* nTime    */ 1651276525,
            /* nTxCount */ 1327614,
            /* dTxRate  */ 0.03350167750212552
        };
    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = CBaseChainParams::TESTNET;
        consensus.nSubsidyHalvingInterval = 831600;
        consensus.BIP16Exception = uint256S("0x000002a62d284b34a40e18f27fc770bf26f7a61560ae6a072a2c95aabc60a129");
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256S("0x000002a62d284b34a40e18f27fc770bf26f7a61560ae6a072a2c95aabc60a129");
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 1;
        consensus.CSVHeight = 1;
        consensus.SegwitHeight = 1;
        consensus.MinBIP9WarningHeight = consensus.SegwitHeight + consensus.nMinerConfirmationWindow;
        consensus.SCOOTRewardMatchStep = 400;
        consensus.SCOOTRewardMatchHeight = 3 * consensus.SCOOTRewardMatchStep;
        consensus.SCOOTDiffAdjHeight = 1500;
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.posLimit = uint256S("0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 10 * 3 * 60; // every 10 blocks
        consensus.nPowTargetSpacing = 3 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.fPoSNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.nLastPOWBlock = 501;
        consensus.nMPoSRewardRecipients = 10;
        consensus.nFirstMPoSBlock = consensus.nLastPOWBlock + 
                                    consensus.nMPoSRewardRecipients + 
                                    COINBASE_MATURITY;
        consensus.nEnableHeaderSignatureHeight = 0;
        consensus.nCheckpointSpan = COINBASE_MATURITY;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000000000000");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x000002a62d284b34a40e18f27fc770bf26f7a61560ae6a072a2c95aabc60a129"); // 0

        pchMessageStart[0] = 0xC8;
        pchMessageStart[1] = 0xe6;
        pchMessageStart[2] = 0xc5;
        pchMessageStart[3] = 0x8c;
        nDefaultPort = 58932;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 40;
        m_assumed_chain_state_size = 2;

        genesis = CreateGenesisBlock(1596107187, 398386, 0x1e0fffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        //assert(consensus.hashGenesisBlock == uint256S("0x000002a62d284b34a40e18f27fc770bf26f7a61560ae6a072a2c95aabc60a129"));
        //assert(genesis.hashMerkleRoot == uint256S("0xfc44eaded503eb48afae3768f272d3ec731ada62b7aeb00d9636fdc73c5b7f98"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        vSeeds.emplace_back("testnet-seed1.scootercoin.org");
        vSeeds.emplace_back("testnet-seed2.scootercoin.org");
        vSeeds.emplace_back("testnet-seed3.scootercoin.org");
        vSeeds.emplace_back("testnet-seed4.scootercoin.org");
        vSeeds.emplace_back("testnet-seed5.tokl.io");
        vSeeds.emplace_back("testnet-seed6.tokl.io");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,65);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,127);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,130);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "lt";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        m_is_test_chain = true;
        m_is_mockable_chain = false;

        checkpointData = {
            {
                {0, uint256S("0x000002a62d284b34a40e18f27fc770bf26f7a61560ae6a072a2c95aabc60a129")},
            }
        };

        chainTxData = ChainTxData{
            // Data from RPC: getchaintxstats 4096 00000000000000b7ab6ce61eb6d571003fbe5fe892da4c9b740c49a07542462d
            /* nTime    */ 1588417200,
            /* nTxCount */ 0,
            /* dTxRate  */ 0.0,
        };
    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    explicit CRegTestParams(const ArgsManager& args) {
        strNetworkID =  CBaseChainParams::REGTEST;
        consensus.nSubsidyHalvingInterval = 150;
        consensus.BIP16Exception = uint256();
        consensus.BIP34Height = 500; // BIP34 activated on regtest (Used in functional tests)
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1351; // BIP65 activated on regtest (Used in functional tests)
        consensus.BIP66Height = 1251; // BIP66 activated on regtest (Used in functional tests)
        consensus.CSVHeight = 432; // CSV activated on regtest (Used in rpc activation tests)
        consensus.SegwitHeight = 0; // SEGWIT is always activated on regtest unless overridden
        consensus.MinBIP9WarningHeight = 0;
        consensus.SCOOTRewardMatchStep = 400;
        consensus.SCOOTRewardMatchHeight = 3 * consensus.SCOOTRewardMatchStep;
        consensus.SCOOTDiffAdjHeight = 1500;
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.posLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 10 * 3 * 60; // every 10 blocks
        consensus.nPowTargetSpacing = 3 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.fPoSNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.nLastPOWBlock = 0x7fffffff;
        consensus.nMPoSRewardRecipients = 10;
        consensus.nFirstMPoSBlock = 5000;
        consensus.nEnableHeaderSignatureHeight = 0;
        consensus.nCheckpointSpan = COINBASE_MATURITY;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        pchMessageStart[0] = 0xf1;
        pchMessageStart[1] = 0xed;
        pchMessageStart[2] = 0x86;
        pchMessageStart[3] = 0xc2;
        nDefaultPort = 58934;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        UpdateActivationParametersFromArgs(args);

        genesis = CreateGenesisBlock(1596107187, 398386, 0x1e0fffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        //assert(consensus.hashGenesisBlock == uint256S("0x000002a62d284b34a40e18f27fc770bf26f7a61560ae6a072a2c95aabc60a129"));
        //assert(genesis.hashMerkleRoot == uint256S("0xfc44eaded503eb48afae3768f272d3ec731ada62b7aeb00d9636fdc73c5b7f98"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = true;
        m_is_test_chain = true;
        m_is_mockable_chain = true;

        checkpointData = {
            {
                {0, uint256S("0x2b8d445931aa4ea9b52db1488d3641fa2d4f7a3c1f8151bfa99d017493129e97")},
            }
        };

        chainTxData = ChainTxData{
           1588417200,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,65);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,78);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,130);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "lpt";
    }

    /**
     * Allows modifying the Version Bits regtest parameters.
     */
    void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
    {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
    }
    void UpdateActivationParametersFromArgs(const ArgsManager& args);
};

void CRegTestParams::UpdateActivationParametersFromArgs(const ArgsManager& args)
{
    if (gArgs.IsArgSet("-segwitheight")) {
        int64_t height = gArgs.GetArg("-segwitheight", consensus.SegwitHeight);
        if (height < -1 || height >= std::numeric_limits<int>::max()) {
            throw std::runtime_error(strprintf("Activation height %ld for segwit is out of valid range. Use -1 to disable segwit.", height));
        } else if (height == -1) {
            LogPrintf("Segwit disabled for testing\n");
            height = std::numeric_limits<int>::max();
        }
        consensus.SegwitHeight = static_cast<int>(height);
    }

    if (!args.IsArgSet("-vbparams")) return;

    for (const std::string& strDeployment : args.GetArgs("-vbparams")) {
        std::vector<std::string> vDeploymentParams;
        boost::split(vDeploymentParams, strDeployment, boost::is_any_of(":"));
        if (vDeploymentParams.size() != 3) {
            throw std::runtime_error("Version bits parameters malformed, expecting deployment:start:end");
        }
        int64_t nStartTime, nTimeout;
        if (!ParseInt64(vDeploymentParams[1], &nStartTime)) {
            throw std::runtime_error(strprintf("Invalid nStartTime (%s)", vDeploymentParams[1]));
        }
        if (!ParseInt64(vDeploymentParams[2], &nTimeout)) {
            throw std::runtime_error(strprintf("Invalid nTimeout (%s)", vDeploymentParams[2]));
        }
        bool found = false;
        for (int j=0; j < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; ++j) {
            if (vDeploymentParams[0] == VersionBitsDeploymentInfo[j].name) {
                UpdateVersionBitsParameters(Consensus::DeploymentPos(j), nStartTime, nTimeout);
                found = true;
                LogPrintf("Setting version bits activation parameters for %s to start=%ld, timeout=%ld\n", vDeploymentParams[0], nStartTime, nTimeout);
                break;
            }
        }
        if (!found) {
            throw std::runtime_error(strprintf("Invalid deployment (%s)", vDeploymentParams[0]));
        }
    }
}

static std::unique_ptr<const CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<const CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CChainParams>(new CRegTestParams(gArgs));
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}

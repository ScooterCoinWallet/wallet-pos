// Copyright (c) 2018-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>
#include <atomic>

#include <chainparams.h>
#include <consensus/merkle.h>
#include <consensus/validation.h>
#include <miner.h>
#include <pow.h>
#include <random.h>
#include <script/standard.h>
#include <test/util/setup_common.h>
#include <util/time.h>
#include <validation.h>
#include <validationinterface.h>

#include <thread>

static const std::vector<unsigned char> V_OP_TRUE{OP_TRUE};

namespace validation_block_tests {
struct MinerTestingSetup : public RegTestingSetup {
    std::shared_ptr<CBlock> Block(const uint256& prev_hash);
    std::shared_ptr<const CBlock> GoodBlock(const uint256& prev_hash);
    std::shared_ptr<const CBlock> BadBlock(const uint256& prev_hash);
    std::shared_ptr<CBlock> FinalizeBlock(std::shared_ptr<CBlock> pblock);
    void BuildChain(const uint256& root, int height, const unsigned int invalid_rate, const unsigned int branch_rate, const unsigned int max_size, std::vector<std::shared_ptr<const CBlock>>& blocks);
};
} // namespace validation_block_tests

BOOST_FIXTURE_TEST_SUITE(validation_block_tests, MinerTestingSetup)

struct TestSubscriber final : public CValidationInterface {
    uint256 m_expected_tip;

    explicit TestSubscriber(uint256 tip) : m_expected_tip(tip) {}

    void UpdatedBlockTip(const CBlockIndex* pindexNew, const CBlockIndex* pindexFork, bool fInitialDownload) override
    {
        BOOST_CHECK_EQUAL(m_expected_tip, pindexNew->GetBlockHash());
    }

    void BlockConnected(const std::shared_ptr<const CBlock>& block, const CBlockIndex* pindex) override
    {
        BOOST_CHECK_EQUAL(m_expected_tip, block->hashPrevBlock);
        BOOST_CHECK_EQUAL(m_expected_tip, pindex->pprev->GetBlockHash());

        m_expected_tip = block->GetHash();
    }

    void BlockDisconnected(const std::shared_ptr<const CBlock>& block, const CBlockIndex* pindex) override
    {
        BOOST_CHECK_EQUAL(m_expected_tip, block->GetHash());
        BOOST_CHECK_EQUAL(m_expected_tip, pindex->GetBlockHash());

        m_expected_tip = block->hashPrevBlock;
    }
};

std::shared_ptr<CBlock> MinerTestingSetup::Block(const uint256& prev_hash)
{
    static int i = 0;
    static uint64_t time = Params().GenesisBlock().nTime;

    CScript pubKey;
    pubKey << i++ << OP_TRUE;

    auto ptemplate = BlockAssembler(*m_node.mempool, Params()).CreateNewBlock(pubKey);
    auto pblock = std::make_shared<CBlock>(ptemplate->block);
    pblock->hashPrevBlock = prev_hash;
    pblock->nTime = ++time;

    pubKey.clear();
    {
        WitnessV0ScriptHash witness_program;
        CSHA256().Write(&V_OP_TRUE[0], V_OP_TRUE.size()).Finalize(witness_program.begin());
        pubKey << OP_0 << ToByteVector(witness_program);
    }

    // Make the coinbase transaction with two outputs:
    // One zero-value one that has a unique pubkey to make sure that blocks at the same height can have a different hash
    // Another one that has the coinbase reward in a P2WSH with OP_TRUE as witness program to make it easy to spend
    CMutableTransaction txCoinbase(*pblock->vtx[0]);
    txCoinbase.vout.resize(2);
    txCoinbase.vout[1].scriptPubKey = pubKey;
    txCoinbase.vout[1].nValue = txCoinbase.vout[0].nValue;
    txCoinbase.vout[0].nValue = 0;
    txCoinbase.vin[0].scriptWitness.SetNull();
    pblock->vtx[0] = MakeTransactionRef(std::move(txCoinbase));

    return pblock;
}

std::shared_ptr<CBlock> MinerTestingSetup::FinalizeBlock(std::shared_ptr<CBlock> pblock)
{
    LOCK(cs_main); // For LookupBlockIndex
    GenerateCoinbaseCommitment(*pblock, LookupBlockIndex(pblock->hashPrevBlock), Params().GetConsensus());

    pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);

    while (!CheckProofOfWork(pblock->GetPoWHash(), pblock->nBits, Params().GetConsensus())) {
        ++(pblock->nNonce);
    }

    return pblock;
}

// construct a valid block
std::shared_ptr<const CBlock> MinerTestingSetup::GoodBlock(const uint256& prev_hash)
{
    return FinalizeBlock(Block(prev_hash));
}

// construct an invalid block (but with a valid header)
std::shared_ptr<const CBlock> MinerTestingSetup::BadBlock(const uint256& prev_hash)
{
    auto pblock = Block(prev_hash);

    CMutableTransaction coinbase_spend;
    coinbase_spend.vin.push_back(CTxIn(COutPoint(pblock->vtx[0]->GetHash(), 0), CScript(), 0));
    coinbase_spend.vout.push_back(pblock->vtx[0]->vout[0]);

    CTransactionRef tx = MakeTransactionRef(coinbase_spend);
    pblock->vtx.push_back(tx);

    auto ret = FinalizeBlock(pblock);
    return ret;
}

void MinerTestingSetup::BuildChain(const uint256& root, int height, const unsigned int invalid_rate, const unsigned int branch_rate, const unsigned int max_size, std::vector<std::shared_ptr<const CBlock>>& blocks)
{
    if (height <= 0 || blocks.size() >= max_size) return;

    bool gen_invalid = InsecureRandRange(100) < invalid_rate;
    bool gen_fork = InsecureRandRange(100) < branch_rate;

    const std::shared_ptr<const CBlock> pblock = gen_invalid ? BadBlock(root) : GoodBlock(root);
    blocks.push_back(pblock);
    if (!gen_invalid) {
        BuildChain(pblock->GetHash(), height - 1, invalid_rate, branch_rate, max_size, blocks);
    }

    if (gen_fork) {
        blocks.push_back(GoodBlock(root));
        BuildChain(blocks.back()->GetHash(), height - 1, invalid_rate, branch_rate, max_size, blocks);
    }
}

BOOST_AUTO_TEST_CASE(processnewblock_signals_ordering)
{
    // build a large-ish chain that's likely to have some forks
    std::vector<std::shared_ptr<const CBlock>> blocks;
    while (blocks.size() < 50) {
        blocks.clear();
        BuildChain(Params().GenesisBlock().GetHash(), 100, 15, 10, 500, blocks);
    }

    bool ignored;
    BlockValidationState state;
    std::vector<CBlockHeader> headers;
    std::transform(blocks.begin(), blocks.end(), std::back_inserter(headers), [](std::shared_ptr<const CBlock> b) { return b->GetBlockHeader(); });

    // Process all the headers so we understand the toplogy of the chain
    BOOST_CHECK(ProcessNewBlockHeaders(headers, state, Params()));

    // Connect the genesis block and drain any outstanding events
    BOOST_CHECK(ProcessNewBlock(Params(), std::make_shared<CBlock>(Params().GenesisBlock()), true, &ignored));
    SyncWithValidationInterfaceQueue();

    // subscribe to events (this subscriber will validate event ordering)
    const CBlockIndex* initial_tip = nullptr;
    {
        LOCK(cs_main);
        initial_tip = ::ChainActive().Tip();
    }
    auto sub = std::make_shared<TestSubscriber>(initial_tip->GetBlockHash());
    RegisterSharedValidationInterface(sub);

    // create a bunch of threads that repeatedly process a block generated above at random
    // this will create parallelism and randomness inside validation - the ValidationInterface
    // will subscribe to events generated during block validation and assert on ordering invariance
    std::vector<std::thread> threads;
    for (int i = 0; i < 10; i++) {
        threads.emplace_back([&blocks]() {
            bool ignored;
            FastRandomContext insecure;
            for (int i = 0; i < 1000; i++) {
                auto block = blocks[insecure.randrange(blocks.size() - 1)];
                ProcessNewBlock(Params(), block, true, &ignored);
            }

            // to make sure that eventually we process the full chain - do it here
            for (auto block : blocks) {
                if (block->vtx.size() == 1) {
                    bool processed = ProcessNewBlock(Params(), block, true, &ignored);
                    assert(processed);
                }
            }
        });
    }

    for (auto& t : threads) {
        t.join();
    }
    while (GetMainSignals().CallbacksPending() > 0) {
        UninterruptibleSleep(std::chrono::milliseconds{100});
    }

    UnregisterSharedValidationInterface(sub);

    LOCK(cs_main);
    BOOST_CHECK_EQUAL(sub->m_expected_tip, ::ChainActive().Tip()->GetBlockHash());
}

/**
 * Test that mempool updates happen atomically with reorgs.
 *
 * This prevents RPC clients, among others, from retrieving immediately-out-of-date mempool data
 * during large reorgs.
 *
 * The test verifies this by creating a chain of `num_txs` blocks, matures their coinbases, and then
 * submits dependent txns to the mempool. A shallow conflicting fork is then processed,
 * invalidating the txns and evicting them from the mempool.
 *
 * We verify that the mempool updates atomically by polling it continuously
 * from another thread during the reorg and checking that its size only changes
 * once. The size changing exactly once indicates that the polling thread's
 * view of the mempool is either consistent with the chain state before reorg,
 * or consistent with the chain state after the reorg, and not just consistent
 * with some intermediate state during the reorg.
 */
BOOST_AUTO_TEST_CASE(mempool_locks_reorg)
{
    bool ignored;
    auto ProcessBlock = [&ignored](std::shared_ptr<const CBlock> block) -> bool {
        return ProcessNewBlock(Params(), block, true, &ignored);
    };
    BOOST_REQUIRE(ProcessBlock(std::make_shared<CBlock>(Params().GenesisBlock())));

    // Mature three independent funding coins before the fork. ScooterCoin's
    // sync-checkpoint rule intentionally forbids a 100+ block coinbase reorg.
    std::vector<CTransactionRef> funding_coins;
    auto tip = Params().GenesisBlock().GetHash();
    for (int height = 1; height <= COINBASE_MATURITY + 3; ++height) {
        const auto block = GoodBlock(tip);
        BOOST_REQUIRE(ProcessBlock(block));
        if (height <= 3) funding_coins.push_back(block->vtx[0]);
        tip = block->GetHash();
    }

    for (const auto& coinbase : funding_coins) {
        const uint256 split_hash = tip;
        CMutableTransaction funding;
        funding.vin.emplace_back(COutPoint{coinbase->GetHash(), 1}, CScript{});
        funding.vin[0].scriptWitness.stack.push_back(V_OP_TRUE);
        CTxOut output = coinbase->vout[1];
        output.nValue = output.nValue / 22 - 1000;
        funding.vout.assign(22, output);
        const auto funding_tx = MakeTransactionRef(funding);
        auto funded_block = Block(split_hash);
        funded_block->vtx.push_back(funding_tx);
        const auto main_block = FinalizeBlock(funded_block);
        BOOST_REQUIRE(ProcessBlock(main_block));
        constexpr size_t reorg_depth = 12;
        std::shared_ptr<const CBlock> main_tip = main_block;
        for (size_t depth = 1; depth < reorg_depth; ++depth) {
            main_tip = GoodBlock(main_tip->GetHash());
            BOOST_REQUIRE(ProcessBlock(main_tip));
        }
        const uint256 tip_init = main_tip->GetHash();

        std::vector<CTransactionRef> txs;
        for (unsigned int index = 0; index < funding.vout.size(); ++index) {
            CMutableTransaction spending;
            spending.vin.emplace_back(COutPoint{funding_tx->GetHash(), index}, CScript{});
            spending.vin[0].scriptWitness.stack.push_back(V_OP_TRUE);
            spending.vout.push_back(output);
            spending.vout[0].nValue -= 1000;
            txs.push_back(MakeTransactionRef(spending));
        }

        // A bounded multi-block fork spends the same mature input elsewhere.
        // All 22 dependent mempool transactions must disappear atomically.
        CMutableTransaction conflict = funding;
        conflict.vout.resize(1);
        conflict.vout[0].nValue = coinbase->vout[1].nValue - 1000;
        auto fork_block = Block(split_hash);
        fork_block->vtx.push_back(MakeTransactionRef(conflict));
        const auto fork_first = FinalizeBlock(fork_block);
        std::vector<std::shared_ptr<const CBlock>> fork_blocks{fork_first};
        while (fork_blocks.size() <= reorg_depth) {
            fork_blocks.push_back(GoodBlock(fork_blocks.back()->GetHash()));
        }
        const auto fork_tip = fork_blocks.back();
        {
            LOCK(cs_main);
            TxValidationState state;
            std::list<CTransactionRef> replaced;
            for (const auto& tx : txs) {
                BOOST_REQUIRE(AcceptToMemoryPool(*m_node.mempool, state, tx, &replaced, false, 0));
            }
        }
        {
            LOCK(m_node.mempool->cs);
            BOOST_REQUIRE_EQUAL(m_node.mempool->mapTx.size(), txs.size());
        }
        std::atomic<bool> processing_done{false};
        std::atomic<bool> observer_ready{false};
        std::thread rpc_thread{[&]() {
            bool saw_empty = false;
            while (!processing_done.load()) {
                LOCK(m_node.mempool->cs);
                const auto size = m_node.mempool->mapTx.size();
                assert(size == 0 || size == txs.size());
                observer_ready = true;
                if (size == 0) {
                    saw_empty = true;
                    break;
                }
            }
            if (saw_empty) {
                LOCK(cs_main);
                assert(tip_init != ::ChainActive().Tip()->GetBlockHash());
            }
        }};
        while (!observer_ready.load()) std::this_thread::yield();
        for (const auto& block : fork_blocks) BOOST_CHECK(ProcessBlock(block));
        processing_done = true;
        rpc_thread.join(); // A failed fork must report failure rather than hang forever.
        BOOST_CHECK_EQUAL(fork_tip->GetHash(), ::ChainActive().Tip()->GetBlockHash());
        BOOST_CHECK(tip_init != ::ChainActive().Tip()->GetBlockHash());
        {
            LOCK(m_node.mempool->cs);
            BOOST_CHECK_EQUAL(m_node.mempool->mapTx.size(), 0U);
        }
        tip = fork_tip->GetHash();
    }
}
BOOST_AUTO_TEST_SUITE_END()

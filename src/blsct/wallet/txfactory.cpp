// Copyright (c) 2023 The Navcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/wallet/txfactory.h>
#include <wallet/fees.h>

using T = Mcl;
using Point = T::Point;
using Points = Elements<Point>;
using Scalar = T::Scalar;
using Scalars = Elements<Scalar>;

namespace blsct {

void TxFactoryBase::AddOutput(const SubAddress& destination, const CAmount& nAmount, std::string sMemo, const TokenId& tokenId, const CreateOutputType& type, const CAmount& minStake)
{
    UnsignedOutput out;
    out = CreateOutput(destination.GetKeys(), nAmount, sMemo, tokenId, Scalar::Rand(), type, minStake);

    if (nAmounts.count(tokenId) == 0)
        nAmounts[tokenId] = {0, 0};

    nAmounts[tokenId].nFromOutputs += nAmount;

    if (vOutputs.count(tokenId) == 0)
        vOutputs[tokenId] = std::vector<UnsignedOutput>();

    vOutputs[tokenId].push_back(out);
}

bool TxFactoryBase::AddInput(const CAmount& amount, const MclScalar& gamma, const PrivateKey& spendingKey, const TokenId& tokenId, const COutPoint& outpoint, const bool& rbf)
{
    if (vInputs.count(tokenId) == 0)
        vInputs[tokenId] = std::vector<UnsignedInput>();

    vInputs[tokenId].push_back({CTxIn(outpoint, CScript(), rbf ? MAX_BIP125_RBF_SEQUENCE : CTxIn::SEQUENCE_FINAL), amount, gamma, spendingKey});

    if (nAmounts.count(tokenId) == 0)
        nAmounts[tokenId] = {0, 0};

    nAmounts[tokenId].nFromInputs += amount;

    return true;
}

std::optional<CMutableTransaction>
TxFactoryBase::BuildTx(const blsct::DoublePublicKey& changeDestination)
{
    CAmount nFee = BLSCT_DEFAULT_FEE * (vInputs.size() + vOutputs.size() + 1);

    while (true) {
        CMutableTransaction tx;
        tx.nVersion |= CTransaction::BLSCT_MARKER;

        Scalar gammaAcc;
        std::map<TokenId, CAmount> mapChange;
        std::vector<Signature> txSigs;

        for (auto& amounts : nAmounts) {
            if (amounts.second.nFromInputs < amounts.second.nFromOutputs)
                return std::nullopt;
            mapChange[amounts.first] = amounts.second.nFromInputs - amounts.second.nFromOutputs - nFee;
        }

        for (auto& in_ : vInputs) {
            for (auto& in : in_.second) {
                tx.vin.push_back(in.in);
                gammaAcc = gammaAcc + in.gamma;
                txSigs.push_back(in.sk.Sign(in.in.GetHash()));
            }
        }

        for (auto& out_ : vOutputs) {
            for (auto& out : out_.second) {
                tx.vout.push_back(out.out);
                gammaAcc = gammaAcc - out.gamma;
                txSigs.push_back(PrivateKey(out.blindingKey).Sign(out.out.GetHash()));
            }
        }

        for (auto& change : mapChange) {
            auto changeOutput = CreateOutput(changeDestination, change.second, "Change", change.first);
            tx.vout.push_back(changeOutput.out);
            gammaAcc = gammaAcc - changeOutput.gamma;
            txSigs.push_back(PrivateKey(changeOutput.blindingKey).Sign(changeOutput.out.GetHash()));
        }

        if (nFee == (long long)(BLSCT_DEFAULT_FEE * (tx.vin.size() + tx.vout.size()))) {
            CTxOut fee_out{nFee, CScript(OP_RETURN)};
            tx.vout.push_back(fee_out);
            txSigs.push_back(PrivateKey(gammaAcc).SignBalance());
            tx.txSig = Signature::Aggregate(txSigs);
            return tx;
        }

        nFee = BLSCT_DEFAULT_FEE * (tx.vin.size() + tx.vout.size());
    }

    return std::nullopt;
}

std::optional<CMutableTransaction> TxFactoryBase::CreateTransaction(const std::vector<InputCandidates>& inputCandidates, const blsct::DoublePublicKey& changeDestination, const SubAddress& destination, const CAmount& nAmount, std::string sMemo, const TokenId& tokenId, const CreateOutputType& type, const CAmount& minStake)
{
    auto tx = blsct::TxFactoryBase();

    for (const auto& output : inputCandidates) {
        tx.AddInput(output.amount, output.gamma, output.spendingKey, output.tokenId, COutPoint(output.outpoint.hash, output.outpoint.n));

        if (tx.nAmounts[tokenId].nFromInputs > nAmount + (long long)(BLSCT_DEFAULT_FEE * (tx.vInputs.size() + 3))) break;
    }

    tx.AddOutput(destination, nAmount, sMemo, tokenId, type, minStake);

    return tx.BuildTx(changeDestination);
}

bool TxFactory::AddInput(const CCoinsViewCache& cache, const COutPoint& outpoint, const bool& rbf)
{
    Coin coin;

    if (!cache.GetCoin(outpoint, coin))
        return false;

    auto recoveredInfo = km->RecoverOutputs(std::vector<CTxOut>{coin.out});

    if (!recoveredInfo.run_to_completion)
        return false;

    if (vInputs.count(coin.out.tokenId) == 0)
        vInputs[coin.out.tokenId] = std::vector<UnsignedInput>();

    vInputs[coin.out.tokenId].push_back({CTxIn(outpoint, CScript(), rbf ? MAX_BIP125_RBF_SEQUENCE : CTxIn::SEQUENCE_FINAL), recoveredInfo.successful_results[0].amount, recoveredInfo.successful_results[0].gamma, km->GetSpendingKeyForOutput(coin.out)});

    if (nAmounts.count(coin.out.tokenId) == 0)
        nAmounts[coin.out.tokenId] = {0, 0};

    nAmounts[coin.out.tokenId].nFromInputs += recoveredInfo.successful_results[0].amount;

    return true;
}

bool TxFactory::AddInput(wallet::CWallet* wallet, const COutPoint& outpoint, const bool& rbf)
{
    AssertLockHeld(wallet->cs_wallet);

    auto tx = wallet->GetWalletTx(outpoint.hash);

    if (tx == nullptr)
        return false;

    auto out = tx->tx->vout[outpoint.n];

    if (vInputs.count(out.tokenId) == 0)
        vInputs[out.tokenId] = std::vector<UnsignedInput>();

    auto recoveredInfo = tx->GetBLSCTRecoveryData(outpoint.n);

    vInputs[out.tokenId].push_back({CTxIn(outpoint, CScript(), rbf ? MAX_BIP125_RBF_SEQUENCE : CTxIn::SEQUENCE_FINAL), recoveredInfo.amount, recoveredInfo.gamma, km->GetSpendingKeyForOutput(out)});

    if (nAmounts.count(out.tokenId) == 0)
        nAmounts[out.tokenId] = {0, 0};

    nAmounts[out.tokenId].nFromInputs += recoveredInfo.amount;

    return true;
}

std::optional<CMutableTransaction>
TxFactory::BuildTx()
{
    return TxFactoryBase::BuildTx(std::get<blsct::DoublePublicKey>(km->GetNewDestination(-1).value()));
}

std::optional<CMutableTransaction> TxFactory::CreateTransaction(wallet::CWallet* wallet, blsct::KeyMan* blsct_km, const SubAddress& destination, const CAmount& nAmount, std::string sMemo, const TokenId& tokenId, const CreateOutputType& type, const CAmount& minStake)
{
    LOCK(wallet->cs_wallet);

    wallet::CoinFilterParams coins_params;
    coins_params.min_amount = 0;
    coins_params.only_blsct = true;
    coins_params.token_id = tokenId;

    std::vector<InputCandidates> inputCandidates;

    for (const wallet::COutput& output : AvailableCoins(*wallet, nullptr, std::nullopt, coins_params).All()) {
        auto tx = wallet->GetWalletTx(output.outpoint.hash);

        if (tx == nullptr)
            continue;

        auto out = tx->tx->vout[output.outpoint.n];

        auto recoveredInfo = tx->GetBLSCTRecoveryData(output.outpoint.n);
        inputCandidates.push_back({recoveredInfo.amount, recoveredInfo.gamma, blsct_km->GetSpendingKeyForOutput(out), out.tokenId, COutPoint(output.outpoint.hash, output.outpoint.n)});
    }

    return TxFactoryBase::CreateTransaction(inputCandidates, std::get<blsct::DoublePublicKey>(blsct_km->GetNewDestination(-1).value()), destination, nAmount, sMemo, tokenId, type, minStake);
}

} // namespace blsct

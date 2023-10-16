// Copyright (c) 2023 The Navcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/wallet/verification.h>

namespace blsct {
bool VerifyTx(const CTransaction& tx, const CCoinsViewCache& view)
{
    if (!view.HaveInputs(tx)) {
        std::cout << "Unknown inputs\n";
        return false;
    }

    std::vector<Message> vMessages;
    std::vector<PublicKey> vPubKeys;
    MclG1Point balanceKey;

    for (auto& in : tx.vin) {
        Coin coin;

        if (!view.GetCoin(in.prevout, coin)) {
            std::cout << "Unknown input\n";
            return false;
        }

        vPubKeys.push_back(coin.out.blsctData.spendingKey);
        auto in_hash = in.GetHash();
        vMessages.push_back(Message(in_hash.begin(), in_hash.end()));
        balanceKey = balanceKey + coin.out.blsctData.rangeProof.Vs[0];
    }

    for (auto& out : tx.vout) {
        vPubKeys.push_back(out.blsctData.ephemeralKey);
        auto out_hash = out.GetHash();
        vMessages.push_back(Message(out_hash.begin(), out_hash.end()));

        if (out.IsBLSCT()) {
            balanceKey = balanceKey - out.blsctData.rangeProof.Vs[0];
        } else {
            range_proof::GeneratorsFactory<Mcl> gf;

            TokenId token_id;
            range_proof::Generators<Mcl> gen = gf.GetInstance(token_id);
            balanceKey = balanceKey - (gen.G * MclScalar(out.nValue));
        }
    }

    vMessages.push_back(blsct::Common::BLSCTBALANCE);
    vPubKeys.push_back(balanceKey);

    return PublicKeys{vPubKeys}.VerifyBatch(vMessages, tx.txSig, true);
}
} // namespace blsct
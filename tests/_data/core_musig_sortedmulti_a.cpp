// Copyright (c) The btclib developers
// Distributed under the MIT software license, see the accompanying
// LICENSE file or https://opensource.org/license/mit for the full text.

// Writes tests/_data/core_musig_sortedmulti_a.json from Bitcoin Core.
// Appended to Core's src/test/descriptor_tests.cpp and run by test_bitcoin,
// as tests/_data/README.md says. It is not part of this package's suite.

#include <key.h>
#include <key_io.h>
#include <script/descriptor.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <cstddef>
#include <iostream>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(core_musig_sortedmulti_a, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(write_vectors)
{
    // Key i (1 to 6) is the account xpub at m/48h/0h/0h/2h of the seed of
    // 32 bytes all equal to i, with its key origin.
    std::vector<std::string> keys;
    for (int i{1}; i <= 6; ++i) {
        const std::vector<std::byte> seed(32, std::byte(i));
        CExtKey master;
        master.SetSeed(seed);
        CExtKey account{master};
        for (const uint32_t step : {48u, 0u, 0u, 2u}) {
            BOOST_REQUIRE(account.Derive(account, step | 0x80000000u));
        }
        const CKeyID id{master.key.GetPubKey().GetID()};
        const std::string fingerprint{HexStr(std::span{id.begin(), 4})};
        keys.push_back("[" + fingerprint + "/48h/0h/0h/2h]" + EncodeExtPubKey(account.Neuter()));
    }

    // The string bitcoin/bitcoin#36143's CreateMultisigDescriptor assembles
    // for BECH32M, for the first n keys and each threshold k.
    const std::string suffix{"/<0;1>/*"};
    UniValue cases{UniValue::VARR};
    for (size_t n{2}; n <= keys.size(); ++n) {
        std::string aggregate{"musig("};
        std::string leaf;
        for (size_t i{0}; i < n; ++i) {
            aggregate += (i ? "," : "") + keys[i];
            leaf += "," + keys[i] + suffix;
        }
        aggregate += ")" + suffix;
        for (size_t k{1}; k <= n; ++k) {
            const std::string body{"tr(" + aggregate + ",sortedmulti_a(" + std::to_string(k) + leaf + "))"};
            const std::string descriptor{body + "#" + GetDescriptorChecksum(body)};
            FlatSigningProvider provider;
            std::string error;
            const auto parsed{Parse(descriptor, provider, error, /*require_checksum=*/true)};
            BOOST_REQUIRE_MESSAGE(parsed.size() == 2, error);
            UniValue entry{UniValue::VOBJ};
            entry.pushKV("threshold", int(k));
            entry.pushKV("descriptor", descriptor);
            for (size_t branch{0}; branch < 2; ++branch) {
                UniValue scripts{UniValue::VARR};
                for (int index{0}; index < 5; ++index) {
                    std::vector<CScript> out;
                    FlatSigningProvider expanded;
                    BOOST_REQUIRE(parsed[branch]->Expand(index, provider, out, expanded));
                    BOOST_REQUIRE_EQUAL(out.size(), 1U);
                    scripts.push_back(HexStr(out[0]));
                }
                entry.pushKV(branch ? "change" : "receive", scripts);
            }
            cases.push_back(entry);
        }
    }
    std::cout << cases.write(4) << "\n";
}

BOOST_AUTO_TEST_SUITE_END()

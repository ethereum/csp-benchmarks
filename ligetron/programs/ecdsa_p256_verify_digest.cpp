#include <cstdlib>
#include <span>

#include <ligetron/api.h>
#include <ligetron/ecc/curves/p256.hpp>
#include <ligetron/ecc/ecdsa.hpp>

// argv: message digest, signature (r || s), public key (x || y).
int main(int argc, char* argv[]) {
    using Context = ligetron::ecc::ecdsa_context<ligetron::ecc::curves::p256>;
    assert_one(argc == 4);
    int lengths[4];
    args_len_get(argv, lengths);
    assert_one(lengths[1] == Context::scalar_bytes);
    assert_one(lengths[2] == Context::signature_bytes);
    assert_one(lengths[3] == Context::pubkey_bytes);
    const auto digest = std::as_bytes(
        std::span<const char, Context::scalar_bytes>{argv[1], Context::scalar_bytes});
    const auto signature = std::as_bytes(
        std::span<const char, Context::signature_bytes>{argv[2], Context::signature_bytes});
    const auto public_key = std::as_bytes(
        std::span<const char, Context::pubkey_bytes>{argv[3], Context::pubkey_bytes});
    Context context{public_key};
    const auto valid = context.verify_digest(signature, digest);
    bn254fr_assert_equal_u32(valid.data(), 1u);
    return EXIT_SUCCESS;
}

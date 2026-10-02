// What Blockchain Commons' C libraries make, for maki-sskr's tests (tests/sskr.rs, `c_library`
// and `seedtools_deterministic_example`): bc-sskr 0.3.2 with bc-shamir 0.4.0 and bc-crypto-base
// 0.3.2, as bc-sskr's own test and seedtool-cli 0.11.0 (C++) call them.
// - bc-sskr's test1: the spec's example secret and layout (2 of 3 and 3 of 5, both needed), split
//   with that test's generator, which starts glibc's rand() over from srand(1234567) each time
//   it's asked (its `seeded` is never set) and takes a byte of each; and the first bytes of that.
// - seedtool's `--deterministic FOOBAR --in hex --out sskr --group 2-of-3` example from its
//   manual: its generator is HKDF-SHA256 (its hkdf.c) keyed by SHA-256("FOOBAR"), salted with a
//   count of the times it's asked, a little-endian u64.
// To make them again, in a scratch folder with those four repositories checked out at those tags
// (github.com/BlockchainCommons/bc-crypto-base, bc-shamir, bc-sskr, seedtool-cli):
//   mkdir inc && ln -s $PWD/bc-crypto-base/src inc/bc-crypto-base && ln -s $PWD/bc-shamir/src inc/bc-shamir
//   ln -s $PWD/bc-sskr/src inc/bc-sskr && ln -s $PWD/seedtool-cli/src inc/seedtool-cli
//   gcc -I inc -o make-c make-c.c bc-sskr/src/encoding.c bc-shamir/src/shamir.c \
//     bc-shamir/src/interpolate.c bc-shamir/src/hazmat.c bc-crypto-base/src/sha2.c \
//     bc-crypto-base/src/hmac.c bc-crypto-base/src/memzero.c seedtool-cli/src/hkdf.c && ./make-c
// (with glibc: its rand() is the generator test1's shares come from; this ran with 2.43)

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bc-crypto-base/bc-crypto-base.h>
#include <bc-sskr/bc-sskr.h>
#include <seedtool-cli/hkdf.h>

// bc-sskr's test/test-utils.c
static void fake_random(uint8_t *buf, size_t count, void *ctx) {
    static bool seeded = false;
    if (!seeded) {
        srand(1234567);
    }
    for (int i = 0; i < count; i++) {
        buf[i] = (uint8_t)rand();
    }
}

// seedtool-cli's src/random.cpp
static uint8_t deterministic_seed[32];
static uint64_t deterministic_salt = 0;

static void deterministic_random(uint8_t *buf, size_t n, void *ctx) {
    deterministic_salt += 1;
    hkdf_sha256(buf, n, (uint8_t *)&deterministic_salt, sizeof(deterministic_salt), deterministic_seed, 32,
                NULL, 0);
}

static void print_hex(const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        printf("%02x", b[i]);
    }
    printf("\n");
}

static void split(const char *label, const char *secret_hex, size_t group_threshold,
                  sskr_group_descriptor *groups, size_t group_count,
                  void (*random)(uint8_t *, size_t, void *)) {
    uint8_t secret[32];
    size_t len = strlen(secret_hex) / 2;
    for (size_t i = 0; i < len; i++) {
        unsigned v;
        sscanf(secret_hex + 2 * i, "%2x", &v);
        secret[i] = v;
    }
    uint8_t out[16 * 16 * 37];
    size_t share_len = 0;
    int count = sskr_generate(group_threshold, groups, group_count, secret, len, &share_len, out, sizeof(out),
                              NULL, random);
    printf("%s: %d shares\n", label, count);
    for (int i = 0; i < count; i++) {
        print_hex(out + i * share_len, share_len);
    }
}

int main() {
    sskr_group_descriptor two[] = {{2, 3}, {3, 5}};
    split("bc-sskr test1", "7daa851251002874e1a1995f0897e6b1", 2, two, 2, fake_random);
    uint8_t first[32];
    fake_random(first, sizeof(first), NULL);
    printf("its generator's bytes: ");
    print_hex(first, sizeof(first));

    sha256_Raw((const uint8_t *)"FOOBAR", 6, deterministic_seed);
    sskr_group_descriptor one[] = {{2, 3}};
    split("seedtool --deterministic FOOBAR", "5cd271b50b98a869da1c26a526e1d3a8", 1, one, 1,
          deterministic_random);

    // bc-sskr refuses a group of more than one that needs only one share
    sskr_group_descriptor single[] = {{1, 3}};
    printf("1 of 3: sskr_count_shards gives %d (SSKR_ERROR_INVALID_SINGLETON_MEMBER is -4)\n",
           sskr_count_shards(1, single, 1));
    return 0;
}

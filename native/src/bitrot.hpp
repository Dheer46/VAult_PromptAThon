#pragma once
#include <cstddef>
#include <cstdint>

extern "C" {
#include "blake3.h"
}

namespace vault {

class Hasher {
public:
    Hasher() { blake3_hasher_init(&h_); }
    void update(const uint8_t* p, size_t n) { blake3_hasher_update(&h_, p, n); }
    void digest(uint8_t out[32]) { blake3_hasher_finalize(&h_, out, 32); }
    void reset() { blake3_hasher_init(&h_); }

private:
    blake3_hasher h_;
};

// One-shot helper used per shard block.
void hash32(const uint8_t* p, size_t n, uint8_t out[32]);

}  // namespace vault

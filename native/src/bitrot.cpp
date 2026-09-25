#include "bitrot.hpp"

namespace vault {

void hash32(const uint8_t* p, size_t n, uint8_t out[32]) {
    blake3_hasher h;
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, p, n);
    blake3_hasher_finalize(&h, out, 32);
}

}  // namespace vault

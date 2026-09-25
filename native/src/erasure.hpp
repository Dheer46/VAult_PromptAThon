#pragma once
#include <cstddef>
#include <cstdint>
#include <vector>

namespace vault {

// Reed-Solomon erasure coder over GF(2^8) backed by Intel ISA-L.
// Uses a Cauchy matrix so any k of the n = k + m rows are invertible.
class Erasure {
public:
    Erasure(int data_shards, int parity_shards);

    // shards: n buffers of shard_size bytes. The first k hold data; the last m
    // are overwritten with parity.
    void encode(std::vector<uint8_t*>& shards, size_t shard_size) const;

    // present[i] == false means shard i is missing/corrupt and must be rebuilt.
    // Requires at least k present shards. Missing shards are rebuilt in place.
    // data_only == true rebuilds only missing data shards (enough to decode).
    void reconstruct(std::vector<uint8_t*>& shards, const std::vector<bool>& present,
                     size_t shard_size, bool data_only) const;

    int k() const { return k_; }
    int m() const { return m_; }

private:
    int k_, m_, n_;
    std::vector<uint8_t> encode_matrix_;  // n x k
    std::vector<uint8_t> g_tbls_;         // tables for the m parity rows
};

}  // namespace vault

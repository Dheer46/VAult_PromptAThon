#include "erasure.hpp"

#include <isa-l/erasure_code.h>

#include <stdexcept>

namespace vault {

Erasure::Erasure(int k, int m)
    : k_(k), m_(m), n_(k + m), encode_matrix_((size_t)(k + m) * k), g_tbls_((size_t)k * m * 32) {
    if (k < 1 || m < 0 || k + m > 255) throw std::invalid_argument("bad k/m");
    // Cauchy matrix: any k rows are invertible, which is what makes decoding work.
    gf_gen_cauchy1_matrix(encode_matrix_.data(), n_, k_);
    // Precompute tables for the m parity rows (rows k..n-1).
    if (m_ > 0) ec_init_tables(k_, m_, &encode_matrix_[(size_t)k_ * k_], g_tbls_.data());
}

void Erasure::encode(std::vector<uint8_t*>& shards, size_t len) const {
    if ((int)shards.size() != n_) throw std::invalid_argument("need n shards");
    if (m_ == 0 || len == 0) return;
    ec_encode_data((int)len, k_, m_, const_cast<uint8_t*>(g_tbls_.data()), shards.data(),
                   shards.data() + k_);
}

void Erasure::reconstruct(std::vector<uint8_t*>& shards, const std::vector<bool>& present,
                          size_t len, bool data_only) const {
    if ((int)shards.size() != n_ || (int)present.size() != n_)
        throw std::invalid_argument("need n shards");
    std::vector<int> survivors, missing;
    for (int i = 0; i < n_; i++) {
        if (present[i]) survivors.push_back(i);
        else if (!data_only || i < k_) missing.push_back(i);
    }
    if ((int)survivors.size() < k_) throw std::runtime_error("not enough shards");
    if (missing.empty() || len == 0) return;

    // Build the k x k matrix from the first k surviving rows and invert it.
    std::vector<uint8_t> b((size_t)k_ * k_), inv((size_t)k_ * k_);
    std::vector<uint8_t*> src(k_);
    for (int r = 0; r < k_; r++) {
        int row = survivors[r];
        src[r] = shards[row];
        for (int c = 0; c < k_; c++) b[(size_t)r * k_ + c] = encode_matrix_[(size_t)row * k_ + c];
    }
    if (gf_invert_matrix(b.data(), inv.data(), k_) < 0)
        throw std::runtime_error("matrix not invertible");

    // For each missing row, compute its decode coefficients.
    int nm = (int)missing.size();
    std::vector<uint8_t> decode((size_t)nm * k_);
    for (int i = 0; i < nm; i++) {
        int row = missing[i];
        if (row < k_) {  // data shard: row of the inverse
            for (int c = 0; c < k_; c++) decode[(size_t)i * k_ + c] = inv[(size_t)row * k_ + c];
        } else {  // parity shard: encode row * inverse
            for (int c = 0; c < k_; c++) {
                uint8_t s = 0;
                for (int j = 0; j < k_; j++)
                    s ^= gf_mul(encode_matrix_[(size_t)row * k_ + j], inv[(size_t)j * k_ + c]);
                decode[(size_t)i * k_ + c] = s;
            }
        }
    }
    std::vector<uint8_t> tbls((size_t)k_ * nm * 32);
    ec_init_tables(k_, nm, decode.data(), tbls.data());
    std::vector<uint8_t*> out(nm);
    for (int i = 0; i < nm; i++) out[i] = shards[missing[i]];
    ec_encode_data((int)len, k_, nm, tbls.data(), src.data(), out.data());
}

}  // namespace vault

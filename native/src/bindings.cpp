#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <algorithm>
#include <cstring>

#include "bitrot.hpp"
#include "erasure.hpp"

namespace py = pybind11;
using namespace vault;

static size_t shard_size_for(size_t block, int k) { return (block + k - 1) / k; }

// Copies a list[bytes | None] of n shards into owned buffers of ss bytes each.
static void load_shards(const py::list& shards, int n, size_t ss,
                        std::vector<std::vector<uint8_t>>& bufs, std::vector<bool>& present) {
    if ((int)py::len(shards) != n) throw std::invalid_argument("need n shards");
    bufs.assign(n, std::vector<uint8_t>(ss, 0));
    present.assign(n, false);
    for (int i = 0; i < n; i++) {
        py::handle h = shards[i];
        if (h.is_none()) continue;
        py::buffer_info info = py::reinterpret_borrow<py::buffer>(h).request();
        size_t len = (size_t)info.size * info.itemsize;
        std::memcpy(bufs[i].data(), info.ptr, std::min(len, ss));
        present[i] = true;
    }
}

PYBIND11_MODULE(vault_native, mod) {
    mod.doc() = "Vault native core: ISA-L erasure coding + BLAKE3 bitrot hashing";

    py::class_<Erasure>(mod, "Erasure")
        .def(py::init<int, int>())
        .def_property_readonly("k", &Erasure::k)
        .def_property_readonly("m", &Erasure::m)
        // encode_block(data: bytes) -> list[bytes] (n shards, zero padded)
        .def("encode_block", [](const Erasure& e, py::buffer data) {
            py::buffer_info info = data.request();
            size_t len = (size_t)info.size * info.itemsize;
            int k = e.k(), n = e.k() + e.m();
            size_t ss = shard_size_for(len, k);
            std::vector<std::vector<uint8_t>> bufs(n, std::vector<uint8_t>(ss, 0));
            const uint8_t* src = static_cast<const uint8_t*>(info.ptr);
            for (int i = 0; i < k; i++) {
                size_t off = (size_t)i * ss;
                if (off < len) std::memcpy(bufs[i].data(), src + off, std::min(ss, len - off));
            }
            std::vector<uint8_t*> ptrs(n);
            for (int i = 0; i < n; i++) ptrs[i] = bufs[i].data();
            {
                py::gil_scoped_release release;
                e.encode(ptrs, ss);
            }
            py::list out;
            for (auto& b : bufs) out.append(py::bytes(reinterpret_cast<char*>(b.data()), b.size()));
            return out;
        })
        // decode_block(shards: list[bytes|None], block_len) -> bytes (original data)
        .def("decode_block", [](const Erasure& e, py::list shards, size_t block_len) {
            int k = e.k(), n = e.k() + e.m();
            size_t ss = shard_size_for(block_len, k);
            std::vector<std::vector<uint8_t>> bufs;
            std::vector<bool> present;
            load_shards(shards, n, ss, bufs, present);
            std::vector<uint8_t*> ptrs(n);
            for (int i = 0; i < n; i++) ptrs[i] = bufs[i].data();
            {
                py::gil_scoped_release release;
                e.reconstruct(ptrs, present, ss, /*data_only=*/true);
            }
            std::string out(block_len, '\0');
            for (int i = 0; i < k; i++) {
                size_t off = (size_t)i * ss;
                if (off < block_len) std::memcpy(&out[off], bufs[i].data(), std::min(ss, block_len - off));
            }
            return py::bytes(out);
        })
        // heal_block(shards: list[bytes|None], shard_size) -> list[bytes] (all n shards)
        .def("heal_block", [](const Erasure& e, py::list shards, size_t ss) {
            int n = e.k() + e.m();
            std::vector<std::vector<uint8_t>> bufs;
            std::vector<bool> present;
            load_shards(shards, n, ss, bufs, present);
            std::vector<uint8_t*> ptrs(n);
            for (int i = 0; i < n; i++) ptrs[i] = bufs[i].data();
            {
                py::gil_scoped_release release;
                e.reconstruct(ptrs, present, ss, /*data_only=*/false);
            }
            py::list out;
            for (auto& b : bufs) out.append(py::bytes(reinterpret_cast<char*>(b.data()), b.size()));
            return out;
        });

    mod.def("hash32", [](py::buffer data) {
        py::buffer_info info = data.request();
        size_t len = (size_t)info.size * info.itemsize;
        uint8_t out[32];
        {
            py::gil_scoped_release release;
            hash32(static_cast<const uint8_t*>(info.ptr), len, out);
        }
        return py::bytes(reinterpret_cast<char*>(out), 32);
    });

    py::class_<Hasher>(mod, "Hasher")
        .def(py::init<>())
        .def("update", [](Hasher& h, py::buffer data) {
            py::buffer_info info = data.request();
            size_t len = (size_t)info.size * info.itemsize;
            py::gil_scoped_release release;
            h.update(static_cast<const uint8_t*>(info.ptr), len);
        })
        .def("digest", [](Hasher& h) {
            uint8_t out[32];
            h.digest(out);
            return py::bytes(reinterpret_cast<char*>(out), 32);
        })
        .def("reset", &Hasher::reset);

    mod.attr("NATIVE") = true;
}

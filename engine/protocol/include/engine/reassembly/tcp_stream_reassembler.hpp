#pragma once

#include <cstdint>
#include <vector>
#include <span>
#include <map>
#include <string>

namespace engine::reassembly {

struct SeqComparator {
    bool operator()(uint32_t a, uint32_t b) const {
        // Signed 32-bit comparison for sequence number wraparound
        return static_cast<int32_t>(a - b) < 0;
    }
};

class DirectionReassembler {
public:
    explicit DirectionReassembler(size_t max_buffer_bytes = 1048576, size_t max_segments = 64);

    bool push_segment(uint32_t seq, std::span<const uint8_t> payload, bool syn, bool fin);

    [[nodiscard]] std::span<const uint8_t> get_contiguous_data() const;
    [[nodiscard]] size_t get_contiguous_size() const;
    [[nodiscard]] uint32_t get_expected_seq() const { return expected_seq_; }
    [[nodiscard]] bool has_init() const { return has_init_; }
    [[nodiscard]] bool has_gap() const { return !out_of_order_segments_.empty(); }
    [[nodiscard]] bool has_overlap_conflict() const { return has_overlap_conflict_; }
    [[nodiscard]] size_t get_out_of_order_segment_count() const { return out_of_order_segments_.size(); }
    void clear();

private:
    void drain_out_of_order();

    size_t max_buffer_bytes_{1048576}; // 1 MB limit
    size_t max_segments_{64};
    bool has_init_{false};
    uint32_t initial_seq_{0};
    uint32_t expected_seq_{0};
    bool has_overlap_conflict_{false};
    std::vector<uint8_t> contiguous_data_;
    std::map<uint32_t, std::vector<uint8_t>, SeqComparator> out_of_order_segments_;
    size_t current_buffered_bytes_{0};
};

class TcpStreamReassembler {
public:
    TcpStreamReassembler() = default;

    bool push_segment(
        bool is_forward,
        uint32_t seq,
        std::span<const uint8_t> payload,
        bool syn,
        bool fin
    );

    [[nodiscard]] const DirectionReassembler& get_forward() const { return fwd_; }
    [[nodiscard]] const DirectionReassembler& get_reverse() const { return rev_; }
    void clear();

private:
    DirectionReassembler fwd_;
    DirectionReassembler rev_;
};

} // namespace engine::reassembly

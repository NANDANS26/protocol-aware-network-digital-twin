#include "engine/reassembly/tcp_stream_reassembler.hpp"
#include <cstring>

namespace engine::reassembly {

DirectionReassembler::DirectionReassembler(size_t max_buffer_bytes, size_t max_segments)
    : max_buffer_bytes_(max_buffer_bytes), max_segments_(max_segments) {}

void DirectionReassembler::clear() {
    contiguous_data_.clear();
    out_of_order_segments_.clear();
    current_buffered_bytes_ = 0;
    has_init_ = false;
    has_overlap_conflict_ = false;
}

std::span<const uint8_t> DirectionReassembler::get_contiguous_data() const {
    return contiguous_data_;
}

size_t DirectionReassembler::get_contiguous_size() const {
    return contiguous_data_.size();
}

bool DirectionReassembler::push_segment(uint32_t seq, std::span<const uint8_t> payload, bool syn, bool /* fin */) {
    if (syn) {
        initial_seq_ = seq + 1;
        expected_seq_ = seq + 1;
        has_init_ = true;
        return true;
    }

    if (!has_init_) {
        initial_seq_ = seq;
        expected_seq_ = seq;
        has_init_ = true;
    }

    if (payload.empty()) {
        return true;
    }

    int32_t delta = static_cast<int32_t>(seq - expected_seq_);

    if (delta == 0) {
        // Exactly matches expected sequence: append to contiguous stream
        if (contiguous_data_.size() + payload.size() <= max_buffer_bytes_) {
            contiguous_data_.insert(contiguous_data_.end(), payload.begin(), payload.end());
            expected_seq_ += static_cast<uint32_t>(payload.size());
        }
        drain_out_of_order();
        return true;
    } else if (delta < 0) {
        // Segment starts before expected sequence (retransmission or partial overlap)
        int32_t bytes_behind = -delta;
        if (static_cast<size_t>(bytes_behind) >= payload.size()) {
            // Complete duplicate/retransmission: verify data matches existing
            size_t overlap_offset = contiguous_data_.size() >= static_cast<size_t>(bytes_behind)
                                        ? contiguous_data_.size() - bytes_behind
                                        : 0;
            size_t check_len = std::min(payload.size(), contiguous_data_.size() - overlap_offset);
            if (check_len > 0 && std::memcmp(contiguous_data_.data() + overlap_offset, payload.data(), check_len) != 0) {
                has_overlap_conflict_ = true;
            }
            return true;
        }

        // Partial overlap: check overlapping prefix for conflict
        size_t overlap_len = static_cast<size_t>(bytes_behind);
        size_t overlap_offset = contiguous_data_.size() - overlap_len;
        if (std::memcmp(contiguous_data_.data() + overlap_offset, payload.data(), overlap_len) != 0) {
            has_overlap_conflict_ = true;
        }

        // Append new non-overlapping suffix
        std::span<const uint8_t> new_bytes = payload.subspan(overlap_len);
        if (contiguous_data_.size() + new_bytes.size() <= max_buffer_bytes_) {
            contiguous_data_.insert(contiguous_data_.end(), new_bytes.begin(), new_bytes.end());
            expected_seq_ += static_cast<uint32_t>(new_bytes.size());
        }
        drain_out_of_order();
        return true;
    } else {
        // Gap: Segment is ahead in sequence space -> store in out-of-order map
        if (out_of_order_segments_.size() < max_segments_ &&
            current_buffered_bytes_ + payload.size() <= max_buffer_bytes_) {
            out_of_order_segments_[seq] = std::vector<uint8_t>(payload.begin(), payload.end());
            current_buffered_bytes_ += payload.size();
        }
        return false;
    }
}

void DirectionReassembler::drain_out_of_order() {
    while (!out_of_order_segments_.empty()) {
        auto it = out_of_order_segments_.begin();
        uint32_t seq = it->first;
        const auto& seg_data = it->second;

        int32_t delta = static_cast<int32_t>(seq - expected_seq_);
        if (delta == 0) {
            if (contiguous_data_.size() + seg_data.size() <= max_buffer_bytes_) {
                contiguous_data_.insert(contiguous_data_.end(), seg_data.begin(), seg_data.end());
                expected_seq_ += static_cast<uint32_t>(seg_data.size());
            }
            current_buffered_bytes_ -= seg_data.size();
            out_of_order_segments_.erase(it);
        } else if (delta < 0) {
            int32_t bytes_behind = -delta;
            if (static_cast<size_t>(bytes_behind) < seg_data.size()) {
                size_t new_len = seg_data.size() - bytes_behind;
                if (contiguous_data_.size() + new_len <= max_buffer_bytes_) {
                    contiguous_data_.insert(contiguous_data_.end(), seg_data.begin() + bytes_behind, seg_data.end());
                    expected_seq_ += static_cast<uint32_t>(new_len);
                }
            }
            current_buffered_bytes_ -= seg_data.size();
            out_of_order_segments_.erase(it);
        } else {
            // Next segment is still in the future (gap remains)
            break;
        }
    }
}

bool TcpStreamReassembler::push_segment(
    bool is_forward,
    uint32_t seq,
    std::span<const uint8_t> payload,
    bool syn,
    bool fin
) {
    if (is_forward) {
        return fwd_.push_segment(seq, payload, syn, fin);
    } else {
        return rev_.push_segment(seq, payload, syn, fin);
    }
}

void TcpStreamReassembler::clear() {
    fwd_.clear();
    rev_.clear();
}

} // namespace engine::reassembly

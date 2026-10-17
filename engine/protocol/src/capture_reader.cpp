#include "engine/capture_reader.hpp"
#include "engine/logger.hpp"
#include <cmath>
#include <cstring>

namespace engine {

namespace {

inline uint16_t swap16(uint16_t val) {
    return static_cast<uint16_t>((val << 8) | (val >> 8));
}

inline uint32_t swap32(uint32_t val) {
    return ((val >> 24) & 0x000000FF) |
           ((val >> 8)  & 0x0000FF00) |
           ((val << 8)  & 0x00FF0000) |
           ((val << 24) & 0xFF000000);
}

inline uint64_t swap64(uint64_t val) {
    return ((val >> 56) & 0x00000000000000FFULL) |
           ((val >> 40) & 0x000000000000FF00ULL) |
           ((val >> 24) & 0x0000000000FF0000ULL) |
           ((val >> 8)  & 0x00000000FF000000ULL) |
           ((val << 8)  & 0x000000FF00000000ULL) |
           ((val << 24) & 0x0000FF0000000000ULL) |
           ((val << 40) & 0x00FF000000000000ULL) |
           ((val << 56) & 0xFF00000000000000ULL);
}

constexpr uint32_t PCAP_MAGIC_MICRO_NATIVE = 0xA1B2C3D4;
constexpr uint32_t PCAP_MAGIC_MICRO_SWAPPED = 0xD4C3B2A1;
constexpr uint32_t PCAP_MAGIC_NANO_NATIVE  = 0xA1B23C4D;
constexpr uint32_t PCAP_MAGIC_NANO_SWAPPED  = 0x4D3CB2A1;

constexpr uint32_t PCAPNG_BLOCK_SHB = 0x0A0D0D0A;
constexpr uint32_t PCAPNG_BLOCK_IDB = 0x00000001;
constexpr uint32_t PCAPNG_BLOCK_SPB = 0x00000003;
constexpr uint32_t PCAPNG_BLOCK_EPB = 0x00000006;
constexpr uint32_t PCAPNG_BOM_NATIVE = 0x1A2B3C4D;
constexpr uint32_t PCAPNG_BOM_SWAPPED = 0x4D3C2B1A;

constexpr uint32_t MAX_REASONABLE_PACKET_LEN = 16 * 1024 * 1024; // 16 MB

} // namespace

CaptureReader::~CaptureReader() {
    close();
}

void CaptureReader::close() {
    if (file_.is_open()) {
        file_.close();
    }
    is_open_ = false;
    is_eof_ = false;
    format_ = CaptureFileFormat::Unknown;
    interfaces_.clear();
}

bool CaptureReader::is_open() const {
    return is_open_;
}

bool CaptureReader::is_eof() const {
    return is_eof_;
}

CaptureFileFormat CaptureReader::get_format() const {
    return format_;
}

const std::vector<CaptureInterfaceInfo>& CaptureReader::get_interfaces() const {
    return interfaces_;
}

PacketSourceStats CaptureReader::get_stats() const {
    return stats_;
}

StatusCode CaptureReader::open(const std::string& file_path, std::string& error_msg) {
    close();
    file_path_ = file_path;
    packet_index_ = 0;
    stats_ = {};

    file_.open(file_path_, std::ios::binary);
    if (!file_.is_open()) {
        error_msg = "Could not open file: " + file_path_;
        return StatusCode::SourceOpenFailed;
    }

    uint32_t magic = 0;
    file_.read(reinterpret_cast<char*>(&magic), 4);
    if (file_.gcount() < 4) {
        error_msg = "File is empty or too small to contain a capture header";
        file_.close();
        return StatusCode::ReadError;
    }

    if (magic == PCAP_MAGIC_MICRO_NATIVE || magic == PCAP_MAGIC_MICRO_SWAPPED ||
        magic == PCAP_MAGIC_NANO_NATIVE  || magic == PCAP_MAGIC_NANO_SWAPPED) {
        return detect_and_open_pcap(magic, error_msg);
    } else if (magic == PCAPNG_BLOCK_SHB) {
        return detect_and_open_pcapng(error_msg);
    }

    error_msg = "Unrecognized capture file format (magic: 0x" + std::to_string(magic) + ")";
    file_.close();
    return StatusCode::SourceOpenFailed;
}

StatusCode CaptureReader::detect_and_open_pcap(uint32_t magic, std::string& error_msg) {
    format_ = CaptureFileFormat::ClassicPcap;
    byte_swapped_ = (magic == PCAP_MAGIC_MICRO_SWAPPED || magic == PCAP_MAGIC_NANO_SWAPPED);
    pcap_ts_resolution_ = (magic == PCAP_MAGIC_NANO_NATIVE || magic == PCAP_MAGIC_NANO_SWAPPED)
                              ? TimestampResolution::Nanosecond
                              : TimestampResolution::Microsecond;

    // Read remainder of 24-byte PCAP header (20 bytes)
    char rest_header[20];
    file_.read(rest_header, 20);
    if (file_.gcount() < 20) {
        error_msg = "Truncated PCAP global header";
        return StatusCode::ReadError;
    }

    uint16_t major = 0, minor = 0;
    uint32_t snaplen = 0, network = 0;
    std::memcpy(&major, rest_header + 0, 2);
    std::memcpy(&minor, rest_header + 2, 2);
    std::memcpy(&snaplen, rest_header + 12, 4);
    std::memcpy(&network, rest_header + 16, 4);

    if (byte_swapped_) {
        major = swap16(major);
        minor = swap16(minor);
        snaplen = swap32(snaplen);
        network = swap32(network);
    }

    pcap_snaplen_ = snaplen == 0 ? 65535 : snaplen;
    pcap_link_type_ = static_cast<LinkType>(network);

    CaptureInterfaceInfo iface{};
    iface.index = 0;
    iface.link_type = pcap_link_type_;
    iface.snaplen = pcap_snaplen_;
    iface.ts_resolution = pcap_ts_resolution_;
    iface.ts_resolution_denominator = (pcap_ts_resolution_ == TimestampResolution::Nanosecond) ? 1000000000ULL : 1000000ULL;
    iface.name = "pcap_default";
    interfaces_.push_back(iface);

    is_open_ = true;
    is_eof_ = false;
    LOG_INFO("CaptureReader", "Opened Classic PCAP file: " + file_path_ +
             " [v" + std::to_string(major) + "." + std::to_string(minor) +
             ", link=" + to_string(pcap_link_type_) +
             ", ts=" + (pcap_ts_resolution_ == TimestampResolution::Nanosecond ? "ns" : "us") + "]");
    return StatusCode::Success;
}

StatusCode CaptureReader::detect_and_open_pcapng(std::string& error_msg) {
    format_ = CaptureFileFormat::PcapNg;

    // We already read 4 bytes (0x0A0D0D0A). Read next 8 bytes (total_len, byte_order_magic).
    uint32_t block_total_len = 0;
    uint32_t bom = 0;

    file_.read(reinterpret_cast<char*>(&block_total_len), 4);
    file_.read(reinterpret_cast<char*>(&bom), 4);
    if (file_.gcount() < 4) {
        error_msg = "Truncated PCAPNG Section Header Block";
        return StatusCode::ReadError;
    }

    if (bom == PCAPNG_BOM_NATIVE) {
        byte_swapped_ = false;
    } else if (bom == PCAPNG_BOM_SWAPPED) {
        byte_swapped_ = true;
        block_total_len = swap32(block_total_len);
    } else {
        error_msg = "Invalid PCAPNG Byte Order Magic: 0x" + std::to_string(bom);
        return StatusCode::SourceOpenFailed;
    }

    if (block_total_len < 16 || block_total_len > MAX_REASONABLE_PACKET_LEN) {
        error_msg = "Invalid PCAPNG Section Header Block length: " + std::to_string(block_total_len);
        return StatusCode::CorruptCaptureRecord;
    }

    // Skip remainder of SHB: total_len - 12 bytes read so far
    file_.seekg(static_cast<std::streamoff>(block_total_len - 12), std::ios::cur);
    if (!file_) {
        error_msg = "Failed seeking past PCAPNG Section Header Block";
        return StatusCode::ReadError;
    }

    is_open_ = true;
    is_eof_ = false;
    LOG_INFO("CaptureReader", "Opened PCAPNG file: " + file_path_ +
             (byte_swapped_ ? " (byte-swapped)" : " (native endian)"));
    return StatusCode::Success;
}

StatusCode CaptureReader::read_next_packet(RawPacket& out_packet) {
    if (!is_open_) {
        return StatusCode::ReadError;
    }
    if (is_eof_) {
        return StatusCode::EndOfFile;
    }

    if (format_ == CaptureFileFormat::ClassicPcap) {
        return read_pcap_packet(out_packet);
    } else if (format_ == CaptureFileFormat::PcapNg) {
        return read_pcapng_packet(out_packet);
    }

    return StatusCode::InternalError;
}

StatusCode CaptureReader::read_pcap_packet(RawPacket& out_packet) {
    // 16-byte PCAP packet record header: ts_sec(4), ts_usec(4), incl_len(4), orig_len(4)
    char rec_hdr[16];
    file_.read(rec_hdr, 16);
    if (file_.gcount() == 0) {
        is_eof_ = true;
        return StatusCode::EndOfFile;
    }
    if (file_.gcount() < 16) {
        LOG_WARN("CaptureReader", "Truncated PCAP packet header encountered at packet " + std::to_string(packet_index_));
        is_eof_ = true;
        return StatusCode::CorruptCaptureRecord;
    }

    uint32_t ts_sec = 0, ts_usec = 0, incl_len = 0, orig_len = 0;
    std::memcpy(&ts_sec,   rec_hdr + 0,  4);
    std::memcpy(&ts_usec,  rec_hdr + 4,  4);
    std::memcpy(&incl_len, rec_hdr + 8,  4);
    std::memcpy(&orig_len, rec_hdr + 12, 4);

    if (byte_swapped_) {
        ts_sec   = swap32(ts_sec);
        ts_usec  = swap32(ts_usec);
        incl_len = swap32(incl_len);
        orig_len = swap32(orig_len);
    }

    if (incl_len > MAX_REASONABLE_PACKET_LEN) {
        LOG_ERROR("CaptureReader", "PCAP packet length exceeds bounds: " + std::to_string(incl_len));
        is_eof_ = true;
        return StatusCode::CorruptCaptureRecord;
    }

    out_packet.index = packet_index_++;
    out_packet.interface_id = 0;
    out_packet.link_type = pcap_link_type_;
    out_packet.wire_length_bytes = orig_len;
    out_packet.capture_length_bytes = incl_len;

    // Convert timestamp to nanoseconds
    if (pcap_ts_resolution_ == TimestampResolution::Nanosecond) {
        out_packet.timestamp_ns = static_cast<uint64_t>(ts_sec) * 1000000000ULL + ts_usec;
    } else {
        out_packet.timestamp_ns = static_cast<uint64_t>(ts_sec) * 1000000000ULL + static_cast<uint64_t>(ts_usec) * 1000ULL;
    }

    out_packet.data.resize(incl_len);
    if (incl_len > 0) {
        file_.read(reinterpret_cast<char*>(out_packet.data.data()), incl_len);
        if (static_cast<uint32_t>(file_.gcount()) < incl_len) {
            LOG_WARN("CaptureReader", "Unexpected EOF reading packet payload bytes at index " + std::to_string(out_packet.index));
            is_eof_ = true;
            return StatusCode::CorruptCaptureRecord;
        }
    }

    stats_.packets_received++;
    stats_.bytes_received += out_packet.capture_length_bytes;
    return StatusCode::Success;
}

StatusCode CaptureReader::read_pcapng_packet(RawPacket& out_packet) {
    while (file_) {
        char block_hdr[8];
        file_.read(block_hdr, 8);
        if (file_.gcount() == 0) {
            is_eof_ = true;
            return StatusCode::EndOfFile;
        }
        if (file_.gcount() < 8) {
            LOG_WARN("CaptureReader", "Truncated PCAPNG block header");
            is_eof_ = true;
            return StatusCode::CorruptCaptureRecord;
        }

        uint32_t block_type = 0;
        uint32_t block_total_len = 0;
        std::memcpy(&block_type, block_hdr + 0, 4);
        std::memcpy(&block_total_len, block_hdr + 4, 4);

        if (byte_swapped_) {
            block_type = swap32(block_type);
            block_total_len = swap32(block_total_len);
        }

        if (block_total_len < 12 || block_total_len > MAX_REASONABLE_PACKET_LEN) {
            LOG_ERROR("CaptureReader", "Corrupt PCAPNG block total length: " + std::to_string(block_total_len));
            is_eof_ = true;
            return StatusCode::CorruptCaptureRecord;
        }

        const uint32_t body_len = block_total_len - 12;

        if (block_type == PCAPNG_BLOCK_IDB) {
            // Interface Description Block: LinkType(2), Reserved(2), SnapLen(4), Options(variable)
            if (body_len < 8) {
                file_.seekg(static_cast<std::streamoff>(body_len + 4), std::ios::cur);
                continue;
            }

            char idb_body[8];
            file_.read(idb_body, 8);
            uint16_t link_type = 0;
            uint32_t snaplen = 0;
            std::memcpy(&link_type, idb_body + 0, 2);
            std::memcpy(&snaplen, idb_body + 4, 4);

            if (byte_swapped_) {
                link_type = swap16(link_type);
                snaplen = swap32(snaplen);
            }

            CaptureInterfaceInfo iface{};
            iface.index = static_cast<uint32_t>(interfaces_.size());
            iface.link_type = static_cast<LinkType>(link_type);
            iface.snaplen = snaplen == 0 ? 65535 : snaplen;
            iface.ts_resolution = TimestampResolution::Microsecond;
            iface.ts_resolution_denominator = 1000000ULL;
            iface.name = "iface_" + std::to_string(iface.index);

            // Read options if present
            const uint32_t opts_len = body_len - 8;
            if (opts_len > 0) {
                std::vector<uint8_t> opt_buf(opts_len);
                file_.read(reinterpret_cast<char*>(opt_buf.data()), opts_len);
                // Parse if_tsresol (option code 9) if present
                uint32_t opt_offset = 0;
                while (opt_offset + 4 <= opts_len) {
                    uint16_t code = 0, len = 0;
                    std::memcpy(&code, opt_buf.data() + opt_offset, 2);
                    std::memcpy(&len, opt_buf.data() + opt_offset + 2, 2);
                    if (byte_swapped_) { code = swap16(code); len = swap16(len); }
                    if (code == 0) break; // End of options
                    opt_offset += 4;
                    if (opt_offset + len > opts_len) break;
                    if (code == 9 && len == 1) { // if_tsresol
                        uint8_t res_val = opt_buf[opt_offset];
                        if (res_val & 0x80) {
                            uint8_t pow2 = res_val & 0x7F;
                            iface.ts_resolution_denominator = 1ULL << pow2;
                        } else {
                            iface.ts_resolution_denominator = static_cast<uint64_t>(std::pow(10, res_val));
                        }
                        if (res_val == 9) {
                            iface.ts_resolution = TimestampResolution::Nanosecond;
                        }
                    }
                    opt_offset += len;
                    // Pad to 32-bit
                    if (opt_offset % 4 != 0) {
                        opt_offset += (4 - (opt_offset % 4));
                    }
                }
            }

            interfaces_.push_back(iface);
            // Read trailing 4-byte block_total_len
            uint32_t trailing_len = 0;
            file_.read(reinterpret_cast<char*>(&trailing_len), 4);
            continue;
        }

        if (block_type == PCAPNG_BLOCK_EPB) {
            // Enhanced Packet Block: InterfaceId(4), TsHigh(4), TsLow(4), CapLen(4), WireLen(4), Data(CapLen), Pad, Options
            if (body_len < 20) {
                file_.seekg(static_cast<std::streamoff>(body_len + 4), std::ios::cur);
                continue;
            }

            char epb_body[20];
            file_.read(epb_body, 20);
            uint32_t if_id = 0, ts_high = 0, ts_low = 0, cap_len = 0, wire_len = 0;
            std::memcpy(&if_id,   epb_body + 0,  4);
            std::memcpy(&ts_high, epb_body + 4,  4);
            std::memcpy(&ts_low,  epb_body + 8,  4);
            std::memcpy(&cap_len, epb_body + 12, 4);
            std::memcpy(&wire_len,epb_body + 16, 4);

            if (byte_swapped_) {
                if_id   = swap32(if_id);
                ts_high = swap32(ts_high);
                ts_low  = swap32(ts_low);
                cap_len = swap32(cap_len);
                wire_len= swap32(wire_len);
            }

            if (cap_len > MAX_REASONABLE_PACKET_LEN) {
                LOG_ERROR("CaptureReader", "EPB packet cap_len exceeds bounds: " + std::to_string(cap_len));
                is_eof_ = true;
                return StatusCode::CorruptCaptureRecord;
            }

            out_packet.index = packet_index_++;
            out_packet.interface_id = if_id;
            out_packet.wire_length_bytes = wire_len;
            out_packet.capture_length_bytes = cap_len;

            // Resolve interface link type and timestamp
            LinkType link_type = LinkType::Ethernet;
            uint64_t denom = 1000000ULL;
            if (if_id < interfaces_.size()) {
                link_type = interfaces_[if_id].link_type;
                denom = interfaces_[if_id].ts_resolution_denominator;
            }
            out_packet.link_type = link_type;

            const uint64_t raw_ts = (static_cast<uint64_t>(ts_high) << 32) | static_cast<uint64_t>(ts_low);
            if (denom == 1000000000ULL) {
                out_packet.timestamp_ns = raw_ts;
            } else if (denom > 0) {
                out_packet.timestamp_ns = static_cast<uint64_t>((static_cast<double>(raw_ts) / denom) * 1000000000.0);
            } else {
                out_packet.timestamp_ns = raw_ts * 1000ULL;
            }

            out_packet.data.resize(cap_len);
            if (cap_len > 0) {
                file_.read(reinterpret_cast<char*>(out_packet.data.data()), cap_len);
            }

            // Skip unread padding and options in block body
            if (body_len > (20 + cap_len)) {
                const uint32_t remaining = body_len - (20 + cap_len);
                file_.seekg(static_cast<std::streamoff>(remaining), std::ios::cur);
            }

            // Read trailing block_total_len (4 bytes)
            uint32_t trailing_len = 0;
            file_.read(reinterpret_cast<char*>(&trailing_len), 4);

            stats_.packets_received++;
            stats_.bytes_received += out_packet.capture_length_bytes;
            return StatusCode::Success;
        }

        // For all other blocks (SHB, SPB, Name Resolution, ISB, Custom), skip body and trailing length
        file_.seekg(static_cast<std::streamoff>(body_len + 4), std::ios::cur);
    }

    is_eof_ = true;
    return StatusCode::EndOfFile;
}

} // namespace engine

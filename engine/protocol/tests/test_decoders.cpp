#include "doctest.h"
#include "engine/decoders/ethernet_decoder.hpp"
#include "engine/decoders/ipv4_decoder.hpp"
#include "engine/decoders/ipv6_decoder.hpp"
#include "engine/decoders/arp_decoder.hpp"
#include "engine/decoders/icmp_decoder.hpp"
#include "engine/decoders/tcp_decoder.hpp"
#include "engine/decoders/udp_decoder.hpp"

using namespace engine::decoders;

TEST_CASE("EthernetDecoder decodes standard Ethernet II frame") {
    const std::vector<uint8_t> frame = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // dst
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // src
        0x08, 0x00,                         // ether_type IPv4
        0xde, 0xad, 0xbe, 0xef              // payload
    };

    DecodedEthernet out;
    std::string diag;
    DecodeResult res = EthernetDecoder::decode(frame, out, diag);
    CHECK(res == DecodeResult::Success);
    CHECK(out.destination_mac.to_string() == "00:11:22:33:44:55");
    CHECK(out.source_mac.to_string() == "66:77:88:99:AA:BB");
    CHECK(out.ether_type == 0x0800);
    CHECK(out.vlan_tags.empty());
    CHECK(out.payload.size() == 4);
    CHECK(out.payload[0] == 0xde);
}

TEST_CASE("EthernetDecoder handles 802.1Q VLAN tagging") {
    const std::vector<uint8_t> frame = {
        0x00, 0x50, 0x56, 0x00, 0x00, 0x01,
        0x00, 0x50, 0x56, 0x00, 0x00, 0x02,
        0x81, 0x00,                         // TPID 802.1Q
        0x60, 0x64,                         // Priority 3, VID 100
        0x08, 0x00,                         // Encapsulated EtherType (IPv4)
        0x01, 0x02, 0x03, 0x04
    };

    DecodedEthernet out;
    std::string diag;
    DecodeResult res = EthernetDecoder::decode(frame, out, diag);
    CHECK(res == DecodeResult::Success);
    CHECK_FALSE(out.vlan_tags.empty());
    CHECK(out.vlan_tags[0].vlan_id == 100);
    CHECK(out.vlan_tags[0].priority == 3);
    CHECK(out.ether_type == 0x0800);
    CHECK(out.payload.size() == 4);
}

TEST_CASE("IPv4Decoder validates header, lengths, and checksums") {
    std::vector<uint8_t> pkt = {
        0x45, 0x00, 0x00, 0x18,
        0x12, 0x34, 0x40, 0x00,
        0x40, 0x06, 0x00, 0x00, // Checksum placeholder at bytes 10-11
        0xc0, 0xa8, 0x01, 0x01, // 192.168.1.1
        0x0a, 0x00, 0x00, 0x01, // 10.0.0.1
        0xaa, 0xbb, 0xcc, 0xdd
    };

    // Calculate checksum over 20-byte header
    uint32_t sum = 0;
    for (size_t i = 0; i < 20; i += 2) {
        if (i == 10) continue;
        sum += (pkt[i] << 8) | pkt[i + 1];
    }
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    uint16_t cksum = static_cast<uint16_t>(~sum);
    pkt[10] = static_cast<uint8_t>(cksum >> 8);
    pkt[11] = static_cast<uint8_t>(cksum & 0xff);

    DecodedIPv4 out;
    std::string diag;
    DecodeResult res = IPv4Decoder::decode(pkt, out, diag);
    CHECK(res == DecodeResult::Success);
    CHECK(out.source_ip == "192.168.1.1");
    CHECK(out.destination_ip == "10.0.0.1");
    CHECK(out.protocol == 6);
    CHECK(out.ttl == 64);
    CHECK(out.identification == 0x1234);
    CHECK(out.flag_df == true);
    CHECK(out.flag_mf == false);
    CHECK(out.checksum_status == ChecksumStatus::Valid);
    CHECK(out.payload.size() == 4);

    // Corrupt checksum test
    pkt[10] ^= 0xff;
    res = IPv4Decoder::decode(pkt, out, diag);
    CHECK(res == DecodeResult::Success);
    CHECK(out.checksum_status == ChecksumStatus::Invalid);
}

TEST_CASE("IPv6Decoder parses header and addresses") {
    std::vector<uint8_t> pkt(44, 0);
    pkt[0] = 0x60;
    pkt[4] = 0x00; pkt[5] = 0x04; // Payload length = 4
    pkt[6] = 17;                   // Next Header = UDP
    pkt[7] = 128;                  // Hop Limit

    // Src: 2001:db8::1
    pkt[8] = 0x20; pkt[9] = 0x01; pkt[10] = 0x0d; pkt[11] = 0xb8;
    pkt[23] = 0x01;

    // Dst: 2001:db8::2
    pkt[24] = 0x20; pkt[25] = 0x01; pkt[26] = 0x0d; pkt[27] = 0xb8;
    pkt[39] = 0x02;

    pkt[40] = 0x11; pkt[41] = 0x22; pkt[42] = 0x33; pkt[43] = 0x44;

    DecodedIPv6 out;
    std::string diag;
    DecodeResult res = IPv6Decoder::decode(pkt, out, diag);
    CHECK(res == DecodeResult::Success);
    CHECK(out.next_header == 17);
    CHECK(out.upper_layer_protocol == 17);
    CHECK(out.hop_limit == 128);
    CHECK(out.payload.size() == 4);
}

TEST_CASE("ArpDecoder extracts sender and target addresses") {
    const std::vector<uint8_t> arp_buf = {
        0x00, 0x01,                         // Hardware type: Ethernet (1)
        0x08, 0x00,                         // Protocol type: IPv4 (0x0800)
        0x06,                               // Hardware size: 6
        0x04,                               // Protocol size: 4
        0x00, 0x01,                         // Opcode: Request (1)
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Sender MAC
        192, 168, 1, 100,                   // Sender IP
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Target MAC (unknown)
        192, 168, 1, 1                      // Target IP
    };

    DecodedArp out;
    std::string diag;
    DecodeResult res = ArpDecoder::decode(arp_buf, out, diag);
    CHECK(res == DecodeResult::Success);
    CHECK(out.opcode == 1);
    CHECK(out.sender_mac.to_string() == "00:11:22:33:44:55");
    CHECK(out.sender_ip == "192.168.1.100");
    CHECK(out.target_ip == "192.168.1.1");
}

TEST_CASE("TcpDecoder extracts header, flags and options") {
    std::vector<uint8_t> seg = {
        0x04, 0xd2,                         // Source Port: 1234
        0x00, 0x50,                         // Destination Port: 80
        0x00, 0x00, 0x10, 0x00,             // Seq: 4096
        0x00, 0x00, 0x20, 0x00,             // Ack: 8192
        0x60,                               // Data Offset: 6 (24 bytes)
        0x12,                               // Flags: SYN + ACK (0x02 | 0x10)
        0x72, 0x10,                         // Window Size: 29200
        0x00, 0x00,                         // Checksum
        0x00, 0x00,                         // Urgent Pointer
        0x02, 0x04, 0x05, 0xb4,             // Option: MSS = 1460 (0x05b4)
        0x41, 0x42                          // Payload "AB"
    };

    DecodedTcp out;
    std::string diag;
    DecodeResult res = TcpDecoder::decode(seg, out, diag);
    CHECK(res == DecodeResult::Success);
    CHECK(out.source_port == 1234);
    CHECK(out.destination_port == 80);
    CHECK(out.sequence_number == 4096);
    CHECK(out.acknowledgment_number == 8192);
    CHECK(out.flag_syn == true);
    CHECK(out.flag_ack == true);
    CHECK(out.flag_fin == false);
    CHECK(out.flag_rst == false);
    CHECK(out.window_size == 29200);
    CHECK(out.opt_mss.has_value());
    CHECK(out.opt_mss.value() == 1460);
    CHECK(out.payload.size() == 2);
    CHECK(out.payload[0] == 0x41);
}

TEST_CASE("UdpDecoder verifies ports and payload length") {
    const std::vector<uint8_t> datagram = {
        0x1f, 0x90,                         // Src Port: 8080
        0x00, 0x35,                         // Dst Port: 53 (DNS)
        0x00, 0x0c,                         // Length: 12 (8 header + 4 payload)
        0x00, 0x00,                         // Checksum
        0x01, 0x02, 0x03, 0x04              // Payload
    };

    DecodedUdp out;
    std::string diag;
    DecodeResult res = UdpDecoder::decode(datagram, out, diag);
    CHECK(res == DecodeResult::Success);
    CHECK(out.source_port == 8080);
    CHECK(out.destination_port == 53);
    CHECK(out.length == 12);
    CHECK(out.payload.size() == 4);
}

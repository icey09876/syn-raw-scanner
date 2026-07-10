#pragma once
#include <cstdint>

#pragma pack(push, 1)

struct CustomIPHeader {
    uint8_t  ihl : 4;
    uint8_t  version : 4;
    uint8_t  tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t flags_offset;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dest_ip;
};

struct CustomTCPHeader {
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t seq;
    uint32_t ack_seq;
    uint8_t  reserved : 4;
    uint8_t  doff : 4;
    uint8_t  fin : 1;
    uint8_t  syn : 1;
    uint8_t  rst : 1;
    uint8_t  psh : 1;
    uint8_t  ack : 1;
    uint8_t  urg : 1;
    uint8_t  ece : 1;
    uint8_t  cwr : 1;
    uint16_t window;
    uint16_t checksum;
    uint16_t urg_ptr;
};

#pragma pack(pop)
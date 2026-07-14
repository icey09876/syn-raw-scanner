#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <windows.h>
#include <vector>
#include <thread>
#include <mutex>
#include <iomanip>
#include <cstring>
#include "Protocal.h"

#pragma comment(lib, "ws2_32.lib")
using namespace std;

mutex vec_mtx;
mutex cout_mtx;

void ScanWorker(string ip, int start_port, int end_port, vector<int>& open_ports) {
    for (int port = start_port; port <= end_port; port++) {
        SOCKET server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (server_socket == INVALID_SOCKET) {
            continue;
        } else {
            unsigned long ul = 1;
            ioctlsocket(server_socket, FIONBIO, &ul);
            sockaddr_in server_addr;

            server_addr.sin_family = AF_INET;
            server_addr.sin_port = htons(port);
            server_addr.sin_addr.s_addr = inet_addr(ip.c_str());

            int res = connect(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr));
            if (res == 0) {
                {
                    lock_guard<mutex> lock(vec_mtx);
                    open_ports.push_back(port);
                }
                {
                    lock_guard<mutex> lock(cout_mtx);
                    cout << dec;
                    cout << "port " << port << " is open" << endl;
                }
            } else if (res == SOCKET_ERROR) {
                int err = WSAGetLastError();
                if (err == WSAEWOULDBLOCK || err == WSAEINPROGRESS) {
                    fd_set writeSet;
                    FD_ZERO(&writeSet);
                    FD_SET(server_socket, &writeSet);
                    timeval timeout;
                    timeout.tv_sec = 0;
                    timeout.tv_usec = 100000;
                    int select_res = select(0, NULL, &writeSet, NULL, &timeout);
                    if (select_res > 0) {
                        int socket_err = 0;
                        int len = sizeof(socket_err);
                        getsockopt(server_socket, SOL_SOCKET, SO_ERROR, (char*)&socket_err, &len);
                        if (socket_err == 0) {
                            {
                                lock_guard<mutex> lock(vec_mtx);
                                open_ports.push_back(port);
                            }
                            {
                                lock_guard<mutex> lock(cout_mtx);
                                cout << dec;
                                cout << "port " << port << " is open" << endl;
                            }
                        }
                    }
                }
            }
            closesocket(server_socket);
        }
    }
}

uint16_t CalculateChecksum(uint16_t* addr, int count) {
    uint32_t sum = 0;

    while (count > 1) {
        sum += *addr;
        addr++;
        count -= 2;
    }
    if (count == 1) {
        sum += static_cast<uint32_t>(*(reinterpret_cast<unsigned char*>(addr))) << 8;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return static_cast<uint16_t>(~sum);
}

void SnifferWorker(SOCKET sniffer_socket, vector<int>& open_ports) {
    char recv_buf[65535];
    while (true) {
        sockaddr_in from_addr;
        int from_addr_len = sizeof(from_addr);
        int packet_size = recvfrom(sniffer_socket, recv_buf, sizeof(recv_buf), 0, (struct sockaddr*)&from_addr, &from_addr_len);
        if (packet_size > 0) {
            {
                lock_guard<mutex> lock(cout_mtx);
                cout << "[Sniffer] Successfully intercepted a " << packet_size << " bytes raw packet!" << endl;
            }
        }
    }
}

int main() {
    SetConsoleOutputCP(65001);
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        cout << "WSAStartup failed" << endl;
        return -1;
    } else {
        cout << "WSAStartup success" << endl;
    }

    vector<int> open_ports;

    CustomIPHeader ip_header;
    CustomTCPHeader tcp_header;
    ip_header.version = 4;
    ip_header.ihl = 5;
    ip_header.tos = 0;
    ip_header.total_len = htons(40);
    ip_header.id = htons(12345);
    ip_header.flags_offset = 0;
    ip_header.ttl = 64;
    ip_header.protocol = 6;
    ip_header.checksum = 0;
    ip_header.src_ip = inet_addr("127.0.0.1");
    ip_header.dest_ip = inet_addr("127.0.0.1");

    tcp_header.src_port = htons(12345);
    tcp_header.dest_port = htons(80);
    tcp_header.seq = htonl(1000);
    tcp_header.ack_seq = 0;
    tcp_header.reserved = 0;
    tcp_header.doff = 5;
    tcp_header.fin = 0;
    tcp_header.syn = 1;
    tcp_header.rst = 0;
    tcp_header.psh = 0;
    tcp_header.ack = 0;
    tcp_header.urg = 0;
    tcp_header.ece = 0;
    tcp_header.cwr = 0;
    tcp_header.window = htons(1024);
    tcp_header.checksum = 0;
    tcp_header.urg_ptr = 0;

    char packet_buf[40];
    memset(packet_buf, 0, sizeof(packet_buf));
    memcpy(packet_buf, &ip_header, sizeof(CustomIPHeader));
    memcpy(packet_buf + sizeof(CustomIPHeader), &tcp_header, sizeof(CustomTCPHeader));
    cout << "====================================\n" << endl;

    PseudoHeader pseudo_hdr;
    pseudo_hdr.src_ip = ip_header.src_ip;
    pseudo_hdr.dest_ip = ip_header.dest_ip;
    pseudo_hdr.reserved = 0;
    pseudo_hdr.protocol = ip_header.protocol;
    pseudo_hdr.tcp_len = htons(sizeof(CustomTCPHeader));

    char tcp_check_buf[32];
    memset(tcp_check_buf, 0, sizeof(tcp_check_buf));
    memcpy(tcp_check_buf, &pseudo_hdr, sizeof(pseudo_hdr));
    memcpy(tcp_check_buf + sizeof(pseudo_hdr), &tcp_header, sizeof(tcp_header));

    uint16_t tcp_checksum = CalculateChecksum(reinterpret_cast<uint16_t*>(tcp_check_buf), 32);
    uint16_t ip_checksum = CalculateChecksum(reinterpret_cast<uint16_t*>(packet_buf), 20);
    *(reinterpret_cast<uint16_t*>(packet_buf + 20 + 16)) = htons(tcp_checksum);
    *(reinterpret_cast<uint16_t*>(packet_buf + 10)) = htons(ip_checksum);

    SOCKET sniffer_socket = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if (sniffer_socket != INVALID_SOCKET) {
        sockaddr_in local_addr;
        memset(&local_addr, 0, sizeof(local_addr));
        local_addr.sin_family = AF_INET;
        local_addr.sin_port = 0;
        local_addr.sin_addr.s_addr = ip_header.src_ip;
        bind(sniffer_socket, (struct sockaddr*)&local_addr, sizeof(local_addr));

        unsigned long flag = 1;
        DWORD dwBytesRet = 0;
        WSAIoctl(sniffer_socket, SIO_RCVALL, &flag, sizeof(flag), NULL, 0, &dwBytesRet, NULL, NULL);

        thread sniffer_thread(SnifferWorker, sniffer_socket, ref(open_ports));
        sniffer_thread.detach();
    }

    SOCKET raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if (raw_socket == INVALID_SOCKET) {
        cout << "Raw Socket creation failed! Error: " << WSAGetLastError() << endl;
    } else {
        int one = 1;
        setsockopt(raw_socket, IPPROTO_IP, IP_HDRINCL, (char*)&one, sizeof(one));
        sockaddr_in dest_addr;
        memset(&dest_addr, 0, sizeof(dest_addr));
        dest_addr.sin_family = AF_INET;
        dest_addr.sin_port = htons(80);
        dest_addr.sin_addr.s_addr = ip_header.dest_ip;

        int bytes_sent = sendto(raw_socket, packet_buf, 40, 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr));
        if (bytes_sent == SOCKET_ERROR) {
            cout << "Send failed! Error: " << WSAGetLastError() << endl;
        }
        closesocket(raw_socket);
    }

    vector<thread> threads;
    int thread_count = 10;
    int min = 500;
    int max = 10000;
    int total_ports = max - min + 1;
    int ports_per_thread = total_ports / thread_count;
    int remainder = total_ports % thread_count;
    int start = min;

    for (int i = 0; i < thread_count; ++i) {
        int ports = ports_per_thread + (i < remainder ? 1 : 0);
        int end = start + ports - 1;
        if (end > max) end = max;
        threads.push_back(thread(ScanWorker, "127.0.0.1", start, end, ref(open_ports)));
        start = end + 1;
    }

    for (auto& th : threads) {
        if (th.joinable()) {
            th.join();
        }
    }

    if (sniffer_socket != INVALID_SOCKET) {
        closesocket(sniffer_socket);
    }

    WSACleanup();
    return 0;
}
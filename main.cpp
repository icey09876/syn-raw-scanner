#include <iostream>
#include <winsock2.h>
#include <windows.h>
#include <vector>
#include <thread>
#include <mutex>
#include <iomanip>
#include <cstring>
#include "Protocal.h"

#pragma comment(lib,"ws2_32.lib")
using namespace std;

mutex vec_mtx;
mutex cout_mtx;

void ScanWorker(string ip, int start_port, int end_port, vector<int>& open_ports) {
    int port;
    for (port = start_port; port <= end_port; port++) {
        SOCKET server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (server_socket == INVALID_SOCKET) {
            cout << "Socket creation failed! Error code: " << WSAGetLastError() << endl;
            continue;
        } else {
            unsigned long ul = 1;
            ioctlsocket(server_socket, FIONBIO, &ul);
            sockaddr_in server_addr;

            server_addr.sin_family = AF_INET;
            server_addr.sin_port = htons(port);
            server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

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
    CustomIPHeader ip_header;
    CustomTCPHeader tcp_header;
    ip_header.version = 4;
    ip_header.ihl = 5;
    ip_header.tos = 0;
    ip_header.total_len = htons(40);
    ip_header.id = htons(12345);
    ip_header.flags_offset = htons(0);
    ip_header.ttl = 64;
    ip_header.protocol = 6;
    ip_header.checksum = 0;
    ip_header.src_ip = htonl(0x7F000001);
    ip_header.dest_ip = htonl(0x7F000001);
    tcp_header.src_port = htons(12345);
    tcp_header.dest_port = htons(80);
    tcp_header.seq = htonl(1000);
    tcp_header.ack_seq = htonl(0);
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
    tcp_header.urg_ptr = htons(0);
    char packet_buf[40];
    memset(packet_buf, 0, sizeof(packet_buf));
    memcpy(packet_buf, &ip_header, sizeof(CustomIPHeader));
    memcpy(packet_buf + sizeof(CustomIPHeader), &tcp_header, sizeof(CustomTCPHeader));
    cout << "====================================\n" << endl;
    vector<thread> threads;
    int thread_count = 10;
    vector<int> open_ports;
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
    uint16_t ip_checksum = CalculateChecksum(reinterpret_cast<uint16_t*>(packet_buf), 20);
    cout << "Calculated IP Checksum: 0x" << hex << uppercase << ip_checksum << endl;
    WSACleanup();
    return 0;
}
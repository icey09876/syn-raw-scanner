#include <iostream>
#include <vector>
#include <string>
#include <mutex>
#include <cstring>
#include <atomic>
#include <thread>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include "Protocal.h"
#include <queue>
#include <condition_variable>

using namespace std;

mutex vec_mtx;
mutex cout_mtx;
atomic<bool> keep_running(true);

queue<int> port_queue;
mutex queue_mtx;
condition_variable cv;
bool all_ports_added = false;


uint16_t CalculateChecksum(uint16_t* addr, int count) {
    uint32_t sum = 0;
    while (count > 1) {
        sum += *addr++;
        count -= 2;
    }
    if (count == 1) {
        sum += *(reinterpret_cast<uint8_t*>(addr)) << 8;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return static_cast<uint16_t>(~sum);
}

void BuildSynPacket(char* packet_buf,const string& src_ip,const string& dest_ip,uint16_t src_port, uint16_t dest_port, uint32_t seq){
    CustomIPHeader ip_header;
    CustomTCPHeader tcp_header;
    memset(&ip_header, 0, sizeof(ip_header));
    memset(&tcp_header, 0, sizeof(tcp_header));

    ip_header.version = 4;
    ip_header.ihl = 5;
    ip_header.tos = 0;
    ip_header.total_len = htons(40);
    ip_header.id = htons(12345);
    ip_header.flags_offset = 0;
    ip_header.ttl = 64;
    ip_header.protocol = IPPROTO_TCP;
    ip_header.checksum = 0;
    ip_header.src_ip = inet_addr(src_ip.c_str());
    ip_header.dest_ip = inet_addr(dest_ip.c_str());

    tcp_header.src_port = htons(src_port);
    tcp_header.dest_port = htons(dest_port);
    tcp_header.seq = htonl(seq);
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

    memcpy(packet_buf, &ip_header, sizeof(CustomIPHeader));
    memcpy(packet_buf + sizeof(CustomIPHeader), &tcp_header, sizeof(CustomTCPHeader));

    PseudoHeader pseudo_hdr;
    pseudo_hdr.src_ip = ip_header.src_ip;
    pseudo_hdr.dest_ip = ip_header.dest_ip;
    pseudo_hdr.reserved = 0;
    pseudo_hdr.protocol = ip_header.protocol;
    pseudo_hdr.tcp_len = htons(sizeof(CustomTCPHeader));

    const int tcp_check_size = sizeof(PseudoHeader) + sizeof(CustomTCPHeader);
    vector<char> tcp_check_buf(tcp_check_size, 0);
    memcpy(tcp_check_buf.data(), &pseudo_hdr, sizeof(pseudo_hdr));
    memcpy(tcp_check_buf.data() + sizeof(pseudo_hdr), &tcp_header, sizeof(tcp_header));

    uint16_t tcp_checksum = CalculateChecksum(reinterpret_cast<uint16_t*>(tcp_check_buf.data()), tcp_check_size);
    uint16_t ip_checksum = CalculateChecksum(reinterpret_cast<uint16_t*>(packet_buf), sizeof(CustomIPHeader));
    *(reinterpret_cast<uint16_t*>(packet_buf + sizeof(CustomIPHeader) + 16)) = tcp_checksum;
    *(reinterpret_cast<uint16_t*>(packet_buf + 10)) = ip_checksum;
}

int ParseResponsePacket(char* recv_buf, int packet_size, uint16_t my_port, uint32_t expct_ack) {
    if (packet_size < static_cast<int>(sizeof(CustomIPHeader))) return -1;

    CustomIPHeader* ip = reinterpret_cast<CustomIPHeader*>(recv_buf);
    if (ip->version == 4) {
        int ip_header_len = ip->ihl * 4;
        if (packet_size < ip_header_len + static_cast<int>(sizeof(CustomTCPHeader))) return -1;

        CustomTCPHeader* tcp = reinterpret_cast<CustomTCPHeader*>(recv_buf + ip_header_len);
        uint16_t src_port = ntohs(tcp->src_port);
        uint16_t dest_port = ntohs(tcp->dest_port);
        uint32_t ack_seq = ntohl(tcp->ack_seq);

        if (dest_port == my_port && ack_seq == expct_ack) {
            if (tcp->syn == 1 && tcp->ack == 1) {
                return src_port;
            }
        }
    }
    return -1;
}

void SendWorker(int raw_socket, string src_ip, string dest_ip, uint16_t my_port, uint32_t seq) {
    while (true) {
        int port;
        {
            unique_lock<mutex> lock(queue_mtx);

            cv.wait(lock, [] {
                return !port_queue.empty() || all_ports_added;
            });

            if (port_queue.empty() && all_ports_added) {
                return;
            }

            port = port_queue.front();
            port_queue.pop();
        }
        char packet_buf[40];
        BuildSynPacket(packet_buf, src_ip, dest_ip, my_port, port, seq);
        sockaddr_in dest_addr;
        memset(&dest_addr, 0, sizeof(dest_addr));
        dest_addr.sin_family = AF_INET;
        dest_addr.sin_port = htons(port);
        dest_addr.sin_addr.s_addr = inet_addr(dest_ip.c_str());
        int sent = sendto(raw_socket, packet_buf, 40, 0, (struct sockaddr *) &dest_addr, sizeof(dest_addr));
        if (sent < 0) {
            lock_guard<mutex> lock(cout_mtx);
            cout << "sendto failed, errno: " << errno << " (" << strerror(errno) << ")" << endl;
        }
        usleep(500);
    }
}

void RecvWorker(int raw_socket, uint16_t my_port, uint32_t seq, vector<int>* open_ports) {
    char recv_buf[65535];

    while (keep_running) {
        sockaddr_in from_addr;
        socklen_t from_addr_len = sizeof(from_addr);
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(raw_socket, &readfds);
        struct timeval timeout={1,0};

        int ret = select(raw_socket + 1, &readfds, NULL, NULL, &timeout);
        if (ret < 0) {
            if (errno == EINTR) continue;
            break;
        }else if(ret == 0) {
            continue;
        }
        if (FD_ISSET(raw_socket, &readfds)) {
            int packet_size = recvfrom(raw_socket, recv_buf, sizeof(recv_buf), 0, (struct sockaddr*)&from_addr, &from_addr_len);
            if (packet_size > 0) {
                int open_port = ParseResponsePacket(recv_buf, packet_size, my_port, seq + 1);
                if (open_port > 0) {
                    lock_guard<mutex> lock(vec_mtx);
                    open_ports->push_back(open_port);
                }
            }
        }
    }
}

int main() {
    string src_ip ="172.25.176.246";
    string dest_ip = "192.168.31.1";
    uint16_t my_port = 12345;
    uint32_t seq = 1000;
    vector<int> open_ports;
    int start_port = 1;
    int end_port = 10000;
    int num_threads = 4;

    int raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (raw_socket == -1) {
        cout << "Raw Socket creation failed! Error: " << errno << endl;
        return -1;
    } else {
        int one = 1;
        if (setsockopt(raw_socket, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
            cout << "setsockopt IP_HDRINCL failed, errno: " << errno << endl;
            close(raw_socket);
        }
    }

    thread recv_th(RecvWorker, raw_socket, my_port, seq, &open_ports);

    vector<thread> send_th;
    for (int i = 0; i < num_threads; i++) {
        send_th.push_back(thread(SendWorker, raw_socket, src_ip, dest_ip, my_port, seq));
    }

    {
        lock_guard<mutex> lock(queue_mtx);
        for (int port = start_port; port <= end_port; port++) {
            port_queue.push(port);
        }
        all_ports_added = true;
    }
    cv.notify_all();

    for (auto& th : send_th) {
        if (th.joinable()) {
            th.join();
        }
    }

    this_thread::sleep_for(chrono::seconds(2));
    keep_running = false;
    recv_th.join();
    for (int p:open_ports) {
        cout <<"open port:"<< p << endl;
    }
    close(raw_socket);
    return 0;
}
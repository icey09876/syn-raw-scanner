#include <iostream>
#include <vector>
#include <string>
#include <mutex>
#include <cstring>
#include <atomic>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include "Protocal.h"
using namespace std;

mutex vec_mtx;
mutex cout_mtx;
atomic<bool> keep_running(true);

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
    ip_header.protocol = IPPROTO_TCP; // 6
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
int ParseResponsePacket(char* recv_buf, int packet_size, uint16_t expct_src_port, uint16_t expct_dest_port, uint32_t expct_ack) {
    if (packet_size < static_cast<int>(sizeof(CustomIPHeader))) {
        return -1;
    }
    CustomIPHeader* ip = reinterpret_cast<CustomIPHeader*>(recv_buf);

    if (ip->version == 4) {
        int ip_header_len = ip->ihl * 4;
        if (packet_size < ip_header_len + static_cast<int>(sizeof(CustomTCPHeader))) {
            return -1;
        }
        CustomTCPHeader* tcp = reinterpret_cast<CustomTCPHeader*>(recv_buf + ip_header_len);
        uint16_t src_port = ntohs(tcp->src_port);
        uint16_t dest_port = ntohs(tcp->dest_port);
        uint32_t ack_seq = ntohl(tcp->ack_seq);
        if (src_port == expct_src_port && dest_port == expct_dest_port && ack_seq == expct_ack) {
            if (tcp->syn == 1 && tcp->ack == 1) {
                return 1;
            } else if (tcp->rst == 1) {
                return 0;
            }
        }
    }
    return -1;

}

/*void ScanWorker(string ip, int start_port, int end_port, vector<int>& open_ports) {
    for (int port = start_port; port <= end_port; port++) {
        int server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (server_socket == -1) {
            continue;
        }

        int flags = fcntl(server_socket, F_GETFL, 0);
        if (flags != -1) {
            fcntl(server_socket, F_SETFL, flags | O_NONBLOCK);
        }

        sockaddr_in server_addr;
        memset(&server_addr, 0, sizeof(server_addr));
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
                cout << "port " << port << " is open" << endl;
            }
        } else if (res == -1) {
            int err = errno;
            if (err == EWOULDBLOCK || err == EAGAIN || err == EINPROGRESS) {
                fd_set writeSet;
                FD_ZERO(&writeSet);
                FD_SET(server_socket, &writeSet);
                timeval timeout;
                timeout.tv_sec = 0;
                timeout.tv_usec = 100000;


                int select_res = select(server_socket + 1, NULL, &writeSet, NULL, &timeout);
                if (select_res > 0) {
                    int socket_err = 0;
                    socklen_t len = sizeof(socket_err);
                    getsockopt(server_socket, SOL_SOCKET, SO_ERROR, &socket_err, &len);
                    if (socket_err == 0) {
                        {
                            lock_guard<mutex> lock(vec_mtx);
                            open_ports.push_back(port);
                        }
                        {
                            lock_guard<mutex> lock(cout_mtx);
                            cout << "port " << port << " is open" << endl;
                        }
                    }
                }
            }
        }
        close(server_socket);
    }
}*/

void SnifferWorker(int sniffer_socket, vector<int>& open_ports) {
    char recv_buf[65535];

    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    if (setsockopt(sniffer_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        lock_guard<mutex> lock(cout_mtx);
        cout << "Failed to set recv timeout, errno: " << errno << endl;
        return;
    }

    while (keep_running) {
        sockaddr_in from_addr;
        socklen_t from_addr_len = sizeof(from_addr);

        int packet_size = recvfrom(sniffer_socket, recv_buf, sizeof(recv_buf), 0, (struct sockaddr*)&from_addr, &from_addr_len);
        if (packet_size < 0) {
            if (errno == EBADF || !keep_running) {
                break;
            }
            continue;
        }
    }
}

int main() {
    string source_ip ="172.25.176.246";
    string target_ip = "192.168.31.142";
    uint16_t my_port = 12345;
    uint16_t target_port = 80;
    uint32_t my_seq = 1000;
    vector<int> open_ports;

    /*int sniffer_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    thread sniffer_thread;
    if (sniffer_socket != -1) {
        sockaddr_in local_addr;
        memset(&local_addr, 0, sizeof(local_addr));
        local_addr.sin_family = AF_INET;
        local_addr.sin_port = 0;
        local_addr.sin_addr.s_addr = ip_header.src_ip;
        bind(sniffer_socket, (struct sockaddr*)&local_addr, sizeof(local_addr));

        sniffer_thread = thread(SnifferWorker, sniffer_socket, ref(open_ports));
    }*/

    int raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (raw_socket == -1) {
        cout << "Raw Socket creation failed! Error: " << errno << endl;
    } else {
        int one = 1;
        if (setsockopt(raw_socket, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
            cout << "setsockopt IP_HDRINCL failed, errno: " << errno << endl;
            close(raw_socket);
            return -1;
        }
        struct timeval timeout;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        setsockopt(raw_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        char packet_buf[40];
        BuildSynPacket(packet_buf, source_ip, target_ip, my_port, target_port, my_seq);
        sockaddr_in dest_addr;
        memset(&dest_addr, 0, sizeof(dest_addr));
        dest_addr.sin_family = AF_INET;
        dest_addr.sin_port = htons(80);
        dest_addr.sin_addr.s_addr = inet_addr(target_ip.c_str());
        int sent = sendto(raw_socket, packet_buf, 40, 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr));
        if (sent < 0) {
            cout << "sendto failed, errno: " << errno << " (" << strerror(errno) << ")" << endl;
        } else {
            cout << "sent " << sent << " bytes" << endl;
        }
        char recv_buf[65535];
        sockaddr_in from_addr;
        socklen_t from_addr_len = sizeof(from_addr);

        while (true){
            int packet_size = recvfrom(raw_socket, recv_buf, sizeof(recv_buf), 0, (struct sockaddr*)&from_addr, &from_addr_len);
            if (packet_size > 0) {
                int result = ParseResponsePacket(recv_buf, packet_size, target_port, my_port, my_seq + 1);
                if (result==1) {
                    cout << "Port " << target_port << " is open (SYN-ACK received)!" << endl;
                    open_ports.push_back(target_port);
                    break;
                } else if (result == 0) {
                    cout << "Port " << target_port << " is closed (RST received)." << endl;
                    break;

            }

            }else {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    cout << "Port 80 Timeout (Filtered/Closed)." << endl;
                } else {
                    cout << "Recv error, errno: " << errno << endl;
                }
                break;
            }

        }
    }
    /*vector<thread> threads;
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

    this_thread::sleep_for(chrono::milliseconds(500));

    keep_running = false;
    if (sniffer_socket != -1) {
        close(sniffer_socket);
    }

    if (sniffer_thread.joinable()) {
        sniffer_thread.join();
    }

    cout << "\n--- Final Open Ports List ---" << endl;
    {
        lock_guard<mutex> lock(vec_mtx);
        for (int p : open_ports) {
            cout << p << " ";
        }
        cout << endl;
    }*/

    close(raw_socket);
    return 0;
}
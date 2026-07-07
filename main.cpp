#include <iostream>
#include <winsock2.h>
#include <windows.h>
#include <vector>
#include <thread>
#include <mutex>
#include "CustomTCPHeader.h"
#pragma comment(lib,"ws2_32.lib")
using namespace std;


mutex vec_mtx;
mutex cout_mtx;
void ScanWorker(string ip,int start_port,int end_port,vector<int>& open_ports) {

        int port;
        for (port= start_port;port<= end_port;port++){
            SOCKET server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (server_socket == INVALID_SOCKET) {
                cout << "Socket creation failed! 错误码是: " << WSAGetLastError() << endl;
                continue;
            } else {
                //cout << "Socket creation success! Handle ID is: " << server_socket << endl;
                unsigned long ul=1;

                ioctlsocket(server_socket,FIONBIO,&ul);
                sockaddr_in server_addr;

                server_addr.sin_family = AF_INET;
                server_addr.sin_port = htons(port);
                server_addr.sin_addr.s_addr=inet_addr("127.0.0.1");


                int res = connect(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr));
                if (res==0) {
                    {
                        lock_guard<mutex> lock(vec_mtx);
                        open_ports.push_back(port);
                    }
                    {
                        lock_guard<mutex> lock(cout_mtx);
                        cout << "port " << port <<" is open"<< endl;
                    }

                }else if (res == SOCKET_ERROR) {
                    int err = WSAGetLastError();
                    if (err == WSAEWOULDBLOCK || err == WSAEINPROGRESS) {
                        fd_set writeSet;
                        FD_ZERO(&writeSet);
                        FD_SET(server_socket, &writeSet);
                        timeval timeout;
                        timeout.tv_sec = 0;
                        timeout.tv_usec = 100000;
                        int select_res = select(0,NULL, &writeSet,  NULL, &timeout);
                        if (select_res >0) {
                            int socket_err = 0;
                            int len = sizeof(socket_err);
                            getsockopt(server_socket, SOL_SOCKET, SO_ERROR, (char*)&socket_err, &len);
                            if (socket_err==0) {
                                {lock_guard<mutex> lock(vec_mtx);
                                    open_ports.push_back(port);
                                }
                                {
                                    lock_guard<mutex> lock(cout_mtx);
                                    cout << "port " << port <<" is open"<< endl;
                                }


                            }


                        }//else{

                        //cout<<"port "<<port <<" disconnected"<<endl;
                        //}
                    }

                }
                closesocket(server_socket);
            }
        }

}

int main() {
    SetConsoleOutputCP(65001);

    WSADATA wsaData;
    int result =WSAStartup(MAKEWORD(2,2),&wsaData);
    if(result != 0) {
        cout << "WSAStartup failed" << endl;
        return -1;
    }else {
        cout << "WSAStartup success" << endl;
    }
    vector<thread> threads;
    int thread_count=10;


    vector<int> open_ports;
    int min = 500;
    int max =10000;
    int total_ports = max - min + 1;
    int ports_per_thread = total_ports / thread_count;
    int remainder = total_ports % thread_count;

    int start=min;

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

    WSACleanup();

    return 0;

}

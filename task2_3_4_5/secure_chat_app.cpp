#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <typeinfo>
#include <string>
#include <cstring>
#include <chrono>
#include <thread>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/opensslv.h>
#include <fcntl.h>

#define SERVER_PORT 9090
#define MAX_BUFFER_SIZE 1024

using namespace std;

int socket_descriptor;
char mode;
struct timeval timeout;


void initialize_openssl() {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_ssl_algorithms();
        ERR_load_crypto_strings();
}

SSL_CTX* create_server_context() {
        const SSL_METHOD *method = DTLSv1_2_server_method();
        SSL_CTX *ctx = SSL_CTX_new(method);
        if (!ctx) {
                perror("Unable to create SSL context");
                ERR_print_errors_fp(stderr);
                exit(EXIT_FAILURE);
        }
        return ctx;
}

SSL_CTX* create_client_context() {
    const SSL_METHOD* method = DTLSv1_2_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        std::cerr << "Unable to create SSL context" << std::endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

int generateCookie(SSL *ssl_context, unsigned char *session_cookie, unsigned int *cookie_len) {
    memcpy(session_cookie,"having",6);
    *cookie_len = 6;
    return 1;
}   

int verifyCookie(SSL *ssl_context, const unsigned char *session_cookie, unsigned int cookie_len) {
    return 1; 
}

void configure_context(SSL_CTX *ctx, const char * crt_path, const char * key_path, const char * CA_crt_path) {
        SSL_CTX_set_ecdh_auto(ctx, 1);
        if (SSL_CTX_use_certificate_file(ctx, crt_path, SSL_FILETYPE_PEM) <= 0) {
                ERR_print_errors_fp(stderr);
                exit(EXIT_FAILURE);
        }

        if (SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) <= 0 ) {
                ERR_print_errors_fp(stderr);
                exit(EXIT_FAILURE);
        }

        if(!SSL_CTX_check_private_key(ctx)){
                cout << " Private Key Verification failed!\n";
                exit(0);
        }

        if (!SSL_CTX_load_verify_locations(ctx, CA_crt_path, NULL)) {
                ERR_print_errors_fp(stderr);
                exit(EXIT_FAILURE);
        }

        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

        SSL_CTX_set_security_level(ctx, 1);
        SSL_CTX_set_cipher_list(ctx,"ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384");
        SSL_CTX_set_mode(ctx,SSL_MODE_AUTO_RETRY);
        SSL_CTX_set_session_cache_mode(ctx,SSL_SESS_CACHE_OFF);
        SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL);
        SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER);
        SSL_CTX_set_session_id_context(ctx, (const unsigned char *)"DTLS", strlen("DTLS"));

        if(mode=='s'){
                SSL_CTX_set_cookie_generate_cb(ctx,generateCookie);
                SSL_CTX_set_cookie_verify_cb(ctx,&verifyCookie);   
        }
}

void setup_nonblocking(){
        int fcntl_check = fcntl(socket_descriptor, F_GETFL, 0);
        if (fcntl_check == -1) {
                perror("F_GETFL error\n");
                exit(1);
        }

        if (fcntl(socket_descriptor, F_SETFL, fcntl_check | O_NONBLOCK) == -1) {
                perror("F_SETFL error\n");
                exit(1);
        }
}

void server()
{
        cout << "Server started...\n \n";
        
        struct sockaddr_in server_address, client_address;
        string ack;
        bool condition = true;
        bool flag_last_ack = false;

        memset(&server_address, 0, sizeof(server_address));
        memset(&client_address, 0, sizeof(client_address));

        server_address.sin_family = AF_INET;
        server_address.sin_addr.s_addr = INADDR_ANY;
        server_address.sin_port = htons(SERVER_PORT);

        if (bind(socket_descriptor, (const struct sockaddr *)&server_address, sizeof(server_address)) < 0) {
                cout << "Binding Failure\n";
                exit(EXIT_FAILURE);
        }

        while(condition) {
                char buffer[MAX_BUFFER_SIZE];
                int received_message_len;
                unsigned int len = sizeof(client_address);

                fd_set readfds;
                FD_ZERO(&readfds);
                FD_SET(socket_descriptor, &readfds);
                timeout.tv_sec = 5;
                timeout.tv_usec = 0;

                int activity = select(socket_descriptor + 1, &readfds, NULL, NULL, &timeout);
                if (activity < 0) {
                        perror("Error in select");
                        exit(EXIT_FAILURE);
                } else if (activity == 0) {
                        if(flag_last_ack == false){
                                printf("Timeout occurred. No data received.\n");
                                continue;
                        }
                }
                
                memset(buffer, 0, sizeof(buffer));
                received_message_len = recvfrom(socket_descriptor, (char *)buffer, MAX_BUFFER_SIZE, 0, (struct sockaddr *) &client_address, &len);
                buffer[received_message_len] = '\0';
                if(flag_last_ack == true && strcmp(buffer,"chat_START_SSL")!=0){
                        break;
                }
                cout << "Client : " << buffer << " received \n";
                if(strcmp(buffer,"chat_hello")==0)
                        ack = "chat_ok";
                else if(strcmp(buffer,"chat_START_SSL")==0)
                        ack = "chat_START_SSL_ACK";
                else{
                        ack="";
                }
                if(ack!=""){
                        cout << "Server (You) : " << ack << " sent\n";
                }
                else{
                        if(strcmp(buffer,"chat_close")==0){
                                condition = false;
                                break;
                        }
                        cout << "Server (You) : ";
                        getline(cin,ack);
                }

                sendto(socket_descriptor, ack.c_str(), ack.length(), 0, (const struct sockaddr *) &client_address, len);
                if(ack == "chat_START_SSL_ACK"){
                        flag_last_ack = true;
                        continue;
                        break;
                }
                else if(ack == "chat_close"){
                        condition = false;
                        break;
                }
        }
        if(condition){
                initialize_openssl();
                cout << "Server OpenSSL initialized \n";

                SSL_CTX *ctx = create_server_context();
                configure_context(ctx,"bob1/bob1_crt_chain.crt","bob1/bob1.pem", "intCA/intCA_crt_chain.crt");
                cout << "Server Context Configured Success \n";

                BIO *bio = BIO_new_dgram(socket_descriptor, BIO_NOCLOSE);
                BIO_ctrl(bio,BIO_CTRL_DGRAM_SET_RECV_TIMEOUT,0,&timeout);
                if (!bio) {
                        ERR_print_errors_fp(stderr);
                        exit(EXIT_FAILURE);
                }
                char buffer[MAX_BUFFER_SIZE];
                unsigned int len = sizeof(client_address);

                SSL* ssl = SSL_new(ctx);
                SSL_set_options(ssl,SSL_OP_COOKIE_EXCHANGE);
                SSL_set_bio(ssl, bio, bio);
                setup_nonblocking();
                int connection = 0;
                int retry = 0;
                do{
                        connection = DTLSv1_listen(ssl, (BIO_ADDR *) &server_address);
                }
                while(connection <= 0);
                        
                do{
                        connection = SSL_accept(ssl);
                }
                while(connection <= 0);

                if(SSL_get_peer_certificate(ssl) && SSL_get_verify_result(ssl) == X509_V_OK)
                        cout << "Certificate Verification successfull.\n";
                
                cout << "Client connected with DTLSv1.2\n";

                cout << "\n--------------------------------------------\n" << endl;
                while(true){
                        fd_set readfds;
                        FD_ZERO(&readfds);
                        FD_SET(socket_descriptor, &readfds);
                        timeout.tv_sec = 5;
                        timeout.tv_usec = 0;
                        int activity = select(socket_descriptor + 1, &readfds, NULL, NULL, &timeout);
                        if (activity < 0) {
                                perror("Error in select\n");
                                exit(EXIT_FAILURE);
                        } else if (activity == 0) {
                                printf("Timeout occurred. No data received.\n");
                                continue;
                        }
                        
                        memset(buffer, 0, sizeof(buffer));
                        int received_message_len = SSL_read(ssl, buffer, sizeof(buffer) - 1);
                        if (received_message_len <= 0) {
                                int ssl_error = SSL_get_error(ssl, received_message_len);
                                if (ssl_error == SSL_ERROR_ZERO_RETURN || ssl_error == SSL_ERROR_SYSCALL) {
                                        break;
                                }
                        } else {
                                buffer[received_message_len] = '\0';
                                cout << "Client: " << buffer << std::endl;
                                if (strcmp(buffer, "chat_close") == 0) {
                                        break;
                                }
                        }
                        string msg;
                        cout << "Server (You) : ";
                        getline(cin,msg);
                        SSL_write(ssl, msg.c_str(), msg.length());
                        if (msg == "chat_close") {
                                break;
                        }
                }
                SSL_free(ssl);
                SSL_CTX_free(ctx);
                EVP_cleanup();
        }
        cout << "Server closed\n";
}

void client(char* arg){
        string server_host_name(arg);
        cout << "Client started...\n \n";
        struct hostent *address;
        address = gethostbyname(arg);
        string server_host_address = inet_ntoa(*(struct in_addr*)address->h_addr);
        cout << "Client connecting to server " << server_host_name << " with "<< server_host_address <<"\n \n";
        struct sockaddr_in server_address;
        bool condition = true;


        if ((socket_descriptor = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
                perror("socket creation failed\n");
                exit(EXIT_FAILURE);
        }

        memset(&server_address, 0, sizeof(server_address));

        server_address.sin_family = AF_INET;
        server_address.sin_port = htons(SERVER_PORT);
        server_address.sin_addr.s_addr = inet_addr(server_host_address.c_str());

        string msg = "chat_hello";
        string print_msg = "You : chat_hello sent\n";
        char buffer[MAX_BUFFER_SIZE];

        if(connect(socket_descriptor,(struct sockaddr*) &server_address,sizeof(server_address))){
                cout << " Error in connecting socket from client\n";
                exit(0);
        }
        
        while(condition){
                int received_message_len, len;
                if(msg==""){
                        cout << "You :";
                        getline(cin,msg);
                }else{
                        cout << print_msg;
                }
                sendto(socket_descriptor, msg.c_str(), msg.length(), 0, (const struct sockaddr *) &server_address, sizeof(server_address));
                if(msg == "chat_close"){
                        condition = false;
                        break;
                }
                fd_set readfds;
                FD_ZERO(&readfds);
                FD_SET(socket_descriptor, &readfds);        
                timeout.tv_sec = 5;
                timeout.tv_usec = 0;
                int activity = select(socket_descriptor + 1, &readfds, NULL, NULL, &timeout);
                if (activity < 0) {
                        perror("Error in select\n");
                        exit(EXIT_FAILURE);
                } else if (activity == 0) {
                        printf("Timeout occurred. No data received.\n");
                        continue;
                }
                
                memset(buffer, 0, sizeof(buffer));
                received_message_len = recvfrom(socket_descriptor, (char *)buffer, MAX_BUFFER_SIZE, 0, (struct sockaddr *) &server_address, (socklen_t *)&len);
                buffer[received_message_len] = '\0';
                cout << "Server : " << buffer << " received \n";
                if(strcmp(buffer,"chat_ok")==0){
                        msg = "chat_START_SSL";
                        print_msg = "You : chat_START_SSL sent\n";
                }
                else if(strcmp(buffer,"chat_START_SSL_ACK")==0){
                        std::this_thread::sleep_for(std::chrono::milliseconds(5000));
                        break;
                }
                else if(strcmp(buffer,"chat_close")==0){
                        condition = false;
                        break;
                }
                else{
                        msg="";
                }
                
        }

        if(condition){

                initialize_openssl();

                cout << "Client OpenSSL initializded \n";
                
                SSL_CTX* ctx = create_client_context();
                if(!ctx)
                        cout << "context error";
                configure_context(ctx,"alice1/alice1_crt_chain.crt","alice1/alice1.pem","intCA/intCA_crt_chain.crt");
                SSL* ssl = SSL_new(ctx);
                if (!ssl) {
                        cout << "ssl error\n";
                }
                SSL_set_fd(ssl, socket_descriptor);
                setup_nonblocking();
                cout << "Client Context Configured Success \n";
                int connection;
                do{
                       connection = SSL_connect(ssl);
                }while(connection <=0 );
                if(SSL_get_peer_certificate(ssl) && SSL_get_verify_result(ssl) == X509_V_OK)
                        cout << "Certificate Verification successfull. \n";
                
                cout << "Client connected with DTLSv1.2\n";

                cout << "\n--------------------------------------------\n" << endl;
                while(true){
                        string msg;
                        cout << "You : ";
                        getline(cin,msg);
                        SSL_write(ssl, msg.c_str(), msg.length());
                        if (msg == "chat_close") {
                                break;
                        }

                        fd_set readfds;
                        FD_ZERO(&readfds);
                        FD_SET(socket_descriptor, &readfds);
                        timeout.tv_sec = 5;
                        timeout.tv_usec = 0;
                        int activity = select(socket_descriptor + 1, &readfds, NULL, NULL, &timeout);
                        if (activity < 0) {
                                perror("Error in select");
                                exit(EXIT_FAILURE);
                        } else if (activity == 0) {
                                printf("Timeout occurred. No data received.\n");
                                continue;
                        }
                        
                        memset(buffer, 0, sizeof(buffer));
                        int received_message_len = SSL_read(ssl, buffer, sizeof(buffer) - 1);
                        if (received_message_len <= 0) {
                                int ssl_error = SSL_get_error(ssl, received_message_len);
                                if (ssl_error == SSL_ERROR_ZERO_RETURN || ssl_error == SSL_ERROR_SYSCALL) {
                                break;
                                }
                        } else {
                                buffer[received_message_len] = '\0';
                                cout << "Server: " << buffer << endl;
                                if (strcmp(buffer, "chat_close") == 0) {
                                        break;
                                }
                        }
                }
                SSL_free(ssl);
                SSL_CTX_free(ctx);
                EVP_cleanup();
        }
        cout << "Client closed\n";
}
        

int main(int argc, char* argv[])
{
        if(argc <= 1){
                cout << "Please enter proper application mode\n";
                cout << "Usage: ./secure_chat_app [OPTIONS] OBJECT \n\n       OPTIONS := { -s[erver] | -c[lient] } \n       OBJECT := { hostname }";
                exit(EXIT_FAILURE);
        }
        else{
                socket_descriptor = socket(AF_INET,SOCK_DGRAM,0);
                if(socket_descriptor < 0){
                        cout << "Socket Creation Failure\n";
                        exit(EXIT_FAILURE);  
                }
                int reuse = 1;
                setsockopt(socket_descriptor, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
                if(argv[1][1] == 's')
                {       mode = 's';
                        server();                        
                }  
                else if(argv[1][1] == 'c')
                {       mode = 'c';
                        client(argv[2]);
                }
        }
        close(socket_descriptor);
        return 0;
}


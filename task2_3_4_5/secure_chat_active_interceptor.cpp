#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <typeinfo>
#include <string>
#include <cstring>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/opensslv.h>
#include <fcntl.h>

#define SERVER_PORT 9090
#define MAX_BUFFER_SIZE 1024

using namespace std;

struct timeval timeout;
string client_host_name, server_host_name;
int fake_server_socket_descriptor,fake_client_socket_descriptor;
struct sockaddr_in fake_server_address, client_address,server_address;
bool modifying_flag;

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


void configure_context(SSL_CTX *ctx, const char * crt_path, const char * key_path, const char * CA_crt_path, char mode) {
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
        timeout.tv_sec = 3;
        timeout.tv_usec = 0;
}

void setup_nonblocking(char mode){
        int socket_descriptor;
        if (mode == 's'){
                socket_descriptor = fake_server_socket_descriptor;
        }
        else if(mode == 'c'){
                socket_descriptor = fake_client_socket_descriptor;
        }
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

void initialize_2_way_dtls(){
        initialize_openssl();
        setup_nonblocking('c');
        setup_nonblocking('s');

        cout << "OpenSSL initializded \n";        
        SSL_CTX* ctx_client = create_client_context();
        if(!ctx_client)
                cout << "context error";
        SSL_CTX *ctx_server = create_server_context();
        if(!ctx_server)
                cout << "context error";

        configure_context(ctx_client,"alice1/alice1_crt_chain.crt","alice1/alice1.pem","intCA/intCA_crt_chain.crt",'c');
        cout << "Fake_client Context Configured Success \n";
        configure_context(ctx_server,"bob1/bob1_crt_chain.crt","bob1/bob1.pem", "intCA/intCA_crt_chain.crt",'s');
        cout << "Fake_server Context Configured Success \n";

        SSL* ssl_client = SSL_new(ctx_client);
        if (!ssl_client) {
                cout << "ssl error\n";
        }
        SSL_set_fd(ssl_client, fake_client_socket_descriptor);

        BIO *bio = BIO_new_dgram(fake_server_socket_descriptor, BIO_NOCLOSE);
        BIO_ctrl(bio,BIO_CTRL_DGRAM_SET_RECV_TIMEOUT,0,&timeout);
        if (!bio) {
                ERR_print_errors_fp(stderr);
                exit(EXIT_FAILURE);
        }
        char buffer[MAX_BUFFER_SIZE];
        SSL* ssl_server = SSL_new(ctx_server);
        SSL_set_options(ssl_server,SSL_OP_COOKIE_EXCHANGE);
        SSL_set_bio(ssl_server, bio, bio);
        int connection;
        do{
                connection = DTLSv1_listen(ssl_server, (BIO_ADDR *) &fake_server_address);
        }
        while(connection <= 0);
        
        do{
                connection = SSL_accept(ssl_server);
        }
        while(connection <= 0);

        if(SSL_get_peer_certificate(ssl_server) && SSL_get_verify_result(ssl_server) == X509_V_OK)
                cout << "Certificate Verification successfull.\n";
        
        cout << "Fake_server connected with DTLSv1.2\n";

        cout << "\n--------------------------------------------\n" << endl;

        do{     
                connection = SSL_connect(ssl_client);
        }while(connection <=0 );

        if(SSL_get_peer_certificate(ssl_client) && SSL_get_verify_result(ssl_client) == X509_V_OK)
                cout << "Certificate Verification successfull. \n";
        
        cout << "Fake_client connected with DTLSv1.2\n";

        cout << "\n--------------------------------------------\n" << endl;
        while(true){
                string msg;
                int received_message_len;
                memset(buffer, '\0', sizeof(buffer));
                fd_set readfds_server;
                FD_ZERO(&readfds_server);
                FD_SET(fake_server_socket_descriptor, &readfds_server);
                timeout.tv_sec = 3;
                timeout.tv_usec = 0;
                int activity = select(fake_server_socket_descriptor + 1, &readfds_server, NULL, NULL, &timeout);
                if (activity < 0) {
                        perror("Error in select");
                        exit(EXIT_FAILURE);
                } else if (activity == 0) {
                        printf("No data received.\n");
                        continue;
                }
                received_message_len = SSL_read(ssl_server, buffer, sizeof(buffer) - 1);
                if (received_message_len <= 0) {
                        int ssl_error = SSL_get_error(ssl_server, received_message_len);
                        if (ssl_error == SSL_ERROR_ZERO_RETURN || ssl_error == SSL_ERROR_SYSCALL) {
                                break;
                        }
                } else {
                        buffer[received_message_len] = '\0';
                        cout << "Client: " << buffer << " received\n";
                }
                string modified;
                cout << "Type to modify else Enter : ";
                getline(cin,modified);
                if (modified == ""){
                        msg = modified;                        
                }
                else{
                        msg = buffer;
                }
                SSL_write(ssl_client, msg.c_str(), msg.length());
                cout << "Message " << msg << " passed to actual server\n";
                if (msg == "chat_close") {
                        break;
                }
                fd_set readfds_client;
                FD_ZERO(&readfds_client);
                FD_SET(fake_client_socket_descriptor, &readfds_client);
                timeout.tv_sec = 3;
                timeout.tv_usec = 0;
                activity = select(fake_client_socket_descriptor + 1, &readfds_client, NULL, NULL, &timeout);
                if (activity < 0) {
                        perror("Error in select");
                        exit(EXIT_FAILURE);
                } else if (activity == 0) {
                        printf("No data received.\n");
                        continue;
                }
                received_message_len = SSL_read(ssl_client, buffer, sizeof(buffer) - 1);
                if (received_message_len <= 0) {
                        int ssl_error = SSL_get_error(ssl_client, received_message_len);
                        if (ssl_error == SSL_ERROR_ZERO_RETURN || ssl_error == SSL_ERROR_SYSCALL) {
                                break;
                        }
                } else {
                        buffer[received_message_len] = '\0';
                        cout << "Server: " << buffer << " received\n";
                }
                cout << "Type to modify else Enter : ";
                getline(cin,modified);
                if (modified == ""){
                        msg = modified;                        
                }
                else{
                        msg = buffer;
                }
                SSL_write(ssl_server, msg.c_str(), msg.length());
                cout << "Message " << msg << " passed to actual client\n";
                if (msg == "chat_close") {
                        break;
                }
        }        
        SSL_free(ssl_client);
        SSL_free(ssl_server);
        SSL_CTX_free(ctx_client);
        SSL_CTX_free(ctx_server);
        EVP_cleanup();
        close(fake_client_socket_descriptor);
        close(fake_server_socket_descriptor);
        cout << "\nActive Interceptor Closed\n";
}

void m_i_t_m(char * server_hostname){
        int reuse = 1;
        //initiaing fake server socket
        fake_server_socket_descriptor = socket(AF_INET,SOCK_DGRAM,0);
        if(fake_server_socket_descriptor < 0){
                cout << "Fake Server Socket Creation Failure\n";
                exit(EXIT_FAILURE);  
        }
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
        fake_client_socket_descriptor = socket(AF_INET,SOCK_DGRAM,0);
        if(fake_client_socket_descriptor < 0){
                cout << "Fake Client Socket Creation Failure\n";
                exit(EXIT_FAILURE);  
        }
        struct hostent *address;
        address = gethostbyname(server_hostname);
        string server_host_address = inet_ntoa(*(struct in_addr*)address->h_addr);

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
                cout << "Client : " << buffer << " received \n";

                msg = buffer;
                sendto(fake_client_socket_descriptor, msg.c_str(), msg.length(), 0, (const struct sockaddr *) &server_address, sizeof(server_address));
                cout << "Forwarding message : " << buffer << " to actual server\n";
                if(msg=="chat_close"){
                        break;
                }
                memset(buffer, '\0', sizeof(buffer));
                received_message_len = recvfrom(fake_client_socket_descriptor, (char *)buffer, MAX_BUFFER_SIZE-1, 0, (struct sockaddr *) &server_address, (socklen_t *)&len);
                buffer[received_message_len] = '\0';
                cout << "Server : " << buffer << " received \n";
                
                ack = buffer;
                sendto(fake_server_socket_descriptor, ack.c_str(), ack.length(), 0, (const struct sockaddr *) &client_address, sizeof(client_address));
                cout << "Forwarding message : " << buffer << " to actual client\n";
                if(ack=="chat_close"){
                        break;
                }else if(ack=="chat_START_SSL_ACK"){
                        initialize_2_way_dtls();
			break;
                }
        }
}

int main(int argc, char* argv[])
{
        if(sizeof(argc) != 4 || argv[1][1] != 'm'){
                cout << "Usage: ./secure_chat_interceptor -m[_i_t_m] { client host name } { server host name } \n \n";
                exit(EXIT_FAILURE);
        }
        else {
                client_host_name = argv[2];
                server_host_name = argv[3];
                // if (sizeof(argc) == 4){

                //         if (argv[5] == "modify"){
                //                 modifying_flag = true;
                //         }
                // }
                m_i_t_m(argv[3]);
                
        }
        return 0;
}


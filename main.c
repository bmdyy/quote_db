// (Vulnerable) quote_db
// Created in preparation for OSED
// William Moody, 06.06.2021

// Compile (DEP, ASLR enabled):
//     gcc main.c -o main.exe -l ws2_32 '-Wl,--nxcompat,--dynamicbase,--export-all-symbols'

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <winsock2.h>
#include <windows.h>
#include <time.h>

#pragma comment(lib, "ws2_32.lib")

#define VERSION 10
#define DEFAULT_PORT 3700 
#define MAX_CONNECTIONS 1
#define BUF_SIZE 8192
#define QUOTE_SIZE 2048 
#define MAX_NUM_QUOTES 100 

/**
 * Packet structure which is used for all communication
 * from the client to the server:
 * 
 * unsigned int opcode;
 * char data[8192];
 * 
 * ----------------------------------------------------
 * 
 * ... server to the client:
 * 
 * char data[8192];
 */

// Array to hold quotes
char quotes[MAX_NUM_QUOTES][QUOTE_SIZE];
int num_quotes;

/**
 * Displays a server banner in the console
 */
void banner()
{
    printf("+===========================+\n");
    printf("| quote_db v%*.*f            |\n", 2, 2, VERSION / 10.f);
    printf("| William Moody, 06.06.2021 |\n");
    printf("+===========================+\n\n");
}

/**
 * Displays a help message and exits the program
 *
 * @param prog_name Name of the program (argv[0])
 */
void usage(char *prog_name)
{
    printf("Usage: %s [-p PORT] [-h]\n", prog_name);
    exit(1);
}

/**
 * A mysterious function which never gets called...
 */
void foo()
{
    asm (
        "inc %eax\n"
        "inc %ebx\n"
        "inc %ecx\n"
        "ret"
    );
}

/**
 * Adds a quote
 * 
 * @param quote The quote to add to the db
 * @returns index of the quote which was added
 */
int add_quote(char* quote)
{
    printf("[?] Adding quote to db...");
    memset(quotes[num_quotes], 0, QUOTE_SIZE);
    printf("#%d.\n", num_quotes);
    int copy_size = strlen(quote);
    copy_size = (copy_size > QUOTE_SIZE) ? QUOTE_SIZE : copy_size;
    memcpy(quotes[num_quotes], quote, copy_size);
    return num_quotes++;
}

/**
 * Gets a quote by index
 * 
 * @param index Index of the quote to give
 * @param quote Buffer to move to quote into
 * @returns a quote
 */
int get_quote(int index, char **quote)
{
    printf("[?] Getting quote #%d from db...\n", index);
    int size = strlen(quotes[index]);
    *quote = malloc(size);
    snprintf(*quote, QUOTE_SIZE, quotes[index]);
    return size;
}

/**
 * Updates a quote by index
 * 
 * @param index Index of the quote to update
 * @param quote New quote to replace the old one with
 */
void update_quote(int index, char *quote)
{
    printf("[?] Updating quote with index #%d...\n", index);
    memset(quotes[index], 0, QUOTE_SIZE);
    memcpy(quotes[index], quote, strlen(quote));
    return;
}

/**
 * Deletes a quote by index
 * 
 * @param index Index of the quote to remove
 */
void delete_quote(int index)
{
    printf("[?] Deleting quote with index #%d...\n", index);
    for (int i = index; i < MAX_NUM_QUOTES - 1; i++)
    {
        memset(quotes[i + 1], 0, QUOTE_SIZE);
        memcpy(quotes[i + 1], quotes[i], strlen(quotes[i]));
    }
    num_quotes--;
    return;
}

/**
 * Thread - Handles a client connection
 * 
 * @param sock The client socket
 */
void handle_connection(void *sock)
{
    // Create a buffer to store the incoming packet
    // and init with 0's
    char buf[BUF_SIZE];
    memset(buf, 0, BUF_SIZE);

    // Receive the packet
    int recvlen;
    if ((recvlen = recv((SOCKET)sock, buf, BUF_SIZE, 0)) < 4)
    {
        printf("....[%d] recv failed.\n", GetCurrentThreadId());
        closesocket((SOCKET)sock);
        return;
    }

    printf("....[%d] received %d bytes.\n", GetCurrentThreadId(), recvlen);

    // Check what opcode the client is calling
    unsigned int opcode;
    memcpy(&opcode, (void *)buf, sizeof(unsigned int));

    printf("....[%d] opcode=%d\n", GetCurrentThreadId(), opcode);

    // Create a bufer to hold response
    char response[BUF_SIZE];
    memset(response, 0, BUF_SIZE);
    unsigned response_size = 0;

    // Some definitions for variables used
    // in the switch statement
    char* quote;
    unsigned int quote_index;
    char new_quote[QUOTE_SIZE];
    char *index_out_of_bounds_msg = "INDEX_OUT_OF_BOUNDS";
    char *bad_request_msg = "BAD_REQUEST";
    char *max_quotes_reached_msg = "MAX_NUM_QUOTES_REACHED";

    switch (opcode)
    {
    case 900: ;
        // Ask for a random quote
        time_t t;
        srand((unsigned) time(&t));
        response_size = get_quote(rand() % num_quotes, &quote);
        memcpy(response, quote, response_size);
        break;
    case 901: ;
        // Ask for a specific quote
        memcpy(&quote_index, (void *)(buf + 4), sizeof(unsigned int));

        if (quote_index >= num_quotes)
        {
            response_size = strlen(index_out_of_bounds_msg);
            memcpy(response, index_out_of_bounds_msg, response_size);
        }
        else 
        {
            response_size = get_quote(quote_index, &quote);
            memcpy(response, quote, response_size);
        }
        break;
    case 902: ;
        // Add a new quote
        if (num_quotes < MAX_NUM_QUOTES)
        {        
            memcpy(new_quote, buf + 4, QUOTE_SIZE);
            quote_index = add_quote(new_quote);
            response_size = sizeof(unsigned int);
            memcpy((void *)response, &quote_index, response_size);
        }
        else
        {
            response_size = strlen(max_quotes_reached_msg);
            memcpy(response, max_quotes_reached_msg, response_size);
        }
        break;
    case 903: ;
        // Update a specific quote
        memcpy(&quote_index, (void *)(buf + 4), sizeof(unsigned int));

        if (quote_index >= num_quotes)
        {
            response_size = strlen(index_out_of_bounds_msg);
            memcpy(response, index_out_of_bounds_msg, response_size);
        }
        else 
        {
            update_quote(quote_index, buf + 8);
        }
        break;
    case 904: ;
        // Delete a specific quote
        memcpy(&quote_index, (void *)(buf + 4), sizeof(unsigned int));

        if (quote_index >= num_quotes)
        {
            response_size = strlen(index_out_of_bounds_msg);
            memcpy(response, index_out_of_bounds_msg, response_size);
        }
        else 
        {
            delete_quote(quote_index);
        }
        break;
    default: ;
        // Default case (invalid opcode).
        response_size = strlen(bad_request_msg);
        memcpy(response, bad_request_msg, strlen(bad_request_msg));
        break;
    }

    // Send a response if we need to
    if (response_size > 0)
    {
        int sent_bytes;
        if ((sent_bytes = send((SOCKET)sock, response, response_size, 0)) == SOCKET_ERROR)
        {
            printf("....[%d] failed while sending response.\n", GetCurrentThreadId());
            closesocket((SOCKET)sock);
            return;
        }
        printf("....[%d] sent response (%d bytes).\n", GetCurrentThreadId(), sent_bytes);
    }

    // Close the client connection and return
    closesocket((SOCKET)sock);
    printf("....[%d] ended connection.\n", GetCurrentThreadId());

    return;
}

/**
 * Starts the server on a given port
 * 
 * @param port Port to start the server on
 * @returns -1 if the server failed to start on the given port
 */
int start_server(int port)
{
    // Display welcome banner
    banner();

    // Init quote array
    memset(quotes, 0, sizeof(char[QUOTE_SIZE]) * MAX_NUM_QUOTES);
    num_quotes = 0;
    
    // Add some sample quotes
    add_quote("If life were predictable it would cease to be life, and be without flavor. - Eleanor Roosevelt");
    add_quote("Give a man a mask and he'll tell you the truth. - Oscar Wilde");
    add_quote("Do not go where the path may lead, go instead where there is no path and leave a trail. - Ralph Waldo Emerson");
    add_quote("Always remember that you are absolutely unique. Just like everyone else. - Margaret Mead");
    add_quote("If you do not change direction, you may end up where you are heading. - Lao Tzu");
    add_quote("No one has ever failed until he has given up. - Anonymous");
    add_quote("Believe you can you're halfway there. - Theodore Roosevelt");
    add_quote("Do it today or regret it tomorrow. - Anonymous");
    add_quote("Action is the foundation key to all success. - Pablo Picasso");
    add_quote("The only place were success comes before work is in the dictionary. - Vidal Sassoon");

    // Try to initialize the winsock library
    WSADATA wsa;
    if (WSAStartup(0x22, &wsa) != 0)
    {
        printf("[-] Failed to initialize WSA library\n");
        return -1;
    }

    printf("[+] WSA Initialized.\n");

    // Try to create socket
    SOCKET s;
    if ((s = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
    {
        printf("[-] Failed to created socket.\n");
        closesocket(s);
        return -1;
    }

    printf("[+] Socket created.\n");

    // Bind socket to the given port
    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(port);

    if (bind(s, (struct sockaddr *)&server, sizeof(server)) == SOCKET_ERROR)
    {
        printf("[-] Failed to bind to port %d.\n", port);
        closesocket(s);
        return -1;
    }

    printf("[+] Bound to port %d.\n", port);

    // Listen for incoming connection
    listen(s, MAX_CONNECTIONS);

    printf("[+] Listening for incoming connections...\n");

    // Accept connections and create handler threads
    struct sockaddr_in client;
    int c = sizeof(struct sockaddr_in);
    SOCKET client_socket;
    while ((client_socket = accept(s, (struct sockaddr *)&client, &c)) != INVALID_SOCKET)
    {
        printf("[+] Accepted a connection from %s:%d.\n", inet_ntoa(client.sin_addr), ntohs(client.sin_port));
        _beginthread(&handle_connection, 0, (void *)client_socket);
    }

    if (client_socket == INVALID_SOCKET)
    {
        printf("[-] Error while accepting socket.\n");
        closesocket(s);
        closesocket(client_socket);
        return -1;
    }

    // Close the server socket
    closesocket(s);

    // Close server without errors
    return 0;
}

/**
 * Entry point
 * Handles arguments and starts the server
 */
int main(int argc, char *argv[])
{
    // Init port to default value
    int port = DEFAULT_PORT;

    // Parse arguments
    int opt;
    while ((opt = getopt(argc, argv, "p:h")) >= 0)
    {
        switch (opt)
        {
        case 'p':
            // Set the server port number
            if (sscanf(optarg, "%i", &port) != 1)
                usage(argv[0]);
            break;
        case 'h':
            // Display the help message
            usage(argv[0]);
            break;
        default:
            break;
        }
    }

    // Start the server
    start_server(port);

    // Cleanup winsock2 library
    WSACleanup();

    // Exit with no errors
    return 0;
}
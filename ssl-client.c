/******************************************************************************

PROGRAM:  ssl-client.c
AUTHOR:   Jeff Hemmes
COURSE:   CS469 - Distributed Systems (Regis University)
SYNOPSIS: This program is a small client application that establishes a secure TCP 
          connection to a server and simply exchanges messages.  It uses a SSL/TLS
          connection using X509 certificates generated with the openssl application.  
          The purpose is to demonstrate how to establish and use secure communication
          channels between a client and server using public key cryptography.

          Some of the code and descriptions can be found in "Network Security with
          OpenSSL", O'Reilly Media, 2002.

          (c) Regis University
******************************************************************************/
#include <netdb.h>
#include <errno.h>
#include <resolv.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#define DEFAULT_PORT        4433
#define DEFAULT_HOST        "localhost"
#define MAX_HOSTNAME_LENGTH 256
#define BUFFER_SIZE         256
#define PATH_LENGTH         248

#define ERR_TOO_FEW_ARGS  1
#define ERR_TOO_MANY_ARGS 2
#define ERR_INVALID_OP    3

//For Authentication
#define PASSWORD_LENGTH 32
#define USERNAME_LENGTH 32
#define HASH_LENGTH     264
#define SEED_LENGTH     8

#include <time.h>
#include <crypt.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <termios.h>

#define PASS_BUFFER_SIZE     264
#define PASSWORD_LENGTH 32
#define SEED_LENGTH     8
/******************************************************************************

This function does the basic necessary housekeeping to establish a secure TCP
connection to the server specified by 'hostname'.

*******************************************************************************/
int create_socket(char* hostname, unsigned int port)
{
  int                sockfd;
  struct hostent*    host;
  struct sockaddr_in dest_addr;

  host = gethostbyname(hostname);
  if (host == NULL)
    {
      fprintf(stderr, "Client: Cannot resolve hostname %s\n",  hostname);
      exit(EXIT_FAILURE);
    }

  // Create a socket (endpoint) for network communication.  The socket()
  // call returns a socket descriptor, which works exactly like a file
  // descriptor for file system operations we worked with in CS431
  //
  // Sockets are by default blocking, so the server will block while reading
  // from or writing to a socket. For most applications this is acceptable.
  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0)
    {
      fprintf(stderr, "Server: Unable to create socket: %s", strerror(errno));
      exit(EXIT_FAILURE);
    }

  // First we set up a network socket. An IP socket address is a combination
  // of an IP interface address plus a 16-bit port number. The struct field
  // sin_family is *always* set to AF_INET. Anything else returns an error.
  // The TCP port is stored in sin_port, but needs to be converted to the
  // format on the host machine to network byte order, which is why htons()
  // is called. The s_addr field is the network address of the remote host
  // specified on the command line. The earlier call to gethostbyname()
  // retrieves the IP address for the given hostname.
  dest_addr.sin_family=AF_INET;
  dest_addr.sin_port=htons(port);
  dest_addr.sin_addr.s_addr = *(long*)(host->h_addr);

  // Now we connect to the remote host.  We pass the connect() system call the
  // socket descriptor, the address of the remote host, and the size in bytes
  // of the remote host's address
  if (connect(sockfd, (struct sockaddr *) &dest_addr, sizeof(struct sockaddr)) <0)
    {
      fprintf(stderr, "Client: Cannot connect to host %s [%s] on port %d: %s\n",
	      hostname, inet_ntoa(dest_addr.sin_addr), port, strerror(errno));
      exit(EXIT_FAILURE);
    }

  return sockfd;
}

// This function reads in a character string that represents a password,
// but does so while not echoing the characters typed to the console.
// Doing that requires first saving the terminal settings, changing the
// echo flag to off, then setting the flags.  Turning the echo back on
// just reverses the steps using the saved terminal settings.

void getPassword(char* password) {
    static struct termios oldsettings, newsettings;
    int c, i = 0;

    // Save the current terminal settings and copy settings for resetting
    tcgetattr(STDIN_FILENO, &oldsettings);
    newsettings = oldsettings;

    // Hide, i.e., turn off echoing, the characters typed to the console
    newsettings.c_lflag &= ~(ECHO);

    // Set the new terminal settings
    tcsetattr(STDIN_FILENO, TCSANOW, &newsettings);

    // Read the password from the console one character at a time
    while ((c = getchar())!= '\n' && c != EOF && i < BUFFER_SIZE)
      password[i++] = c;

    password[i] = '\0';

    // Restore the old (saved) terminal settings
    tcsetattr(STDIN_FILENO, TCSANOW, &oldsettings);
}

/******************************************************************************

The sequence of steps required to establish a secure SSL/TLS connection is:

1.  Initialize the SSL algorithms
2.  Create and configure an SSL context object
3.  Create an SSL session object
4.  Create a new network socket in the traditional way
5.  Bind the SSL object to the network socket descriptor
6.  Establish an SSL session on top of the network connection

Once these steps are completed successfully, use the functions SSL_read() and
SSL_write() to read from/write to the socket, but using the SSL object rather
then the socket descriptor.  Once the session is complete, free the memory
allocated to the SSL object and close the socket descriptor.

******************************************************************************/
int main(int argc, char** argv)
{
  const SSL_METHOD* method;
  unsigned int      port = DEFAULT_PORT;
  char              remote_host[MAX_HOSTNAME_LENGTH];
  char              filename[PATH_LENGTH] = {0};
  char              buffer[BUFFER_SIZE] = {0};
  char*             temp_ptr;
  int               sockfd;
  int               writefd;
  int               rcount;
  int               error_code;
  int               total = 0;
  SSL_CTX*          ssl_ctx;
  SSL*              ssl;


  if (argc != 2)
    {
      fprintf(stderr, "Client: Usage: ssl-client <server name>:<port>\n");
      exit(EXIT_FAILURE);
    }
  else
    {
      // Search for ':' in the argument to see if port is specified
      temp_ptr = strchr(argv[1], ':');
      if (temp_ptr == NULL)    // Hostname only. Use default port
	  strncpy(remote_host, argv[1], MAX_HOSTNAME_LENGTH);
      else
	{
	  // Argument is formatted as <hostname>:<port>. Need to separate
	  // First, split out the hostname from port, delineated with a colon
	  // remote_host will have the <hostname> substring
	  strncpy(remote_host, strtok(argv[1], ":"), MAX_HOSTNAME_LENGTH);
	  // Port number will be the substring after the ':'. At this point
	  // temp is a pointer to the array element containing the ':'
	  port = (unsigned int) atoi(temp_ptr+sizeof(char));
	}
    }

  // Initialize OpenSSL ciphers and digests
  OpenSSL_add_all_algorithms();

  // SSL_library_init() registers the available SSL/TLS ciphers and digests.
  if(SSL_library_init() < 0)
    {
      fprintf(stderr, "Client: Could not initialize the OpenSSL library!\n");
      exit(EXIT_FAILURE);
    }

  // Use the SSL/TLS method for clients
  method = SSLv23_client_method();

  // Create new context instance
  ssl_ctx = SSL_CTX_new(method);
  if (ssl_ctx == NULL)
    {
      fprintf(stderr, "Unable to create a new SSL context structure.\n");
      exit(EXIT_FAILURE);
    }

  // This disables SSLv2, which means only SSLv3 and TLSv1 are available
  // to be negotiated between client and server
  SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2);

  // Create a new SSL connection state object
  ssl = SSL_new(ssl_ctx);

  // Create the underlying TCP socket connection to the remote host
  sockfd = create_socket(remote_host, port);
  if(sockfd != 0)
    fprintf(stderr, "Client: Established TCP connection to '%s' on port %u\n", remote_host, port);
  else
    {
      fprintf(stderr, "Client: Could not establish TCP connection to %s on port %u\n", remote_host, port);
      exit(EXIT_FAILURE);
    }

  // Bind the SSL object to the network socket descriptor.  The socket descriptor
  // will be used by OpenSSL to communicate with a server. This function should only
  // be called once the TCP connection is established, i.e., after create_socket()
  SSL_set_fd(ssl, sockfd);

  // Initiates an SSL session over the existing socket connection.  SSL_connect()
  // will return 1 if successful.
  if (SSL_connect(ssl) == 1)
    fprintf(stdout, "Client: Established SSL/TLS session to '%s' on port %u\n", remote_host, port);
  else
    {
      fprintf(stderr, "Client: Could not establish SSL session to '%s' on port %u\n", remote_host, port);
      exit(EXIT_FAILURE);
    }
  char  pass_buffer[USERNAME_LENGTH + HASH_LENGTH + 1];
  char  password[PASSWORD_LENGTH];
  char  username[USERNAME_LENGTH];
  char  hash[HASH_LENGTH];

  fprintf(stdout, "Enter username: \n");
  fgets(username, USERNAME_LENGTH, stdin);
  username[strlen(username)-1] = '\0';

  fprintf(stdout, "Enter password: \n");
  getPassword(password);


  sprintf(pass_buffer, "user %s", username);
  SSL_write(ssl, pass_buffer, strlen(pass_buffer) + 1);

  sprintf(pass_buffer, "pass %s", password);
  SSL_write(ssl, pass_buffer, strlen(pass_buffer) + 1);
  // Request filename from user and strip trailing newline character
 /* fprintf(stdout, "Enter file name: ");
  fgets(filename, PATH_LENGTH, stdin);
  filename[strlen(filename)-1] = '\0';

  // Marshal the parameter into an RPC message
  sprintf(buffer, "getfile %s", filename);
  SSL_write(ssl, buffer, strlen(buffer) + 1);

  // Clear the buffer and await the reply
  bzero(buffer, BUFFER_SIZE);
  rcount = SSL_read(ssl, buffer, BUFFER_SIZE);
  if (sscanf(buffer, "rpcerror %d", &error_code) == 1) {
    fprintf(stderr, "Client: Bad request: ");
    switch(error_code) {
    case ERR_INVALID_OP:
      fprintf(stderr, "Invalid message format\n");
      break;
    case ERR_TOO_FEW_ARGS:
      fprintf(stderr, "No filename specified\n");
      break;
    case ERR_TOO_MANY_ARGS:
      fprintf(stderr, "Too many file names provided\n");
      break;
    }
  } else if (sscanf(buffer, "fileerror %d", &error_code) == 1) {
    fprintf(stderr, "Client: Could not retrieve file: %s\n", strerror(error_code));
  } else {
    writefd = creat(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    do {
      total += rcount;
      write(writefd, buffer, rcount);
      rcount = SSL_read(ssl, buffer, BUFFER_SIZE);
    } while (rcount > 0);
    close(writefd);
    fprintf(stdout, "Client: Successfully transferred file '%s' (%d bytes) from server\n", filename, total);
  }*/

  // Deallocate memory for the SSL data structures and close the socket
  SSL_free(ssl);
  SSL_CTX_free(ssl_ctx);
  close(sockfd);
  fprintf(stdout, "Client: Terminated SSL/TLS connection with server '%s'\n", remote_host);

  return(0);
}


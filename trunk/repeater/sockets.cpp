/////////////////////////////////////////////////////////////////////////////
//  Copyright (C) 2010 Juan Pedro Gonzalez. All Rights Reserved.
//
//
//  The VNC system is free software; you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation; either version 2 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program; if not, write to the Free Software
//  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307,
//  USA.
//
/////////////////////////////////////////////////////////////////////////////

#include <string.h>
#ifndef WIN32
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <errno.h>
#endif

#include "sockets.h"
#include "repeater.h"

#ifdef WIN32
int errno;
#endif

#ifdef WIN32

/*****************************************************************************
 *
 * Winsock specific functions
 *
 *****************************************************************************/
int
WinsockInitialize( void )
{
	WORD	wVersionRequested;
	WSADATA	wsaData;

	/* Use the MAKEWORD(lowbyte, highbyte) macro declared in Windef.h */
	wVersionRequested = MAKEWORD(2, 2);

	if( WSAStartup(wVersionRequested, &wsaData) != 0 ) {
		fatal("main(): WSAStartup failed.\n");
		return 0;
	}

	if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) {
		fatal("main(): Could not find a usable version of Winsock.dll\n");
		WSACleanup();
		return 0;
	}

	return 1;
}


void
WinsockFinalize( void )
{
	WSACleanup();
}

#endif /* END WIN32 */




/*****************************************************************************
 *
 * Common functions
 *
 *****************************************************************************/

SOCKET 
CreateListenerSocket(u_short port)
{
	SOCKET              sock;
	struct sockaddr_in  addr;
	const int one = 1;

	/* zero the struct before filling the fields */
	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family = AF_INET;					
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;

	/* Initialize the socket */
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if( sock < 0 ) {
		error("Failed to create a listening socket for port %d.\n", port);
		return INVALID_SOCKET;
	}

	/* Set Socket options */
#ifdef WIN32
	setsockopt( sock, SOL_SOCKET, SO_REUSEADDR, (char *)&one, sizeof( one ));
	/* Disable Nagle Algorithm */
	setsockopt( sock, IPPROTO_TCP, TCP_NODELAY, (char *)&one, sizeof( one ));
#else
	setsockopt( sock, SOL_SOCKET, SO_REUSEADDR, (void *)&one, sizeof( one ));
	/* Disable Nagle Algorithm */
	setsockopt( sock, IPPROTO_TCP, TCP_NODELAY, (void *)&one, sizeof( one ));
#endif

	/* Bind the socket to the port */
	if( bind(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr)) < 0 ) {
		error("Failed to bind socket on port %d.\n", port);
		socket_close(sock);
		return INVALID_SOCKET;
	}

	/* Start listening */
	if( listen(sock, 5) < 0 ) {
		error("Failed to start listening on port %d.\n", port);
		socket_close(sock);
		return INVALID_SOCKET;
	}

	/* Return the SOCKET */
	return sock;
}



int 
ReadExact(int sock, char *buf, int len)
{
	int n;

	while (len > 0) {
		n = recv(sock, buf, len, 0);
		if (n > 0) {
			buf += n;
			len -= n;
		} else {
			return n;
		}
	}

	return 1;
}

int 
socket_read(SOCKET s, char * buff, socklen_t bufflen)
{
	int bytes;

	errno = 0;
	if( ( bytes = recv( s, buff, bufflen, 0) ) < 0 ) {
#ifdef WIN32
		errno = WSAGetLastError();
#endif
		return -1;
	}

	return bytes;
}

int 
socket_read_exact(SOCKET s, char * buff, socklen_t bufflen)
{
	int bytes;
	socklen_t currlen = bufflen;
	fd_set read_fds;
	struct timeval tm;
	int count;

	while (currlen > 0) {
		// Wait until some data can be read or sent
		do {
			FD_ZERO( &read_fds );
			FD_SET( s, &read_fds );
			
			tm.tv_sec = 0;
			tm.tv_usec = 50;
			count = select( s + 1, &read_fds, NULL, NULL, &tm);
		} while (count == 0);

		if( count < 0 ) {
#ifdef WIN32
			errno = WSAGetLastError();
#endif
			return -1;
		} else if( count > 2 ) {
			error("socket error in select()\n");
			return -1;
		}
		
		if( FD_ISSET( s, &read_fds ) ) {
			// Try to read some data in
			bytes = socket_read(s, buff, currlen);
			if (bytes > 0) {
				// Adjust the buffer position and size
				buff += bytes;
				currlen -= bytes;
			} else if ( bytes < 0 ) {
#ifdef WIN32
				errno = WSAGetLastError();
#endif
				if( errno != EWOULDBLOCK) {
					error("socket error.\n");
					return -1;
				}
			} else if (bytes == 0) {
				error("zero bytes read\n");
				return -1;
			}
		}
    }

	return 0;
}



SOCKET 
socket_accept(SOCKET s, struct sockaddr * addr, socklen_t * addrlen)
{
	SOCKET sock;
	const int one = 1;

	errno = 0;

#ifdef WIN32
	u_long ioctlsocket_arg = 1;
#endif

	if( ( sock = accept(s, addr, addrlen) ) < 0 ) {
#ifdef WIN32
		errno = WSAGetLastError();
#endif
		return -1;
	}

	// Attempt to set the new socket's options
	// Disable Nagle Algorithm
#ifndef _DEBUG
	setsockopt( sock, IPPROTO_TCP, TCP_NODELAY, (char *)&one, sizeof(one));
#else
	if( setsockopt( sock, IPPROTO_TCP, TCP_NODELAY, (char *)&one, sizeof(one)) == -1 ) {
		debug("Failed to disable Nagle Algorithm.\n");
	} else {
		debug("Nagle Algoritmh has been disabled.\n");
	}
#endif

	// Put the socket into non-blocking mode
#ifdef WIN32
	if (ioctlsocket( sock, FIONBIO, &ioctlsocket_arg) != 0) {
		error("Failed to set socket in non-blocking mode.\n");
		socket_close( sock );
		return -1;
	}
#else
	if (fcntl( sock, F_SETFL, O_NDELAY) != 0) {
		error("Failed to set socket in non-blocking mode.\n");
		socket_close( sock );
		return -1;
	}
#endif

	return sock;
}

int 
socket_close(SOCKET s)
{
	errno = 0;

	shutdown( s, 2);
#ifdef WIN32
	if( closesocket( s ) != 0 ) {
		errno = WSAGetLastError();
#else
	if( close( s ) != 0 ) {
#endif
		return -1;
	}

	return 0;
}

int 
WriteExact(int sock, char *buf, int len)
{
	int n;

	while (len > 0) {
		n = send(sock, buf, len, 0);

		if (n > 0) {
			buf += n;
			len -= n;
		} else if (n == 0) {
			error("WriteExact: write returned 0?\n");
			return -1;
		} else {
			return n;
		}
	}
	return 1;
}

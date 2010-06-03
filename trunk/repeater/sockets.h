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

#ifdef WIN32
#include <windows.h>
#include <winsock.h>
#else
#include <strings.h>
#include <netdb.h>
#include <unistd.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h> 
#include <sys/time.h>
#include <errno.h>
#endif

/*****************************************************************************
 *
 * Defines for compatibility
 *
 *****************************************************************************/


#ifndef INVALID_SOCKET
#define INVALID_SOCKET -1
#endif

#ifndef SOCKET_ERROR
#define SOCKET_ERROR -1
#endif

#ifndef EWOULDBLOCK
#define EWOULDBLOCK WSAEWOULDBLOCK
#endif

#ifndef ENOTCONN
#define ENOTCONN WSAENOTCONN
#endif

#ifndef ECONNRESET
#define ECONNRESET WSAECONNRESET 
#endif

#ifndef ENOTSOCK
#define ENOTSOCK WSAENOTSOCK
#endif

#ifndef FD_ALLOC
#define FD_ALLOC(nfds) ((fd_set*)malloc((nfds+7)/8))
#endif 


#ifdef WIN32
extern int errno;
typedef int socklen_t;
#else
typedef int SOCKET;
typedef uint8_t	BYTE;
#endif


/*****************************************************************************
 *
 * Winsock specific functions
 *
 *****************************************************************************/
#ifdef WIN32
int WinsockInitialize( void );
void WinsockFinalize( void );
#endif

/*****************************************************************************
 *
 * Common functions
 *
 *****************************************************************************/
SOCKET CreateListenerSocket(u_short port);
//int ReadExact(int sock, char *buf, int len);
int WriteExact(int sock, char *buf, int len);
SOCKET socket_accept(SOCKET s, struct sockaddr * addr, socklen_t * addrlen);
int socket_close(SOCKET s);
int socket_read(SOCKET s, char * buff, socklen_t bufflen);
int socket_read_exact(SOCKET s, char * buff, socklen_t bufflen);
int socket_write_exact(SOCKET s, char * buff, socklen_t bufflen);
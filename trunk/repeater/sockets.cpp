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

#include "sockets.h"
#include "repeater.h"

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

#endif /* END WIN32




/*****************************************************************************
 *
 * Common functions
 *
 *****************************************************************************/

SOCKET 
CreateListenerSocket(u_short port)
{
	SOCKET				sock;
	struct sockaddr_in	addr;
	int one = 1;

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;

	/* Initialize the socket */
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if( sock < 0 ) {
		error("Failed to create a listening socket for port %d.\n", port);
		return INVALID_SOCKET;
	}

	/* Bind the socket to the port */
	if( bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0 ) {
		error("Failed to bind socket on port %d.\n", port);
		closesocket(sock);
		return INVALID_SOCKET;
	}

	/* Start listening */
	if( listen(sock, 5) < 0 ) {
		error("Failed to start listening on port %d.\n", port);
		closesocket(sock);
		return INVALID_SOCKET;
	}

	/* Return the SOCKET */
	return sock;
}


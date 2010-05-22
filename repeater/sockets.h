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
#include <netdb.h>
#include <unistd.h> 
#include <pthreads.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h> 
#include <sys/time.h>
#endif

/*****************************************************************************
 *
 * Defines for compatibility
 *
 *****************************************************************************/

#ifndef SOCKET
#define SOCKET int
#endif

#ifndef INVALID_SOCKET
#define INVALID_SOCKET -1
#endif

#ifndef SOCKET_ERROR
#define SOCKET_ERROR -1
#endif

#ifndef WIN32
#define closesocket(s) close(s)
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
int ReadExact(int sock, char *buf, int len);
int WriteExact(int sock, char *buf, int len);
/////////////////////////////////////////////////////////////////////////////
//  Copyright (C) 2010 Juan Pedro Gonzalez. All Rights Reserved.
//  Copyright (C) 2005 Jari Korhonen, jarit1.korhonen@dnainternet.net
//  Copyright (C) 2002 Ultr@VNC Team Members. All Rights Reserved.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <memory.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <stdarg.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <sys/stat.h> 
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

#include "rfb.h"
#include "vncauth.h"

// MACROS FOR SOCKET COMPATIBILITY
#ifdef WIN32
#define CLOSE(a)			closesocket(a)
#ifndef errno
#define errno				WSAGetLastError()
#endif
#else
#define CLOSE(a)			close(a)
#endif

// Defines
#define TRUE	1
#define FALSE	0 
#ifndef FD_ALLOC
#define FD_ALLOC(nfds) ((fd_set*)malloc((nfds+7)/8))
#endif 

#define MAX_HOST_NAME_LEN	250
#define MAX_LIST			20

// Structures
typedef struct _repeaterinfo {
	int server;
	int viewer;
	unsigned long timestamp;
	int used;
	unsigned char code[(CHALLENGESIZE*2)+1];
	CARD8 client_init;
} repeaterinfo;

// Global variables
int notstopped;
unsigned char known_challenge[CHALLENGESIZE];

u_short server_port;

repeaterinfo Viewers[MAX_LIST];
repeaterinfo Servers[MAX_LIST];

// Prototypes
void debug(const char *fmt, ...);
void error( const char *fmt, ... );
void fatal(const char *fmt, ...);
void report_bytes(char *prefix, char *buf, int len);
void Clear_server_list();
void Clear_viewer_list();
unsigned long Add_server_list(repeaterinfo * Viewerstruct);
unsigned long Add_viewer_list(repeaterinfo * Viewerstruct);
unsigned long Find_server_list(repeaterinfo * Viewerstruct);
unsigned long Find_viewer_list(repeaterinfo * Viewerstruct);
void Remove_server_list(unsigned char * code);
void Remove_viewer_list(unsigned char * code);
int ParseDisplay(char *display, char *phost, int hostlen, char *pport);
int ReadExact(int sock, char *buf, int len);
int WriteExact(int sock, char *buf, int len);
#ifdef WIN32
DWORD WINAPI do_repeater(LPVOID lpParam);
DWORD WINAPI server_listen(LPVOID lpParam);
//DWORD WINAPI timer(LPVOID lpParam);
#else
void *do_repeater(void *lpParam) 
void *server_listen(void *lpParam);
//void *timer(void *lpParam);
#endif

/*************************************************************/

void debug(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	fprintf(stderr, "UltraVNC> ");
	vfprintf(stderr, fmt, args);
	va_end(args);
}

void error( const char *fmt, ... )
{
    va_list args;
    va_start( args, fmt );
    fprintf(stderr, "ERROR: ");
    vfprintf( stderr, fmt, args );
    va_end( args );
}

void fatal(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	fprintf(stderr, "FATAL: ");
	vfprintf(stderr, fmt, args);
	va_end(args);
}

void Clear_server_list()
{
	int i;
	for( i=0; i<MAX_LIST; i++ )
	{
		memset(&Servers[i].code, 0, sizeof(Servers[i].code));
		Servers[i].used = FALSE;
		Servers[i].timestamp = 0;
		Servers[i].server = 0;
		Servers[i].viewer = 0;
		Servers[i].client_init = 1;
	}
}

void Clear_viewer_list()
{
	int i;
	for( i=0; i<MAX_LIST; i++ )
	{
		memset(&Viewers[i].code, 0, sizeof(Viewers[i].code));
		Viewers[i].used = FALSE;
		Viewers[i].timestamp = 0;
		Viewers[i].server = 0;
		Viewers[i].viewer = 0;
		Servers[i].client_init = 1;
	}
}

void report_bytes(char *prefix, char *buf, int len)
{
	// ToDo: If verbose parmeter is not set, return.
	debug("%s", prefix);
	while (0 < len) {
		fprintf(stderr, " %02x", *(unsigned char *) buf);
		buf++;
		len--;
	}
	fprintf(stderr, "\n");
	return;
}

unsigned long Add_server_list(repeaterinfo * Viewerstruct) 
{
	int i;
	for( i=0; i<MAX_LIST; i++ ) 
	{
		// ToDo: If the Viewer exists return invalid, but should check
		//       things like IDLE time.
		if( strcmp((char *)&Servers[i].code, (char *)&Viewerstruct->code) == 0 ) {
			return (MAX_LIST + 1);
		}
	}

	// The Viewer does not exist, so find an empty slot
	for( i=0; i<MAX_LIST; i++ ) 
	{
		if( strlen((char *)&Servers[i].code) < 1 ) {
			memcpy(&Servers[i].code, Viewerstruct->code, sizeof(Viewerstruct->code));
			Servers[i].used = FALSE;
			Servers[i].timestamp = (unsigned long)time(NULL);
			Servers[i].server = Viewerstruct->server;
			debug("Add_server_list(): Server added with ID %s.\n", Viewerstruct->code);
			return i;
		}
	}

	// No available slot
	return (MAX_LIST + 1);
}

unsigned long Add_viewer_list(repeaterinfo * Viewerstruct) 
{
	int i;
	for( i=0; i<MAX_LIST; i++ ) 
	{
		// ToDo: If the Viewer exists return invalid, but should check
		//       things like IDLE time.
		if( strcmp((char *)&Viewers[i].code, (char *)&Viewerstruct->code) == 0 ) {
			return (MAX_LIST + 1);
		}
	}

	// The Viewer does not exist, so find an empty slot
	for( i=0; i<MAX_LIST; i++ ) 
	{
		if( strlen((char *)&Viewers[i].code) < 1 ) {
			memcpy(&Viewers[i].code, Viewerstruct->code, sizeof(Viewerstruct->code));
			Viewers[i].used = FALSE;
			Viewers[i].timestamp = (unsigned long)time(NULL);
			Viewers[i].viewer = Viewerstruct->viewer;
			Viewers[i].client_init = Viewerstruct->client_init;
			debug("Add_viewer_list(): Viewer added with ID %s.\n", Viewerstruct->code);
			return i;
		}
	}

	// No available slot
	return (MAX_LIST + 1);
}

unsigned long Find_server_list(repeaterinfo * Viewerstruct) 
{
	int i;
	for( i=0; i<MAX_LIST; i++)
	{
		if( strcmp((char *)&Servers[i].code, (char *)&Viewerstruct->code) == 0 )
			return i;
	}

	return (MAX_LIST + 1);
}

unsigned long Find_viewer_list(repeaterinfo * Viewerstruct) 
{
	int i;
	for( i=0; i<MAX_LIST; i++)
	{
		if( strcmp((char *)&Viewers[i].code, (char *)&Viewerstruct->code) == 0 )
			return i;
	}

	return (MAX_LIST + 1);
}

void Remove_server_list(unsigned char * code)
{
	int i;
	for( i=0; i<MAX_LIST; i++ ) 
	{
		if( strcmp((char *)&Servers[i].code, (char *)code) == 0 ) {
			memset(&Servers[i].code, 0, sizeof(Servers[i].code));
			Servers[i].used = FALSE;
			Servers[i].timestamp = 0;
			// Try to close the sockets
			if( Servers[i].server != 0 ) {
				shutdown(Servers[i].server, 1);
				CLOSE(Servers[i].server);
				Servers[1].server = 0;
			}
			if( Servers[i].viewer != 0 ) {
				shutdown(Servers[i].viewer, 1);
				CLOSE(Servers[i].viewer);
				Servers[1].viewer = 0;
			}
			debug("Remove_server_list(): Server Removed from list %s\n", code);
			return;
		}
	}
}

void Remove_viewer_list(unsigned char * code)
{
	int i;
	for( i=0; i<MAX_LIST; i++ ) 
	{
		if( strcmp((char *)&Viewers[i].code, (char *)code) == 0 ) {
			memset(&Viewers[i].code, 0, sizeof(Viewers[i].code));
			Viewers[i].used = FALSE;
			Viewers[i].timestamp = 0;
			// Try to close the sockets
			if( Viewers[i].server != 0 ) {
				shutdown(Viewers[i].server, 1);
				CLOSE(Viewers[i].server);
				Viewers[1].server = 0;
			}
			if( Viewers[i].viewer != 0 ) {
				shutdown(Viewers[i].viewer, 1);
				CLOSE(Viewers[i].viewer);
				Viewers[1].viewer = 0;
			}
			debug("Remove_viewer_list(): Viewer Removed from list %s\n", code);
			return;
		}
	}
}

int ParseDisplay(char *display, char *phost, int hostlen, char *pport) 
{
	unsigned char challenge[CHALLENGESIZE];
	unsigned char hex_id[(CHALLENGESIZE * 2) + 1];
	char tmp_id[MAX_HOST_NAME_LEN + 1];
	char *colonpos = strchr(display, ':');
	if( hostlen < (int)strlen(display) ) return FALSE;

	if( colonpos == NULL ) return FALSE;

	strncpy(phost, display, colonpos - display);
	phost[colonpos - display]  = '\0';

	memset(&tmp_id, 0, sizeof(tmp_id));
	if( sscanf(colonpos + 1, "%s", tmp_id) != 1 ) return FALSE;

	// encrypt
	memcpy(&challenge, known_challenge, sizeof(challenge));
	vncEncryptBytes(challenge, tmp_id);

	// HEX the challenge response
	memset(&hex_id, 0, sizeof(hex_id));
	for(int i=0; i<CHALLENGESIZE; i++)
	{
		char hex_char[3];
		sprintf((char *)&hex_char, "%02x", (int)challenge[i]);
		memcpy(hex_id + (i * 2), hex_char, 2);
	}

	memset((char *)pport, 0, sizeof(pport));
	strncpy((char *)pport, (char *)&hex_id, CHALLENGESIZE * 2);
	return TRUE;
}

int ReadExact(int sock, char *buf, int len)
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

int WriteExact(int sock, char *buf, int len)
{
	int n;

	while (len > 0) {
		n = send(sock, buf, len, 0);

		if (n > 0) {
			buf += n;
			len -= n;
		} else if (n == 0) {
			fprintf(stderr, "WriteExact: write returned 0?\n");
			exit(1);
		} else {
			return n;
		}
	}
	return 1;
} 

//#ifdef WIN32
//DWORD WINAPI timer(LPVOID lpParam)
//#else
//void *timer(void *lpParam) 
//#endif
//{
//	
//	return 0;
//}

#ifdef WIN32
DWORD WINAPI do_repeater(LPVOID lpParam)
#else
void *do_repeater(void *lpParam) 
#endif
{
	/** vars for viewer input data **/
	char viewerbuf[1024];		/* viewer input buffer */
	int viewerbuf_len;			/* available data in viewerbuf */
	int f_viewer;				/* read viewer input more? */ 
	/** vars for server input data **/
	char serverbuf[1024];		/* server input buffer */
	int serverbuf_len;			/* available data in serverbuf */
	int f_server;				/* read server input more? */
	/** other variables **/
	int nfds, len;
	fd_set *ifds, *ofds; 
	struct timeval *tmo;
	int viewer = 0;
	int server = 0;
	CARD8 client_init;
	unsigned char code[(CHALLENGESIZE * 2) +  1];
	repeaterinfo *inout = (repeaterinfo *) lpParam; 

	viewer = inout->viewer;
	server = inout->server;
	if( inout->client_init == 1) {
		client_init = 1;
	} else {
		client_init = 0;
	}
	memset(code, 0, sizeof(code));
	memcpy((char *)&code, inout->code, sizeof(inout->code));
	viewerbuf_len = 0;
    serverbuf_len = 0; 

	debug("do_reapeater(): Starting repeater for ID %s.\n", code);

	// Send ClientInit to the server to start repeating
	if( WriteExact(server, (char *)&client_init, 1) < 0 ) {
		error("do_repeater(): Writting ClientInit error.\n");
		Remove_server_list(code);
		Remove_viewer_list(code);
		return 0;
	}

	/* repeater between stdin/out and socket  */
    nfds = ((viewer < server) ? server : viewer) + 1;
    ifds = FD_ALLOC(nfds);
    ofds = FD_ALLOC(nfds);
	f_viewer = 1;              /* yes, read from viewer */
    f_server = 1;              /* yes, read from server */
	tmo = NULL;

	// Start the repeater loop.
	while( f_viewer || f_server)
	{
		FD_ZERO(ifds);
		FD_ZERO(ofds); 
		tmo = NULL;

		/** prepare for reading viewer input **/ 
		if (f_viewer && (viewerbuf_len < sizeof(viewerbuf))) {
			FD_SET(viewer, ifds);
		} 

		/** prepare for reading server input **/
		if (f_server && (serverbuf_len < sizeof(serverbuf))) {
			FD_SET(server, ifds);
		} 

		//if( select(nfds, ifds, ofds, NULL, tmo) == -1 ) {
		if( select(nfds, ifds, ofds, NULL, NULL) == -1 ) {
            /* some error */
            error("do_repeater(): select() failed, errno=%d\n", errno);
            Remove_server_list(code);
            Remove_viewer_list(code);
            return 0;
        }

		/* server => viewer */ 
		if (FD_ISSET(server, ifds) && (serverbuf_len < sizeof(serverbuf))) { 
			len = recv(server, serverbuf + serverbuf_len, sizeof(serverbuf) - serverbuf_len, 0); 

			if (len == 0) { 
				debug("do_repeater(): connection closed by server.\n");
				Remove_server_list(code);
				Remove_viewer_list(code);
				return 0;
			} else if ( len == -1 ) {
				/* error on reading from stdin */
				Remove_server_list(code);
				Remove_viewer_list(code);
				return 0;
			} else {
				/* repeat */
				serverbuf_len += len; 
			}
		}

		/* viewer => server */ 
		if( FD_ISSET(viewer, ifds)  && (viewerbuf_len < sizeof(viewerbuf)) ) {
			len = recv(viewer, viewerbuf + viewerbuf_len, sizeof(viewerbuf) - viewerbuf_len, 0);

			if (len == 0) { 
				debug("do_repeater(): connection closed by viewer.\n");
				// ToDo: Leave ready, but don't remove it...
				Remove_server_list(code);
				Remove_viewer_list(code);
				return 0;
			} else if ( len == -1 ) {
				/* error on reading from stdin */
				// ToDo: Leave ready, but don't remove it...
				Remove_server_list(code);
				Remove_viewer_list(code);
				return 0;
			} else {
				/* repeat */
				viewerbuf_len += len; 
			}
		}
		
		/* flush data in viewerbuffer to server */ 
		if( 0 < viewerbuf_len ) { 
			len = send(server, viewerbuf, viewerbuf_len, 0); 
			if( len == -1 ) {
				debug("do_repeater(): send() failed, %d\n", errno);
				Remove_server_list(code);
				Remove_viewer_list(code);
				return 0;
			} else if ( 0 < len ) {
				/* move data on to top of buffer */ 
				viewerbuf_len -= len;
				if( 0 < viewerbuf_len ) 
					memcpy(viewerbuf, viewerbuf + len, viewerbuf_len);
				assert(0 <= viewerbuf_len); 
			}
		}

		/* flush data in serverbuffer to viewer */
		if( 0 < serverbuf_len ) { 
			len = send(viewer, serverbuf, serverbuf_len, 0);
			if( len == -1 ) {
				debug("do_repeater(): send() failed, %d\n", errno);
				Remove_server_list(code);
				Remove_viewer_list(code);
				return 0;
			} else if ( 0 < len ) {
				/* move data on to top of buffer */ 
				serverbuf_len -= len;
				if( len < serverbuf_len )
					memcpy(serverbuf, serverbuf + len, serverbuf_len);
				assert(0 <= serverbuf_len); 
			}
		}

	}

	/** When the thread exits **/
	Remove_server_list(code);
	Remove_viewer_list(code);
	return 0;
}

#ifdef WIN32
DWORD WINAPI server_listen(LPVOID lpParam)
#else
void *server_listen(void *lpParam) 
#endif
{
	int sock;      /* socket */
	int connection;
	struct sockaddr_in name;
	struct sockaddr client;
	int socklen;
	repeaterinfo teststruct;
	rfbProtocolVersionMsg protocol_version; 
	unsigned long server_index;
	unsigned long viewer_index;
	char host_id[MAX_HOST_NAME_LEN + 1];
	char phost[MAX_HOST_NAME_LEN + 1];
	unsigned char server_id[(CHALLENGESIZE * 2) + 1];
	CARD32 auth_type;
#ifdef WIN32
	DWORD dwThreadId;
#else
	pthread_t repeater_thread; 
#endif

	sock = socket(PF_INET, SOCK_STREAM, 0);
	if( sock < 0 ) {
		fatal("server_listen(): socket() failed, errno=%d\n", errno);
		notstopped = FALSE;
		return 0;
	} else
		debug("server_listen(): socket() initialized.\n");

	name.sin_family = AF_INET;
	name.sin_port = htons(server_port);
	name.sin_addr.s_addr = htonl(INADDR_ANY);

	// Bind the socket to the port
	if( bind(sock, (struct sockaddr *)&name, sizeof(name)) < 0 ) {
		fatal("server_listen(): bind() failed, errno=%d\n", errno);
		notstopped = FALSE;
		return 0;
	} else 
		debug("server_listen(): bind() suceeded to port %i\n", server_port);
	
	// Start listening for incoming connections
	if( listen(sock, 1) < 0 ) {
		fatal("server_listen(): listen() failed, errno=%d\n", errno);
		notstopped = FALSE;
		return 0;
	}
	
	socklen = sizeof(client);

	while( notstopped )
	{
		connection = accept(sock, &client, &socklen);
		if( connection < 0 ) {
			debug("main(): accept() failed, errno=%d\n", errno);
		} else {
			// First thing is first: Get the repeater ID...
			if( ReadExact(connection, host_id, MAX_HOST_NAME_LEN) < 0 ) {
				debug("server_listen(): Reading Proxy settings error");
				CLOSE(connection); 
				continue;
			}

			// Check and cypher the ID
			memset((char *)&server_id, 0, sizeof(server_id));
			if( ParseDisplay(host_id, phost, MAX_HOST_NAME_LEN, (char *)&server_id) == FALSE ) {
				debug("server_listen(): Reading Proxy settings error");
				CLOSE(connection); 
				continue;
			}

			// Continue with the handshake until ClientInit.
			// Read the Protocol Version
			if( ReadExact(connection, protocol_version, sz_rfbProtocolVersionMsg) < 0 ) {
				debug("server_listen(): Reading protocol version error.\n");
				CLOSE(connection);
				continue;
			}

			// ToDo: Make sure the version is OK!

			// Tell the server we are using Protocol Version 3.3
			sprintf(protocol_version, rfbProtocolVersionFormat, rfbProtocolMajorVersion, rfbProtocolMinorVersion);
			if( WriteExact(connection, protocol_version, sz_rfbProtocolVersionMsg) < 0 ) {
				debug("server_listen(): Writting protocol version error.\n");
				CLOSE(connection);
				continue;
			}

			// The server should send the authentication type it whises to use.
			// ToDo: We could add a password this would restrict other servers from
			//       connecting to our repeater, in the meanwhile, assume no auth
			//       is the only scheme allowed.
			if( ReadExact(connection, (char *)&auth_type, sizeof(auth_type)) < 0 ) {
				debug("server_listen(): Reading authentication type error.\n");
				CLOSE(connection);
				continue;
			}
			auth_type = Swap32IfLE(auth_type);
			if( auth_type != rfbNoAuth ) {
				debug("server_listen(): Invalid authentication scheme.\n");
				CLOSE(connection);
				continue;
			}

			shutdown(sock, 2);

			// Prepare the reapeaterinfo structure for the viewer
			teststruct.server = connection;
			memset(&teststruct.code, 0, sizeof(teststruct.code));
			memcpy(&teststruct.code, server_id, sizeof(server_id));
			
			server_index = Add_server_list(&teststruct);
			if( server_index > MAX_LIST ) {
				debug("server_listen(): Add_server_list() unable to allocate a slot.\n");
				CLOSE(connection);
				continue;
			}

			// Is there a server to link to?
			viewer_index = Find_viewer_list(&teststruct);
			if( viewer_index < MAX_LIST) {
				teststruct.viewer = Viewers[viewer_index].viewer;
				teststruct.client_init = Servers[server_index].client_init = Viewers[viewer_index].client_init;
				// Thread...
#ifdef WIN32
				CreateThread(NULL, 0, do_repeater, (LPVOID)&teststruct, 0, &dwThreadId);
#else
				pthread_create(&repeater_thread, NULL, do_repeater, (void *) &teststruct); 
#endif
			}
		}
	}

	notstopped = FALSE;
	CLOSE(sock);

	return 0;
}

int main(int argc, char **argv)
{
	int sock;      /* socket */
	int connection;
	struct sockaddr_in name;
	struct sockaddr client;
	int socklen;
	repeaterinfo teststruct;
	rfbProtocolVersionMsg protocol_version; 
	CARD32 auth_type;
	CARD32 auth_response;
	CARD8 client_init;
	unsigned char challenge_response[CHALLENGESIZE];
	unsigned char viewer_id[(CHALLENGESIZE * 2) + 1];
	unsigned long server_index;
	unsigned long viewer_index;
	u_short viewer_port = 5900;
#ifdef WIN32
	// Winsock
	WORD	wVersionRequested;
	WSADATA	wsaData;
	// Windows Threads
	DWORD dwThreadId;

	/* Use the MAKEWORD(lowbyte, highbyte) macro declared in Windef.h */
	wVersionRequested = MAKEWORD(2, 2);

	if( WSAStartup(wVersionRequested, &wsaData) != 0 ) {
		fatal("main(): WSAStartup failed.\n");
		return 1;
	}

	if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) {
		fatal("main(): Could not find a usable version of Winsock.dll\n");
		WSACleanup();
		return 1;
	}
#else
	// POSIX Threads
	pthread_t server_listen_thread;
	pthread_t repeater_thread; 
	// ToDo: Implement timer....
	//pthread_t timer_thread;
#endif
	
	notstopped = TRUE;
	// Although it is a static challenge, it is randomlly generated when the repeater is launched
	vncRandomBytes((unsigned char *)&known_challenge);

	Clear_server_list();
	Clear_viewer_list();

	server_port = 5500;

	sock = socket(PF_INET, SOCK_STREAM, 0);
	if( sock < 0 ) {
		fatal("main(): socket() failed, errno=%d\n", errno);
#ifdef WIN32
		WSACleanup();
#endif
		return 1;
	} else
		debug("main(): socket() initialized.\n");

	name.sin_family = AF_INET;
	name.sin_port = htons(viewer_port);
	name.sin_addr.s_addr = htonl(INADDR_ANY);

	// Bind the socket to the port
	if( bind(sock, (struct sockaddr *)&name, sizeof(name)) < 0 ) {
		fatal("main(): bind() failed, errno=%d\n", errno);
#ifdef WIN32
		WSACleanup();
#endif
		return 1;
	} else 
		debug("main(): bind() suceeded to port %i\n", viewer_port);
	
	// Start listening for incoming connections
	if( listen(sock, 1) < 0 ) {
		fatal("main(): listen() failed, errno=%d\n", errno);
#ifdef WIN32
		WSACleanup();
#endif
		return 1;
	}
	
	socklen = sizeof(client);

	// Start multithreading...
#ifdef WIN32
	CreateThread(NULL, 0, server_listen, (LPVOID)&teststruct, 0, &dwThreadId);
	// ToDo: Implement timer....
	//CreateThread(NULL, 0, timer, (LPVOID)&teststruct, 0, &dwThreadId);
#else
	pthread_create(&server_listen_thread, NULL, server_listen, (void *)&teststruct);
	// ToDo: Implement timer....
	//pthread_create(&timer_thread, NULL, timer, (void *) &teststruct); 
#endif

	// Main loop
	while( notstopped )
	{
		debug("main(): Waiting for viewer connection...\n");
		connection = accept(sock, &client, &socklen);
		if( connection < 0 ) {
			debug("main(): accept() failed, errno=%d\n", errno);
		} else {
			debug("main(): accept() connection.\n");

			// Act like a server until the authentication phase is over.
			// Send the protocol version.
			sprintf(protocol_version, rfbProtocolVersionFormat, rfbProtocolMajorVersion, rfbProtocolMinorVersion);
			if( WriteExact(connection, protocol_version, sz_rfbProtocolVersionMsg) < 0 ) {
				debug("main(): Writting protocol version error.\n");
				CLOSE(connection);
				continue;
			}

			// Read the protocol version the client suggests (Must be 3.3)
			if( ReadExact(connection, protocol_version, sz_rfbProtocolVersionMsg) < 0 ) {
				debug("main(): Reading protocol version error.\n");
				CLOSE(connection);
				continue;
			}

			// Send Authentication Type (VNC Authentication to keep it standard)
			auth_type = Swap32IfLE(rfbVncAuth);
			if( WriteExact(connection, (char *)&auth_type, sizeof(auth_type)) < 0 ) {
				debug("main(): Writting authentication type error.\n");
				CLOSE(connection);
				continue;
			}

			// We must send the 16 bytes challenge key.
			// In order for this to work the challenge must be always the same.
			if( WriteExact(connection, (char *)&known_challenge, sizeof(known_challenge)) < 0 ) {
				debug("main(): Writting challenge error.\n");
				CLOSE(connection);
				continue;
			}

			// Read the password.
			// It will be treated as the repeater IDentifier.
			memset(&challenge_response, 0, sizeof(challenge_response));
			if( ReadExact(connection, (char *)&challenge_response, sizeof(challenge_response)) < 0 ) {
				debug("main(): Reading challenge response error.\n");
				CLOSE(connection);
				continue;
			}

			// HEX the challenge response
			memset(&viewer_id, 0, sizeof(viewer_id));
			for(int i=0; i<CHALLENGESIZE; i++)
			{
				unsigned char hex_char[3];
				sprintf((char *)&hex_char, "%02x", (int)challenge_response[i]);
				memcpy(viewer_id + (i * 2),hex_char,2);
			}

			// Send Authentication response
			auth_response = Swap32IfLE(rfbVncAuthOK);
			if( WriteExact(connection, (char *)&auth_response, sizeof(auth_response)) < 0 ) {
				debug("main(): Writting authentication response error.\n");
				CLOSE(connection);
				continue;
			}

			// Retrieve ClientInit and save it inside the structure.
			if( ReadExact(connection, (char *)&client_init, sizeof(client_init)) < 0 ) {
				debug("main(): Reading ClientInit message error.\n");
				CLOSE(connection);
				continue;
			}

			shutdown(sock, 2);

			// Prepare the reapeaterinfo structure for the viewer
			teststruct.viewer = connection;
			teststruct.client_init = client_init;
			memset(&teststruct.code, 0, sizeof(teststruct.code));
			memcpy(&teststruct.code, viewer_id, sizeof(viewer_id));
			
			viewer_index = Add_viewer_list(&teststruct);
			if( viewer_index > MAX_LIST ) {
				debug("main(): Add_viewer_list() unable to allocate a slot.\n");
				CLOSE(connection);
				continue;
			}

			// Is there a server to link to?
			server_index = Find_server_list(&teststruct);
			if( server_index < MAX_LIST) {
				teststruct.server = Servers[server_index].server;
				// Thread...
#ifdef WIN32
				CreateThread(NULL, 0, do_repeater, (LPVOID)&teststruct, 0, &dwThreadId);
#else
				pthread_create(&repeater_thread, NULL, do_repeater, (void *) &teststruct); 
#endif

			}
		}
	}

	notstopped = FALSE;
	debug("main(): relaying done.\n");
	CLOSE(sock);

#ifdef WIN32
	WSACleanup();
#endif
	return 0;
}
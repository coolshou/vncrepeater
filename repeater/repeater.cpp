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

#include "sockets.h"
#include "rfb.h"
#include "vncauth.h"
#include "repeater.h"

// MACROS FOR SOCKET COMPATIBILITY
#ifdef WIN32
#ifndef errno
#define errno				WSAGetLastError()
#endif
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

typedef struct _listener_thread_params {
	u_short	port;
	SOCKET	sock;
} listener_thread_params;

// Global variables
int notstopped;
unsigned char known_challenge[CHALLENGESIZE];

repeaterinfo Viewers[MAX_LIST];
repeaterinfo Servers[MAX_LIST];

// Prototypes
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
#ifdef WIN32
void ThreadCleanup(HANDLE hThread, DWORD dwMilliseconds);
DWORD WINAPI do_repeater(LPVOID lpParam);
DWORD WINAPI server_listen(LPVOID lpParam);
DWORD WINAPI viewer_listen(LPVOID lpParam);
//DWORD WINAPI timer(LPVOID lpParam);
#else
void *do_repeater(void *lpParam) 
void *server_listen(void *lpParam);
void *viewer_listen(void *lpParam);
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
				closesocket( Servers[i].server );
				Servers[1].server = 0;
			}
			if( Servers[i].viewer != 0 ) {
				shutdown(Servers[i].viewer, 1);
				closesocket( Servers[i].viewer );
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
				closesocket( Viewers[i].server );
				Viewers[1].server = 0;
			}
			if( Viewers[i].viewer != 0 ) {
				shutdown(Viewers[i].viewer, 1);
				closesocket( Viewers[i].viewer );
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
	listener_thread_params *thread_params;
	int connection;
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

	thread_params = (listener_thread_params *)lpParam;
	thread_params->sock = CreateListenerSocket( thread_params->port );
	if ( thread_params->sock == INVALID_SOCKET ) {
		notstopped = FALSE;
	} else {
		debug("Listening for incoming server connections on port %d.\n", thread_params->port);
		socklen = sizeof(client);
	}

	while( notstopped )
	{
		connection = accept(thread_params->sock, &client, &socklen);
	
		if( connection < 0 ) {
			if( notstopped )
				debug("server_listen(): accept() failed, errno=%d\n", errno);
		} else {
			// First thing is first: Get the repeater ID...
			if( ReadExact(connection, host_id, MAX_HOST_NAME_LEN) < 0 ) {
				debug("server_listen(): Reading Proxy settings error");
				closesocket( connection ); 
				continue;
			}

			// Check and cypher the ID
			memset((char *)&server_id, 0, sizeof(server_id));
			if( ParseDisplay(host_id, phost, MAX_HOST_NAME_LEN, (char *)&server_id) == FALSE ) {
				debug("server_listen(): Reading Proxy settings error");
				closesocket( connection ); 
				continue;
			}

			// Continue with the handshake until ClientInit.
			// Read the Protocol Version
			if( ReadExact(connection, protocol_version, sz_rfbProtocolVersionMsg) < 0 ) {
				debug("server_listen(): Reading protocol version error.\n");
				closesocket( connection );
				continue;
			}

			// ToDo: Make sure the version is OK!

			// Tell the server we are using Protocol Version 3.3
			sprintf(protocol_version, rfbProtocolVersionFormat, rfbProtocolMajorVersion, rfbProtocolMinorVersion);
			if( WriteExact(connection, protocol_version, sz_rfbProtocolVersionMsg) < 0 ) {
				debug("server_listen(): Writting protocol version error.\n");
				closesocket(connection);
				continue;
			}

			// The server should send the authentication type it whises to use.
			// ToDo: We could add a password this would restrict other servers from
			//       connecting to our repeater, in the meanwhile, assume no auth
			//       is the only scheme allowed.
			if( ReadExact(connection, (char *)&auth_type, sizeof(auth_type)) < 0 ) {
				debug("server_listen(): Reading authentication type error.\n");
				closesocket( connection );
				continue;
			}
			auth_type = Swap32IfLE(auth_type);
			if( auth_type != rfbNoAuth ) {
				debug("server_listen(): Invalid authentication scheme.\n");
				closesocket( connection );
				continue;
			}

			shutdown(thread_params->sock, 2);

			// Prepare the reapeaterinfo structure for the viewer
			teststruct.server = connection;
			memset(&teststruct.code, 0, sizeof(teststruct.code));
			memcpy(&teststruct.code, server_id, sizeof(server_id));
			
			server_index = Add_server_list(&teststruct);
			if( server_index > MAX_LIST ) {
				debug("server_listen(): Add_server_list() unable to allocate a slot.\n");
				closesocket( connection );
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
	closesocket(thread_params->sock);

	return 0;
}



#ifdef WIN32
DWORD WINAPI viewer_listen(LPVOID lpParam)
#else
void *viewer_listen(void *lpParam) 
#endif
{
	listener_thread_params *thread_params;
	int connection;
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
#ifdef WIN32
	DWORD dwThreadId;
#else
	pthread_t repeater_thread; 
#endif

	thread_params = (listener_thread_params *)lpParam;
	thread_params->sock = CreateListenerSocket( thread_params->port );
	if ( thread_params->sock == INVALID_SOCKET ) {
		notstopped = FALSE;
	} else {
		debug("Listening for incoming viewer connections on port %d.\n", thread_params->port);
		socklen = sizeof(client);
	}

	// Main loop
	while( notstopped )
	{
		connection = accept(thread_params->sock, &client, &socklen);
		if( notstopped == 0) break;
		if( connection < 0 ) {
			if( notstopped )
				debug("viewer_listen(): accept() failed, errno=%d\n", errno);
		} else {
			// Act like a server until the authentication phase is over.
			// Send the protocol version.
			sprintf(protocol_version, rfbProtocolVersionFormat, rfbProtocolMajorVersion, rfbProtocolMinorVersion);
			if( WriteExact(connection, protocol_version, sz_rfbProtocolVersionMsg) < 0 ) {
				debug("viewer_listen(): Writting protocol version error.\n");
				closesocket( connection );
				continue;
			}

			// Read the protocol version the client suggests (Must be 3.3)
			if( ReadExact(connection, protocol_version, sz_rfbProtocolVersionMsg) < 0 ) {
				debug("viewer_listen(): Reading protocol version error.\n");
				closesocket( connection );
				continue;
			}

			// Send Authentication Type (VNC Authentication to keep it standard)
			auth_type = Swap32IfLE(rfbVncAuth);
			if( WriteExact(connection, (char *)&auth_type, sizeof(auth_type)) < 0 ) {
				debug("viewer_listen(): Writting authentication type error.\n");
				closesocket( connection );
				continue;
			}

			// We must send the 16 bytes challenge key.
			// In order for this to work the challenge must be always the same.
			if( WriteExact(connection, (char *)&known_challenge, sizeof(known_challenge)) < 0 ) {
				debug("viewer_listen(): Writting challenge error.\n");
				closesocket( connection );
				continue;
			}

			// Read the password.
			// It will be treated as the repeater IDentifier.
			memset(&challenge_response, 0, sizeof(challenge_response));
			if( ReadExact(connection, (char *)&challenge_response, sizeof(challenge_response)) < 0 ) {
				debug("viewer_listen(): Reading challenge response error.\n");
				closesocket( connection );
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
				debug("viewer_listen(): Writting authentication response error.\n");
				closesocket( connection );
				continue;
			}

			// Retrieve ClientInit and save it inside the structure.
			if( ReadExact(connection, (char *)&client_init, sizeof(client_init)) < 0 ) {
				debug("viewer_listen(): Reading ClientInit message error.\n");
				closesocket( connection );
				continue;
			}

			shutdown(thread_params->sock, 2);

			// Prepare the reapeaterinfo structure for the viewer
			teststruct.viewer = connection;
			teststruct.client_init = client_init;
			memset(&teststruct.code, 0, sizeof(teststruct.code));
			memcpy(&teststruct.code, viewer_id, sizeof(viewer_id));
			
			viewer_index = Add_viewer_list(&teststruct);
			if( viewer_index > MAX_LIST ) {
				debug("viewer_listen(): Add_viewer_list() unable to allocate a slot.\n");
				closesocket( connection );
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
	closesocket( thread_params->sock );
	return 0;
}



#ifdef WIN32

void
ThreadCleanup(HANDLE hThread, DWORD dwMilliseconds)
{
	/* Wait for the threads to complete... */
	switch( WaitForSingleObject(hThread, 10000) )
	{
		case WAIT_OBJECT_0 :
			/* Thread exited */
			CloseHandle( hThread );
			break;
		case WAIT_TIMEOUT :
			/* Timeout elapsed, thread still running */
			TerminateThread( hThread, 0 );
			CloseHandle( hThread );
#ifdef _DEBUG
			error("Thread timed out (Please check what could be wrong).\n");
#endif
			break;
#ifdef _DEBUG
		default:
			error("Something went REALLY wrong while waiting for a thread to complete!\n");
#endif
	};
}



BOOL CtrlHandler( DWORD fdwCtrlType ) 
{ 
	switch( fdwCtrlType ) 
	{ 
		/* Handle the CTRL-C signal. */
		case CTRL_C_EVENT: 
			notstopped = FALSE;
			return( TRUE );
 
		/* CTRL-CLOSE: confirm that the user wants to exit. */
		case CTRL_CLOSE_EVENT: 
			notstopped = FALSE;
			return( TRUE ); 
 
		/* Pass other signals to the next handler. */
		case CTRL_BREAK_EVENT: 
			return FALSE; 
 
		case CTRL_LOGOFF_EVENT: 
			notstopped = FALSE;
			return FALSE; 
 
		case CTRL_SHUTDOWN_EVENT: 
			notstopped = FALSE;
			return FALSE; 
 
		default: 
			return FALSE; 
	} 
} 

#endif



int main(int argc, char **argv)
{
	listener_thread_params *server_thread_params;
	listener_thread_params *viewer_thread_params;

#ifdef WIN32
	// Windows Threads
	DWORD dwThreadId;
	HANDLE hServerThread;
	HANDLE hViewerThread;

	/* Install a control handler to gracefully exiting the application */
	if( !SetConsoleCtrlHandler( (PHANDLER_ROUTINE) CtrlHandler, TRUE ) ) 
	{ 
		printf( "\nVNC REPEATER ERROR: The Control Handler could not be installed.\n" ); 
		return 1;
	}

	if( WinsockInitialize() == 0 )
		return 1;
#else
	// POSIX Threads
#endif
	
	printf("VNC Repeater - http://code.google.com/p/vncrepeater\n===================================================\n\n");
		    
	/* Initialize some variables */
	notstopped = TRUE;

	server_thread_params = (listener_thread_params *)malloc(sizeof(listener_thread_params));
	memset(server_thread_params, 0, sizeof(listener_thread_params));
	viewer_thread_params = (listener_thread_params *)malloc(sizeof(listener_thread_params));
	memset(viewer_thread_params, 0, sizeof(listener_thread_params));

	server_thread_params->port = 5500;
	viewer_thread_params->port = 5900;

	// Although it is a static challenge, it is randomlly generated when the repeater is launched
	vncRandomBytes((unsigned char *)&known_challenge);

	Clear_server_list();
	Clear_viewer_list();

	// Start multithreading...
#ifdef WIN32

	if( notstopped ) {
		hServerThread = CreateThread(NULL, 0, server_listen, (LPVOID)server_thread_params, 0, &dwThreadId);
		if( hServerThread == NULL ) {
			error("Unable to create the thread to listen for servers.\n");
			notstopped = 0;
		}
	}

	if( notstopped ) {
		hViewerThread = CreateThread(NULL, 0, viewer_listen, (LPVOID)viewer_thread_params, 0, &dwThreadId);
		if( hServerThread == NULL ) {
			error("Unable to create the thread to listen for servers.\n");
			notstopped = 0;
		}
	}

	// ToDo: Implement timer....
	//CreateThread(NULL, 0, timer, (LPVOID)&teststruct, 0, &dwThreadId);
#else
	// POSIX THREADS
#endif

	// Main loop
	while( notstopped ) { }

	printf("\nExiting VNC Repeater...\n");

	notstopped = FALSE;

	/* Close the sockets used for the listeners */
	closesocket( server_thread_params->sock );
	closesocket( viewer_thread_params->sock );
	
	/* Free allocated memory for the thread parameters */
	free( server_thread_params );
	free( viewer_thread_params );

	/* Make sure the threads have finalized */
#ifdef WIN32
	ThreadCleanup( hServerThread, 10000 );
	ThreadCleanup( hViewerThread, 10000 );

	// Cleanup Winsock.
	WinsockFinalize();
#else
	// CLEANUP POSIX THREADS
#endif

	return 0;
}
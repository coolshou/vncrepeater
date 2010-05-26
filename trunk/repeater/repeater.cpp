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
#ifndef WIN32
#include <string.h>
#include <pthread.h>
#endif

#include "sockets.h"
#include "rfb.h"
#include "vncauth.h"
#include "repeater.h"
#include "slots.h"

// Defines
#ifndef WIN32
#define _stricmp strcasecmp
#endif

#define TRUE	1
#define FALSE	0 
#ifndef FD_ALLOC
#define FD_ALLOC(nfds) ((fd_set*)malloc((nfds+7)/8))
#endif 

#define MAX_HOST_NAME_LEN	250

// Structures

typedef struct _listener_thread_params {
	u_short	port;
	SOCKET	sock;
} listener_thread_params;

// Global variables
int notstopped;

// Prototypes
int ParseDisplay(char *display, char *phost, int hostlen, char *pport);
void ExitRepeater(int sig);
void usage(char * appname);
#ifdef WIN32
void ThreadCleanup(HANDLE hThread, DWORD dwMilliseconds);
DWORD WINAPI do_repeater(LPVOID lpParam);
DWORD WINAPI server_listen(LPVOID lpParam);
DWORD WINAPI viewer_listen(LPVOID lpParam);
#else
void *do_repeater(void *lpParam);
void *server_listen(void *lpParam);
void *viewer_listen(void *lpParam);
#endif


/*****************************************************************************
 *
 * Output methods
 *
 *****************************************************************************/

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


/*****************************************************************************
 *
 * Helpers / Misc.
 *
 *****************************************************************************/

int ParseDisplay(char *display, char *phost, int hostlen, unsigned char *pport) 
{
	unsigned char challenge[CHALLENGESIZE];
	char tmp_id[MAX_HOST_NAME_LEN + 1];
	char *colonpos = strchr(display, ':');

	if( hostlen < (int)strlen(display) ) return FALSE;

	if( colonpos == NULL ) return FALSE;

	strncpy(phost, display, colonpos - display);
	phost[colonpos - display]  = '\0';

	memset(&tmp_id, 0, sizeof(tmp_id));
	if( sscanf(colonpos + 1, "%s", tmp_id) != 1 ) return FALSE;

	// encrypt
	memcpy(&challenge, challenge_key, CHALLENGESIZE);
	vncEncryptBytes(challenge, tmp_id);

	memcpy((unsigned char *)pport, challenge, CHALLENGESIZE);
	return TRUE;
}


/*****************************************************************************
 *
 * Threads
 *
 *****************************************************************************/

#ifdef WIN32
DWORD WINAPI do_repeater(LPVOID lpParam)
#else
void *do_repeater(void *lpParam) 
#endif
{
	/** vars for viewer input data **/
	char viewerbuf[1024];		/* viewer input buffer */
	unsigned int viewerbuf_len;			/* available data in viewerbuf */
	int f_viewer;				/* read viewer input more? */ 
	/** vars for server input data **/
	char serverbuf[1024];		/* server input buffer */
	unsigned int serverbuf_len;			/* available data in serverbuf */
	int f_server;				/* read server input more? */
	/** other variables **/
	int nfds, len;
	fd_set *ifds, *ofds; 
	struct timeval *tmo;
	CARD8 client_init;
	repeaterslot *slot;

	slot = (repeaterslot *)lpParam;
	
	viewerbuf_len = 0;
	serverbuf_len = 0; 

	debug("do_reapeater(): Starting repeater for ID %s.\n", slot->challenge);

	// Send ClientInit to the server to start repeating
	client_init = 1;
	if( WriteExact(slot->server, (char *)&client_init, 1) < 0 ) {
		error("do_repeater(): Writting ClientInit error.\n");
		f_viewer = 0;              /* no, don't read from viewer */
		f_server = 0;              /* no, don't read from server */
	} else {
		/* repeater between stdin/out and socket  */
		nfds = ((slot->viewer < slot->server) ? slot->server : slot->viewer) + 1;
		ifds = FD_ALLOC(nfds);
		ofds = FD_ALLOC(nfds);
		f_viewer = 1;              /* yes, read from viewer */
		f_server = 1;              /* yes, read from server */
		tmo = NULL;
	}

	// Start the repeater loop.
	while( f_viewer && f_server)
	{
		FD_ZERO(ifds);
		FD_ZERO(ofds); 
		tmo = NULL;

		/** prepare for reading viewer input **/ 
		if (f_viewer && (viewerbuf_len < sizeof(viewerbuf))) {
			FD_SET(slot->viewer, ifds);
		} 

		/** prepare for reading server input **/
		if (f_server && (serverbuf_len < sizeof(serverbuf))) {
			FD_SET(slot->server, ifds);
		} 

		//if( select(nfds, ifds, ofds, NULL, tmo) == -1 ) {
		if( select(nfds, ifds, ofds, NULL, NULL) == -1 ) {
			/* some error */
			error("do_repeater(): select() failed, errno=%d\n", errno);
			f_viewer = 0;              /* no, don't read from viewer */
			f_server = 0;              /* no, don't read from server */
			continue;
		}

		/* server => viewer */ 
		if (FD_ISSET(slot->server, ifds) && (serverbuf_len < sizeof(serverbuf))) { 
			len = recv(slot->server, serverbuf + serverbuf_len, sizeof(serverbuf) - serverbuf_len, 0); 

			if (len == 0) { 
				debug("do_repeater(): connection closed by server.\n");
				f_server = 0;              /* no, don't read from server */
				continue;
			} else if ( len == -1 ) {
				/* error on reading from stdin */
				f_server = 0;              /* no, don't read from server */
				continue;
			} else {
				/* repeat */
				serverbuf_len += len; 
			}
		}

		/* viewer => server */ 
		if( FD_ISSET(slot->viewer, ifds)  && (viewerbuf_len < sizeof(viewerbuf)) ) {
			len = recv(slot->viewer, viewerbuf + viewerbuf_len, sizeof(viewerbuf) - viewerbuf_len, 0);

			if (len == 0) { 
				debug("do_repeater(): connection closed by viewer.\n");
				// ToDo: Leave ready, but don't remove it...
				f_viewer = 0;
				continue;
			} else if ( len == -1 ) {
				/* error on reading from stdin */
				f_viewer = 0;
				continue;
			} else {
				/* repeat */
				viewerbuf_len += len; 
			}
		}
		
		/* flush data in viewerbuffer to server */ 
		if( 0 < viewerbuf_len ) { 
			len = send(slot->server, viewerbuf, viewerbuf_len, 0); 
			if( len == -1 ) {
				debug("do_repeater(): send() failed, %d\n", errno);
				f_server = 0;
				continue;
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
			len = send(slot->viewer, serverbuf, serverbuf_len, 0);
			if( len == -1 ) {
				debug("do_repeater(): send() failed, %d\n", errno);
				f_viewer = 0;
				continue;
			} else if ( 0 < len ) {
				/* move data on to top of buffer */ 
				serverbuf_len -= len;
				if( len < (int)serverbuf_len )
					memcpy(serverbuf, serverbuf + len, serverbuf_len);
				assert(0 <= serverbuf_len); 
			}
		}
	}

	/** When the thread exits **/
	FreeSlot( slot );
	return 0;
}



#ifdef WIN32
DWORD WINAPI server_listen(LPVOID lpParam)
#else
void *server_listen(void *lpParam) 
#endif
{
	listener_thread_params *thread_params;
	SOCKET connection;
	struct sockaddr client;
	socklen_t socklen;
	rfbProtocolVersionMsg protocol_version; 
	char host_id[MAX_HOST_NAME_LEN + 1];
	char phost[MAX_HOST_NAME_LEN + 1];
	CARD32 auth_type;
	unsigned char challenge[CHALLENGESIZE];
	repeaterslot *slot;
	repeaterslot *current;
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
			memset((char *)&challenge, 0, CHALLENGESIZE);
			if( ParseDisplay(host_id, phost, MAX_HOST_NAME_LEN, (unsigned char *)&challenge) == FALSE ) {
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

			// Screws LINUX!
			// shutdown(thread_params->sock, 2);

			// Prepare the reapeaterinfo structure for the viewer
			/* Initialize the slot */
			slot = (repeaterslot *)malloc( sizeof(repeaterslot) );
			memset(slot, 0, sizeof(repeaterslot));

			slot->server = connection;
			slot->viewer = INVALID_SOCKET;
			slot->timestamp = (unsigned long)time(NULL);
			memcpy(slot->challenge, challenge, CHALLENGESIZE);
			slot->next = NULL;
			
			current = AddSlot(slot);
			free( slot );

			if( current == NULL ) {
				closesocket( connection );
				continue;
			} else if( ( current->viewer > 0 ) && ( current->server > 0 ) ) {
				// Thread...
#ifdef WIN32
				CreateThread(NULL, 0, do_repeater, (LPVOID)current, 0, &dwThreadId);
#else
				pthread_create(&repeater_thread, NULL, do_repeater, (void *)current); 
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
	SOCKET connection;
	struct sockaddr client;
	socklen_t socklen;
	rfbProtocolVersionMsg protocol_version; 
	CARD32 auth_type;
	CARD32 auth_response;
	CARD8 client_init;
	unsigned char challenge[CHALLENGESIZE];
	repeaterslot *slot;
	repeaterslot *current;
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
			if( WriteExact(connection, (char *)&challenge_key, CHALLENGESIZE) < 0 ) {
				debug("viewer_listen(): Writting challenge error.\n");
				closesocket( connection );
				continue;
			}

			// Read the password.
			// It will be treated as the repeater IDentifier.
			memset(&challenge, 0, CHALLENGESIZE);
			if( ReadExact(connection, (char *)&challenge, CHALLENGESIZE) < 0 ) {
				debug("viewer_listen(): Reading challenge response error.\n");
				closesocket( connection );
				continue;
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

			// Screws LINUX!
			//shutdown(thread_params->sock, 2);

			// Prepare the reapeaterinfo structure for the viewer
			slot = (repeaterslot *)malloc( sizeof(repeaterslot) );
			memset(slot, 0, sizeof(repeaterslot));

			slot->server = INVALID_SOCKET;
			slot->viewer = connection;
			slot->timestamp = (unsigned long)time(NULL);
			memcpy(slot->challenge, challenge, CHALLENGESIZE);
			slot->next = NULL;
			
			current = AddSlot( slot );
			free( slot );

			if( current == NULL ) {
				closesocket( connection );
				continue;
			} else if( ( current->server > 0 ) && ( current->viewer > 0 ) ) {
				// Thread...
#ifdef WIN32
				CreateThread(NULL, 0, do_repeater, (LPVOID)current, 0, &dwThreadId);
#else
				pthread_create(&repeater_thread, NULL, do_repeater, (void *)current); 
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

#endif



void 
ExitRepeater(int sig)
{
	notstopped = FALSE;
}



void usage(char * appname)
{
	fprintf(stderr, "\nUsage: %s [-server port] [-viewer port]\n\n", appname);
	fprintf(stderr, "  -server port  Defines the listening port for incoming VNC Server connections.\n");
	fprintf(stderr, "  -viewer port  Defines the listening port for incoming VNC viewer connections.\n");
	fprintf(stderr, "\nFor more information please visit http://code.google.com/p/vncrepeater\n\n");

	exit(1);
}

/*****************************************************************************
 *
 * Main entry point
 *
 *****************************************************************************/

int main(int argc, char **argv)
{
	listener_thread_params *server_thread_params;
	listener_thread_params *viewer_thread_params;
	u_short server_port;
	u_short viewer_port;
#ifdef WIN32
	// Windows Threads
	DWORD dwThreadId;
	HANDLE hServerThread;
	HANDLE hViewerThread;
#else
	// POSIX Threads
	pthread_t hServerThread;
	pthread_t hViewerThread;
#endif

	/* Arguments */
	server_port = 5500;
	viewer_port = 5900;

	if( argc > 1 ) {
		for( int i=1;i<argc;i++ )
		{
			if( _stricmp( argv[i], "-server" ) == 0 ) {
				/* Requires argument */
				if( (i+i) == argc ) {
					usage( argv[0] );
					return 1;
				}

				server_port = atoi( argv[(i+1)] );
				if( argv[(i+1)][0] == '-' ) {
					usage( argv[0] );
					return 1;
				} else if( server_port == 0 ) {
					usage( argv[0] );
					return 1;
				} else if( server_port > 65535 ) {
					usage( argv[0] );
					return 1;
				}
				i++;
			} else if( _stricmp( argv[i], "-viewer" ) == 0 ) {
				/* Requires argument */
				if( (i+i) == argc ) {
					usage( argv[0] );
					return 1;
				}

				viewer_port = atoi( argv[(i+1)] );
				if( argv[(i+1)][0] == '-' ) {
					usage( argv[0] );
					return 1;
				} else if( viewer_port == 0 ) {
					usage( argv[0] );
					return 1;
				} else if( viewer_port > 65535 ) {
					usage( argv[0] );
					return 1;
				}

				i++;
			} else {
				usage( argv[0] );
				return 1;
			}
		}
	}
	
#ifdef WIN32
	/* Winsock */
	if( WinsockInitialize() == 0 )
		return 1;
#endif

	/* Start */
	printf("\nVNC Repeater - http://code.google.com/p/vncrepeater\n===================================================\n\n");
		    
	/* Initialize some variables */
	notstopped = TRUE;
	InitializeSlots( 20 );

	/* Trap signal in order to exit cleanlly */
	signal(SIGINT, ExitRepeater);

	server_thread_params = (listener_thread_params *)malloc(sizeof(listener_thread_params));
	memset(server_thread_params, 0, sizeof(listener_thread_params));
	viewer_thread_params = (listener_thread_params *)malloc(sizeof(listener_thread_params));
	memset(viewer_thread_params, 0, sizeof(listener_thread_params));

	server_thread_params->port = server_port;
	viewer_thread_params->port = viewer_port;


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
#else
	// POSIX THREADS
	if( notstopped ) {
		pthread_create(&hServerThread, NULL, server_listen, (void *)server_thread_params); 
	}

	if( notstopped ) {
		pthread_create(&hViewerThread, NULL, viewer_listen, (void *)viewer_thread_params); 
	}
#endif

	// Main loop
	while( notstopped ) { }

	printf("\nExiting VNC Repeater...\n");

	notstopped = FALSE;

	/* Free the repeater slots */
	FreeSlots();

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
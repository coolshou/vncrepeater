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

#include <time.h>
#include "thread.h"
#include "repeater.h" /* Logging */
#ifndef WIN32
#include <errno.h>
#endif

#ifndef WAIT_TIMEOUT
#define WAIT_TIMEOUT ETIMEDOUT 
#endif

#ifndef WAIT_OBJECT_0
#define WAIT_OBJECT_0 0
#endif


int
#ifdef WIN32
thread_create(thread_t * thread, LPTHREAD_SECURITY_ATTRIBUTES attr, LPTHREAD_START_ROUTINE start_routine, LPVOID arg)
#else
thread_create(thread_t * thread, LPTHREAD_SECURITY_ATTRIBUTES attr, void *(*start_routine)(void *), LPVOID arg)
#endif
{
#ifdef WIN32
	DWORD dwThreadId;
	DWORD dwLastError;

	*thread = CreateThread(attr, 0, start_routine, arg, 0, &dwThreadId);
	if( *thread == NULL ) {
		dwLastError = GetLastError();
		if( dwLastError == 0 ) {
			return -1;
		} else {
			return dwLastError;
		}
	} else {
		return 0;
	}
#else
	return pthread_create(thread, attr, start_routine, arg);
#endif
	/* If successful, the pthread_create() function shall return zero; otherwise, an error number shall be returned to indicate the error. */
	return 0;
}

int
thread_join( thread_t thread, unsigned int seconds)
{
	int rc;
#ifndef WIN32
	struct timespec ts;

	if( clock_gettime(CLOCK_REALTIME, &ts) == -1 ) {
		rc = pthread_join( thread, NULL );
	} else {
		ts.tv_sec += seconds;
		rc = pthread_timedjoin_np( thread, NULL, &ts);
	}
#else
	rc = WaitForSingleObject( thread, ( seconds * 1000 ) );
#endif
	
	return rc;
}

int
thread_cleanup(thread_t thread, unsigned int seconds)
{
	int rc;

	rc = thread_join(thread, seconds);

	switch( rc )
	{
	case WAIT_OBJECT_0:
		// Everything OK! Thread exited
#ifdef WIN32
		CloseHandle( thread );
#endif
		return 0;
		break;
	case WAIT_TIMEOUT:
		// Damn! Should be closed by now... Force it!
#ifndef WIN32
		pthread_detach( thread );
#endif
		rc = thread_terminate( thread );
#ifdef WIN32
		if( rc == 0 ) CloseHandle( thread );
#endif
		return rc;
		break;
	default:
		// WTF??? Something went really wrong.
		fatal("Something went REALLY wrong while waiting for a thread to complete!\n");
	}

	return rc;
}


int
thread_terminate(thread_t thread)
{
	int rc;

#ifdef WIN32
	if( TerminateThread( thread, 0 ) == 0 ) {
		rc = GetLastError();
	}
#else
	rc = pthread_cancel( thread );
#endif

	return rc;
}
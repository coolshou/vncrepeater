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
#else
#include <pthread.h>
#endif

#include "mutex.h"

int
mutex_destroy( mutex_t * mutex)
{
#ifdef WIN32
	if( CloseHandle( *mutex ) == 0 ) {
		return GetLastError();
	} else {
		return 0;
	}
#else
	return pthread_mutex_destroy( mutex );
#endif
}


int
mutex_init( mutex_t * mutex )
{
#ifdef WIN32
	*mutex = (mutex_t)CreateMutex( NULL, FALSE, NULL);
	
	if( *mutex == NULL )
		return GetLastError();
	else
		return 0;
#else
	int retVal;
	pthread_mutexattr_t mutexattr;

	// Set the mutex as a recursive mutex
	pthread_mutexattr_settype(&mutexattr, PTHREAD_MUTEX_RECURSIVE_NP);

	// Create the mutex with the attributes set
	retVal = pthread_mutex_init( mutex, &mutexattr );

	// Destroy the attribute
	pthread_mutexattr_destroy( &mutexattr );

	return retVal;
#endif
}


int
mutex_lock( mutex_t * mutex )
{
#ifdef WIN32
	DWORD dwWaitResult;

	dwWaitResult = WaitForSingleObject( *mutex, INFINITE );
	if( dwWaitResult == WAIT_FAILED ) {
		return GetLastError();
	} else {
		return dwWaitResult;
	}
#else
	return pthread_mutex_lock( mutex );
#endif
}


int
mutex_unlock( mutex_t * mutex )
{
#ifdef WIN32
	if( ReleaseMutex( *mutex ) == 0 ) {
		return GetLastError();
	} else {
		return 0;
	}
#else
	return pthread_mutex_unlock( mutex );
#endif
}
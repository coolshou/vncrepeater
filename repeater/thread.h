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

#ifndef _THREAD_H
#define _THREAD_H

#ifdef WIN32
/* WINDOWS */
#include <windows.h>

#define thread_t HANDLE
#define LPTHREAD_SECURITY_ATTRIBUTES LPSECURITY_ATTRIBUTES
#define THREAD_CALL DWORD WINAPI 
#else
/* LINUX*/
#include <pthread.h>

#define thread_t pthread_t
#define LPVOID void * 
#define LPTHREAD_SECURITY_ATTRIBUTES const pthread_attr_t *
#define THREAD_CALL void * 
#endif

int thread_cleanup(thread_t thread, unsigned int seconds);
#ifdef WIN32
int thread_create(thread_t * thread, LPTHREAD_SECURITY_ATTRIBUTES attr, LPTHREAD_START_ROUTINE start_routine, LPVOID arg);
#else
int thread_create(thread_t * thread, LPTHREAD_SECURITY_ATTRIBUTES attr, void *(*start_routine)(void *), LPVOID arg);
#endif
int thread_join( thread_t thread, unsigned int seconds);
int thread_terminate(thread_t thread);

#endif
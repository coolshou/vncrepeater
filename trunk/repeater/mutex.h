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

#ifndef _MUTEX_H
#define _MUTEX_H

#ifdef WIN32
#define mutex_t HANDLE
#define mutexattr_t LPSECURITY_ATTRIBUTES
#else
#define mutex_t pthread_mutex_t
#define mutexattr_t pthread_mutexattr_t
#endif


/* Prototypes */
int mutex_destroy( mutex_t * mutex );
int mutex_init(mutex_t * mutex, mutexattr_t * attr);
int mutex_lock( mutex_t * mutex);
int mutex_unlock( mutex_t * mutex );

#endif
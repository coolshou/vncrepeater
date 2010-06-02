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

#include <stdlib.h>
#include <time.h>
#include <ctype.h>
#ifndef WIN32
#include <string.h>
#endif
#include "sockets.h" /* SOCKET */
#include "rfb.h"     /* CARD8 */
#include "vncauth.h" /* CHALLENGESIZE */
#include "repeater.h"
#include "slots.h"


repeaterslot * Slots;
unsigned int slotCount;
unsigned int max_slots;

unsigned char challenge_key[CHALLENGESIZE];



int
ParseID(char * code)
{
	unsigned int i;
	int retVal;

	for( i=0; i<strlen( code ); i++ ) {
		if( !isdigit( code[i] ) ) {
			error("The repeater ID must be numeric.\n");
			return 0;
		}
	}

	retVal = strtol(code, NULL, 10);
	if( retVal <= 0 ) {
		error("The repeater ID should be a positive integer.\n");
		return 0;
	} else if( retVal > 99999999 ) {
		/* VNC password only allows for 8 characters, so 99999999 is the biggest number */
		error("The repeater ID is too big.\n");
		return 0;
	}

	return retVal;
}

repeaterslot *
NewSlot( void )
{
	repeaterslot * new_slot;
	new_slot = ((repeaterslot *)malloc( sizeof( repeaterslot ) ) );
	if( new_slot == NULL )
		error("Not enough memory to allocate a new slot.\n");
	return new_slot;
}


void
InitializeSlots( unsigned int max )
{
	Slots = NULL;
	//nextSlot = NULL;
	slotCount = 0;
	max_slots = max;
	vncRandomBytes( challenge_key );
}



void 
FreeSlots( void )
{
	repeaterslot *current;

	current = Slots;
	while( current != NULL )
	{
		/* Close server connection */
		if( current->server > 0 ) {
			shutdown( current->server, 2);
			if( socket_close( current->server ) == -1 ) {
				error("Server socket failed to close. Socket error = %d.\n", errno);
			}
#ifdef _DEBUG
				else {
					debug("Server socket has been closed.\n");
				}
#endif
		}

		/* Close viewer connection */
		if( current->viewer > 0 ) {
			shutdown( current->viewer, 2);
			if( socket_close( current->viewer ) == -1 ) {
				error("Viewer socket failed to close. Socket error = %d.\n", errno);
			}
#ifdef _DEBUG
				else {
					debug("Viewer socket has been closed.\n");
				}
#endif
		}

		Slots = current->next;
		free( current );
		slotCount--;

		current = Slots;
	}

	/* Check */
	if( slotCount != 0 ) {
		fatal("Failed to free repeater slots.\n");
		slotCount = 0;
	}
}



repeaterslot * 
AddSlot(repeaterslot *slot)
{
	repeaterslot *current;

	if( ( slot->server <= 0 ) && ( slot->viewer <= 0 ) ) {
		error("Trying to allocate an empty slot.\n");
		return NULL;
	} else if( slot->next != NULL ) {
		error("Memory allocation problem detected while trying to add a slot.\n");
		return NULL;
	} else if( ( max_slots > 0 ) && (max_slots == slotCount) ) {
		error("All the slots are in use.\n");
		return NULL;
	}

	if( Slots == NULL ) {
		/* There is no slot in use */
		Slots = NewSlot();
		if( Slots != NULL ) {
			memcpy(Slots, slot, sizeof(repeaterslot) );
			Slots->next = NULL;
			slotCount++;
		}
		return Slots;
	} else {
		current = FindSlotByChallenge( slot->challenge );
		if( current == NULL ) {
			/* This is a new slot, but slots already exist */
			slot->next = Slots;
			Slots = slot;
			slotCount++;
			return Slots;
		} else if( current->server <= 0 ) {
			current->server = slot->server;
		} else if( current->viewer <= 0 ) {
			current->viewer = slot->viewer;
		} else {
			return NULL;
		}

		return current;
	}
}

/* Free any slot if the connection has been reseted by peer */
void
CleanupSlots( void )
{
	repeaterslot *current;
	repeaterslot * previous;
	repeaterslot *next;
	fd_set read_fds;
	struct timeval tm;
	BYTE buf;
	int num_bytes;

	current = Slots;
	previous = NULL;
	tm.tv_sec=0;
	tm.tv_usec=50;

	while( current != NULL )
	{
		/* " <= 0 " should be " == INVALID_SOCKET" but this fails somehow :( */
		if( ( current->viewer <= 0 ) || ( current->server <= 0 ) ) {
			FD_ZERO( &read_fds );
			
			if( current->viewer <= 0 ) {
				/* check the server connection */
				FD_SET( current->server , &read_fds );
				if( select( current->server + 1, &read_fds, NULL, NULL, &tm) == 0 ) {
					/* Timed out */
					previous = current;
					current = current->next;
					continue;
				}
	
				if( ( num_bytes = recv( current->server, (char *)&buf, 1, MSG_PEEK) ) < 0 ) {
#ifdef WIN32
					errno = WSAGetLastError();
#endif
					if( errno == ECONNRESET ) {
#ifndef _DEBUG
						debug("Connection closed by server.\n");
#else
						debug("Connection closed by server (socket=%d).\n", current->server );
#endif
					} else {
#ifndef _DEBUG
						debug("Closing server connection due to socket error number %d.\n", errno);
#else
						debug("Closing server (socket=%d) connection due to socket error number %d.\n", current->server, errno);
#endif
					}
				} else if( num_bytes == 0 ){
#ifndef _DEBUG
						debug("Connection closed by server.\n");
#else
						debug("Connection closed by server (socket=%d).\n", current->server );
#endif
				} else {
					/* Server is alive */
					previous = current;
					current = current->next;
					continue;
				}
			} else if( current->server <= 0 ) {
				/* Check the viewer connection */
				FD_SET( current->viewer , &read_fds );
				if( select( current->viewer + 1, &read_fds, NULL, NULL, &tm) == 0 ) {
					/* Timed out */
					previous = current;
					current = current->next;
					continue;
				}

				if( ( num_bytes = recv( current->viewer, (char *)&buf, 1, MSG_PEEK) ) < 0 ) {
#ifdef WIN32
					errno = WSAGetLastError();
#endif
					if( errno == ECONNRESET ) {
#ifndef _DEBUG
						debug("Connection closed by viewer.\n");
#else
						debug("Connection closed by viewer (socket=%d).\n", current->viewer );
#endif
					} else {
#ifndef _DEBUG
						debug("Closing viewer connection due to socket error number %d.\n", errno);
#else
						debug("Closing viewer (socket=%d) connection due to socket error number %d.\n", current->viewer, errno);
#endif
					}
				} else if( num_bytes == 0 ){
#ifndef _DEBUG
						debug("Connection closed by viewer.\n");
#else
						debug("Connection closed by viewer (socket=%d).\n", current->viewer );
#endif
				} else {
					/* Server is alive */
					previous = current;
					current = current->next;
					continue;
				}
			}

			// Free slot.
			next = current->next;
			if( previous == NULL )
				Slots = current->next;
			else
				previous->next = current->next;

			socket_close( current->viewer );
			free( current );
			current = next;
#ifdef _DEBUG
			debug("Slot has been freed.\n");
#endif
		} else {
			previous = current;
			current = current->next;
			continue;
		}
	}
}


repeaterslot *
FindSlotByChallenge(unsigned char * challenge)
{
	repeaterslot *current;

	current = Slots;
#ifdef _DEBUG
	debug("Trying to find a slot for a challenge ID.\n");
#endif
	while( current != NULL)
	{
		// ERROR: Getting exception here!!!
		if( memcmp(challenge, current->challenge, CHALLENGESIZE) == 0 ) {
#ifdef _DEBUG
			debug("Found a slot assigned to the given challenge ID.\n");
#endif
			return current;
		}
		current = current->next;
	}

#ifdef _DEBUG
	debug("Failed to find an assigned slot for the given Challenge ID. Probably a new ID.\n");
#endif
	return NULL;
}



void 
FreeSlot(repeaterslot *slot)
{
	repeaterslot *current;
	repeaterslot *previous;

	if( Slots == NULL ) {
		debug("There are no slots to be freed.\n");
		return;
	}

	current = Slots;
	previous = NULL;

#ifdef _DEBUG
	debug("Trying to free slot...\n");
#endif
	while( current != NULL )
	{
		if( memcmp(current->challenge, slot->challenge, CHALLENGESIZE) == 0 ) {
			/* The slot has been found */
#ifdef _DEBUG
			debug("Slots found. Trying to free resources.\n");
#endif
			/* Close server socket */
			if( slot->server >= 0 ) {
				shutdown( slot->server, 2 );
				if( socket_close( slot->server ) == -1 ) {
					error("Server socket failed to close. Socket error = %d\n", errno);
				}
#ifdef _DEBUG
				else {
					debug("Server socket has been closed.\n");
				}
#endif
			}

			/* Close Viewer Socket */
			if( slot->viewer >= 0 ) {
				shutdown( slot->viewer, 2 );
				if( socket_close( slot->viewer ) == -1 ) {
					error("Viewer socket failed to close. Socket error = %d\n", errno);
				}
#ifdef _DEBUG
				else {
					debug("Viewer socket has been closed.\n");
				}
#endif
			}

			if( previous != NULL )
				previous->next = current->next;
			else
				Slots = current->next;
			
			free( current );
			slotCount--;
#ifdef _DEBUG
			debug("Slot has been freed.\n");
#endif
			return;
		}

		previous = current;
		current = current->next;
	}

	fatal("Called FreeSlot() but no slot was found.\n");
}


void DeleteSlotByChallenge(unsigned char * challenge)
{
	repeaterslot *current;
	repeaterslot *previous;

	current = Slots;
	previous = NULL;

	while( current != NULL)
	{
		if( memcmp(challenge, current->challenge, CHALLENGESIZE) == 0 ) {
			/* Close server connection */
			if( current->server > 0 ) {
				shutdown( current->server, 2 );
				socket_close( current->server );
			}

			/* Close viewer connection */
			if( current->viewer > 0 ) {
				shutdown( current->viewer, 2 );
				socket_close( current->viewer );
			}

			if( previous == NULL )
				previous->next = current->next;
			else
				Slots = current->next;
				
			free( current );
			slotCount--;

			return;
		}

		current = current->next;
		previous = current;
	}
}
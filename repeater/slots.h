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


#ifndef _SLOTS_H
#define _SLOTS_H

#include "mutex.h"


typedef struct _repeaterslot
{
	SOCKET server;
	SOCKET viewer;
	unsigned long timestamp;
	unsigned char challenge[CHALLENGESIZE];

	struct _repeaterslot * next;
} repeaterslot;


extern repeaterslot * Slots;

extern unsigned char challenge_key[CHALLENGESIZE];

extern mutex_t mutex_slots;

/* Prototypes */
void InitializeSlots( unsigned int max );
void FreeSlots( void );

repeaterslot * AddSlot(repeaterslot *slot);
void CleanupSlots( void );
void  FreeSlot(repeaterslot *slot);
repeaterslot * AddServer(SOCKET s, char * code);
repeaterslot * AddViewer(SOCKET s, unsigned char * challenge);
repeaterslot * FindSlotByChallenge(unsigned char * challenge);

#endif
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef WIN32
#include <winsock.h>
#else
#include <sys/types.h>
#endif

#include "config.h"

#ifndef WIN32
#define _stricmp strcasecmp
#endif

#ifdef WIN32
#define CONFIG_FILE_PATH "vncrepeater.conf"
#else
#define CONFIG_FILE_PATH "/etc/vncrepeater.conf"
#endif

char * 
trim(char * s) {
	char * start;
	char * end;

	if (!s)
		return NULL;   // handle NULL string
	if (!*s)
		return s;      // handle empty string

	start = s;
	end = (s + strlen( s ) - 1);

	/* Trim left */
	while( ( *start == ' ' ) || ( *start == '\t' ) || ( *start == '\n' ) ) {
		if( *start == '\0' ) return NULL;
		start++;
	}

	/* Trim right */
	while( ( *end == ' ' ) || ( *end == '\t' ) || ( *end == '\n' ) || ( *end == '\r' ) ) {
		if( start == end ) return NULL;
		end--;
	}

	end++;
	*end = '\0';

	return start;
}

int 
LoadConfigurationKey(const char * key, char * value, unsigned int size)
{
	FILE * fp;
	char line[ CONFIG_LINE_LIMIT ];
	char * config_key;
	char * config_value;

	/* Zero memory */
	memset( value, 0, size);

	/* Open the file */
	if( ( fp = fopen( CONFIG_FILE_PATH , "r") ) == NULL )
	{
		/* The configuration file is optional */
		return 0;
	}

	while( !feof( fp ) )
	{
		/* Read a line */
		if( fgets( line, CONFIG_LINE_LIMIT, fp ) == NULL ) {
			break;
		}

		/* Ignore comments and empty lines */
		if( ( line[0] == '#' ) || ( line[0] == '\n' ) )
			continue;

		/* Tokenize string to get the key name */
		config_key = strtok( line, " \n\t");

		/* If it is NOT the correct key, continue to the next line */
		if( config_key == NULL )
			continue;
		else if( _stricmp( config_key, key ) != 0 ) 
			continue;

		/* They key is OK! Grab the value... */
		config_value = strtok(NULL, "\0");
		fclose( fp );

		if( config_value == NULL ) {
			return 0;
		} else {
			config_value = trim( config_value );
			if( config_value == NULL )
				return 0;
		}

		/* Convert the values */
		if( strlen( config_value ) > size ) {
			memcpy( value, config_value, size - 1);
			return 1;
		} else {
			memcpy( value, config_value, strlen( config_value ) );
			return 1;
		}
	}

	fclose( fp );
	return 0;
}

int GetConfigurationPort(const char * key, u_short * value)
{
	char * result;
	int retVal;

	retVal = 0;
	result = (char *)malloc( CONFIG_LINE_LIMIT );
	if( result == NULL ) {
		fprintf( stderr, "Not enough memory.\n");
		return 0;
	}

	if ( LoadConfigurationKey( key, result, CONFIG_LINE_LIMIT ) == 1 ) {
		if( result[0] != '-' ) {
			int port = atoi( result );
			if( ( port > 0 ) && ( port < 65535 ) ) {
				memcpy( value, (u_short *)&port, sizeof(u_short) );
				retVal = 1;
			}
		}
	}

	free( result );
	return retVal;
}

int 
GetConfigurationBoolean(const char * key, int * value)
{
	char * result;

	int retVal;

	retVal = 0;
	result = (char *)malloc( CONFIG_LINE_LIMIT );
	if( result == NULL ) {
		fprintf( stderr, "Not enough memory.\n");
		return 0;
	}

	if ( LoadConfigurationKey( key, result, CONFIG_LINE_LIMIT ) == 1 ) {
		if( ( _stricmp( "TRUE", result ) == 0 ) || ( _stricmp( "1", result) == 0 ) ) {
			int mem_value = 1;
			memcpy( value, &mem_value, sizeof( int ));
			retVal = 1;
		} else if( ( _stricmp( "FALSE", result ) == 0 ) || ( _stricmp( "0", result) == 0 ) ) {
			int mem_value = 0;
			memcpy( value, &mem_value, sizeof( int ));
			retVal = 1;
		}	
	}

	free( result );
	return retVal;
}
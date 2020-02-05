// SPDX-License-Identifier: GPL-3.0-or-later

/**
 * fishminder
 *
 * (C) Copyright 2018-2019 Hewlett Packard Enterprise Development LP.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * Author(s):
 *	Jonas Arndt <jonas.arndt@hpe.com>
 **/

#ifndef LISTENER_H
#define LISTENER_H

#define REGISTRIES "/redfish/v1/Registries/"
#define INFLATEBUFLEN 1048576 // One MB, should be enough for most registries
#define DEFLATEBUFLEN 262144 // 256 kB should be enough for most registries
#define ISCLEARMODE 1
#define EPOCHCHARSIZE 32

struct lsnthread {
	int argc;
	char **argv;
};

struct Clearing {
	char host[256];
	char originofcondition[256];
	char messageid[256];
	int time;
	char clearmessage[256];
};



/**
 * Main listener Thread
 */

void *listener(void *input);

/**
 * get_event_registry
 * returns: json object representing the event registry
 * takes: a *char for an IP address
 * Needs to be freed
 */

json_t *get_event_registry(char *input_host, char *input_eventid,
		const char* db_path, struct _u_request *request,
		struct _u_response *response);

/**
 * ourgzip
 * returns: The size of the deflated data
 * sets: The deflated content is available the dst void pointer
 */
int ourgzip(const void *src, int srcLen, void *dst, int dstLen);

/**
 * ourgunzip
 * returns: The size of the inflated data
 * sets: The inflated content is available in the dst void pointer
 *
 */
int ourgunzip(const void *src, int srcLen, void *dst, int dstLen);

/**
 * read_file
 * returns: char array buffer that needs to be freed
 * takes: pointer to file name to read
**/
char * read_file(const char * filename);

/**
 * Function to produce an Event struct that can be used to commit to the DB.
 * The Event struct event needs to have been allocated prior to a call
 * to this function and the clearmessages variable needs to be returned
 */
int preparedbmessage (json_t *eventobj, json_t *event_reg, char *host,
		     struct Events *event, json_t **clearmsgs);

/**
 * Function that will take a char and a char array and return a message
 * This will be used for producing an event message for the DB
 * The input is based on Redfish message text from the registry and 
 * parameters from the event
**/
char *regarg2msg(char *eventmsg, char **argarray, int arraysize);

/**
 * Function to convert a time string to integer (number of seconds since 1970)
 * Takes and input like: 2018-09-17T16:12:06Z and output char representation
 * of the integer
**/

int string2epoch(char *input, char *output);

/**
 * Function to commit a clearing event entry to the DB
 * Takes an Struct Clearing and returns 0 on success and 1 if failure
**/

int commitclearing2db(struct Clearing *input, const char *db_path);

/**
 * Function to delete entries from the event table based on ClearMessages
 * in a clear event
**/

int deleteclearing(struct Clearing *input, const char *db_path);


/**
 * Function to commit an event entry to the DB
 * Takes an Struct Event and returns 0 on success and 1 if failure
**/

int commitevent2db(struct Events *input, const char* db_path);

/**
 * Callback function that goes through the event and output it to std output
 */
int callback_post (const struct _u_request *request,
		   struct _u_response *response, void *user_data);

/**
  * Function that returns position of last '.' in a string
  * instring - String that should be searched
  * Returns: Integer of the last position of the '.'
  */
int get_last_dot_pos (char *instring);

#define PORT 8080

#endif

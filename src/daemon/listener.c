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
 *
 * Listener - Redfish Event Listener
 **/

#include "rfeventrec.h"
#include "listener.h"
#include "credentialmgr.h"

/**
  * Function that returns position of last '.' in a string
  * instring - String that should be searched
  * Returns: Integer of the last position of the '.'
  */
int get_last_dot_pos (char *instring) {
	int stringlen = 0, dotpos = 0;

	for (stringlen=0; stringlen<strlen(instring);stringlen++) {
		if(instring[stringlen] == '.') {
			dotpos = stringlen;
		}
	}
	return dotpos;
}


/**
 * read_file
 * returns: char array buffer that needs to be freed
 * takes: pointer to file name to read
**/
char * read_file(const char * filename) {
	char * buffer = NULL;
	long length;
	FILE * f = fopen (filename, "rb");
	if (filename != NULL) {
		if (f) {
			fseek (f, 0, SEEK_END);
			length = ftell (f);
			fseek (f, 0, SEEK_SET);
			buffer = o_malloc (length + 1);
			if (buffer) {
				//fread(buffer, 1, length, f);
				if (fread(buffer, 1, length, f) != length)
					exit(1);
			}
			buffer[length] = '\0';
			fclose (f);
		}
		return buffer;
	} else {
		return NULL;
	}
}

/**
 * ourgzip
 * returns: The size of the deflated data
 * sets: The deflated content is available the dst void pointer
 */
int ourgzip(const void *src, int srcLen, void *dst, int dstLen) {
	z_stream strm  = {0};
	strm.total_in  = strm.avail_in  = srcLen;
	strm.total_out = strm.avail_out = dstLen;
	strm.next_in   = (Bytef *) src;
	strm.next_out  = (Bytef *) dst;

	strm.zalloc = Z_NULL;
	strm.zfree  = Z_NULL;
	strm.opaque = Z_NULL;

	int err = -1;
	int ret = -1;

	err = deflateInit2(&strm, 6, Z_DEFLATED, 15 + 16,
			   8, Z_DEFAULT_STRATEGY);
	if (err == Z_OK) {
		err = deflate(&strm, Z_FINISH);
		if (err == Z_STREAM_END) {
			ret = strm.total_out;
		}
		else {
			deflateEnd(&strm);
			return err;
		}
	} else {
		deflateEnd(&strm);
		return err;
	}

	return ret;
}

/**
 * ourgunzip
 * returns: The size of the inflated data
 * sets: The inflated content is available in the dst void pointer
 *
 */
int ourgunzip(const void *src, int srcLen, void *dst, int dstLen) {
	z_stream strm  = {0};
	strm.total_in  = strm.avail_in  = srcLen;
	strm.total_out = strm.avail_out = dstLen;
	strm.next_in   = (Bytef *) src;
	strm.next_out  = (Bytef *) dst;

	strm.zalloc = Z_NULL;
	strm.zfree  = Z_NULL;
	strm.opaque = Z_NULL;

	int err = -1;
	int ret = -1;

	// 15 window bits, and the +32 tells zlib to to detect if using gzip
	// or zlib
	err = inflateInit2(&strm, (15 + 32));
	if (err == Z_OK) {
		err = inflate(&strm, Z_FINISH);
		if (err == Z_STREAM_END) {
			ret = strm.total_out;
		}
		else {
			inflateEnd(&strm);
			return err;
		}
	}
	else {
		inflateEnd(&strm);
		return err;
	}

	inflateEnd(&strm);
	return ret;
}

/**
 * get_event_registry
 * returns: json object representing the event registry
 * takes: a *char for an IP address and a char for the event ID,
 * 	struct _u_request pointer and struct _u_response pointers as well,
 * 	these pointers need from the caller stack to clear the memory after
 * 	return fro this function.
 * Needs to be freed with json_decref
 */

json_t *get_event_registry(char *input_host,
			char *input_eventid,
			const char* db_path,
			struct _u_request *request,
			struct _u_response *response) {
	char *x_auth_token = NULL, *eventslink = NULL, *regchar = NULL,
	     *jsonetag = NULL;
	const char *contentencoding = NULL, *etagheader = NULL;
	struct Credentials *mycreds = NULL;
	struct Credentials_list *mycreds_like = NULL;
	int i = 0, res = 0, gzipint = 0;
	json_t  *event_reg = NULL, *json_body = NULL, *location = NULL,
		*eventsobj = NULL;
	struct hostent *he = NULL;
	struct in_addr **addr_list = NULL;
	char *url = NULL, ip[100] = "";
	struct _u_map map_header;
	json_error_t myjsonerr;
	void *gunzippedreg = NULL;


	ulfius_init_request(request);
	ulfius_init_response(response);
	// we wil start out with getting the registry links to the Event JSON
	// We need to get the IP
	if((he = gethostbyname(input_host)) == NULL)
	{
		// get the host info
		herror("gethostbyname"); // Get rid of
		return NULL;
	}
	addr_list = (struct in_addr **) he->h_addr_list;
	for(i =0; addr_list[i] != NULL; i++){
		// Return the first one;
		strcpy(ip, inet_ntoa(*addr_list[i]));
		break;
	}
	// First let's see if we have the guy in the DB and can retrive
	// credentials
	mycreds_like = get_creds_like(ip, db_path);
	mycreds = &mycreds_like->cred;
	if (mycreds == NULL) {
		// Try it with hostname
		mycreds_like = get_creds_like(input_host, db_path);
		mycreds = &mycreds_like->cred;
		if(mycreds == NULL){
			CRIT( "error: Could not retrieve DB info for "
					"host %s\n", ip);
			free(mycreds_like);
			ulfius_clean_request(request);
			ulfius_clean_response(response);
			return NULL;
		}
	}

	// Construct the request to the the registry
	ASPRINTF(&url, "https://%s%s%s/", mycreds->host, REGISTRIES, input_eventid);
	request->http_verb = o_strdup("GET");
	request->http_url = o_strdup(url);
	free(url);
	url = NULL;
	request->check_server_certificate = 0;

	// Set up some info needed from the credentials
	x_auth_token = mycreds->x_auth_token;
	jsonetag = mycreds->jsonetag;

	// Set up header
	u_map_init(&map_header);
	u_map_put(&map_header, "X-Auth-Token", x_auth_token);
	u_map_copy_into(request->map_header, &map_header);

	// Send the request to get the registry
	res = ulfius_send_http_request(request, response);
	if (res != U_OK) {
		u_map_clean(&map_header);
		free(mycreds_like);
		ulfius_clean_request(request);
		ulfius_clean_response(response);
		return NULL;
	}
	// If we are not authorized we need a new x_auth_token
	// and try again
	if (response->status == 401) {
		x_auth_token = get_session_token(mycreds, db_path);
		strcpy(mycreds->x_auth_token, x_auth_token);
		u_map_put(&map_header, "X-Auth-Token", x_auth_token);
		u_map_copy_into(request->map_header, &map_header);
		res = ulfius_send_http_request(request, response);
		if (response->status == 401) {
			u_map_clean(&map_header);
			free(mycreds_like);
			ulfius_clean_request(request);
			ulfius_clean_response(response);
			return NULL;
		}
	}

	// Okay, done with all the auth stuff. Now let's get the body and peel
	// off the JSON
	json_body = ulfius_get_json_body_response(response, &myjsonerr);
	if(!json_is_object(json_body)) {
		CRIT( "error: commit data is not an object\n");
		// Need to also clean request, response and map_header
		u_map_clean(&map_header);
		json_decref(json_body);
		free(mycreds_like);
		ulfius_clean_request(request);
		ulfius_clean_response(response);
		return NULL;
	}
	location = json_object_get(json_body, "Location");
	if (location == NULL) {
		u_map_clean(&map_header);
		json_decref(json_body);
		free(mycreds_like);
		ulfius_clean_request(request);
		ulfius_clean_response(response);
		return NULL;
	}
	i = json_array_size(location);
	// This is an array but we only need the first element. This is kind of
	// a big assumption and will need to be verified. However, what to do
	// with more than one link?
	for (i=0; i < json_array_size(location); i++) {
		eventsobj = json_array_get(location, i);
		if (!json_is_object(eventsobj)) {
			CRIT( "error: Got back a non json object\n");
			u_map_clean(&map_header);
			json_decref(location);
			json_decref(json_body);
			free(mycreds_like);
			ulfius_clean_request(request);
			ulfius_clean_response(response);
			return NULL;
		}
		eventsobj = json_object_get(eventsobj, "Uri");
		if (eventsobj == NULL) {
			CRIT( "error: Got back a non json object: "
				"eventsobj\n");
			u_map_clean(&map_header);
			json_decref(location);
			json_decref(json_body);
			free(mycreds_like);
			ulfius_clean_request(request);
			ulfius_clean_response(response);
			return NULL;
		}
		eventslink = strdup(json_string_value(eventsobj));
		json_decref(eventsobj);
		break; // We only need the first one (there should be no more)
	}
	DBG("Json registry link is:\n%s\n", eventslink); //REMOVE

	// Decres the objects
	json_decref(location);
	json_decref(json_body);

	// Some clenaup
	u_map_clean(&map_header);
	ulfius_clean_request(request);
	ulfius_clean_response(response);

	// Init again
	u_map_init(&map_header);
	ulfius_init_request(request);
	ulfius_init_response(response);

	// Construct the request to the the JSON Object
	ASPRINTF(&url, "https://%s%s", mycreds->host, eventslink);
	request->http_verb = o_strdup("GET");
	request->http_url = o_strdup(url);
	free(url);
	url = NULL;
	free(eventslink);
	eventslink = NULL;
	request->check_server_certificate = 0; // Need again?

	// Setup the if-none-match with etag (later)
	u_map_put(&map_header, "X-Auth-Token", x_auth_token);
	u_map_put(&map_header, "If-None-Match", jsonetag);
	u_map_copy_into(request->map_header, &map_header);
	res = ulfius_send_http_request(request, response);
	if (res != U_OK) {
		u_map_clean(&map_header);
		free(mycreds_like);
		ulfius_clean_request(request);
		ulfius_clean_response(response);
		return NULL;
	}

	// Now, there is a chance this is gzipped. Check the header
	contentencoding = u_map_get_case(response->map_header,
					 "Content-Encoding");
	etagheader = u_map_get_case(response->map_header, "ETag");
	// Check if we got something back or if the json has not changed
	if (304 == response->status) {
		// It hasn't changed, use the one in the DB
		mycreds->jsonreg_len = get_json_registry(mycreds->host,
							 &(mycreds->jsonreg),
							db_path);
		if (mycreds->jsonreg_len == 0) {
			CRIT( "A problem retrieving jsonreg from "
				"the DB\n");
			free(mycreds->jsonreg);
			free(mycreds_like);
			u_map_clean(&map_header);
			ulfius_clean_request(request);
			ulfius_clean_response(response);
			return NULL;
		}
		gunzippedreg = malloc(INFLATEBUFLEN);

		if (gunzippedreg == NULL) {
			CRIT( "Could not allocate memory for gunzip "
								"buffer\n");
			free(mycreds->jsonreg);
			free(mycreds_like);
			u_map_clean(&map_header);
			ulfius_clean_request(request);
			ulfius_clean_response(response);
			return NULL;
		}
		gzipint = ourgunzip(mycreds->jsonreg,
				mycreds->jsonreg_len, gunzippedreg, 262144);
		if(gzipint < 0) {
			CRIT( "Something went wrong when trying to "
						"inflate registry data\n");
			free(gunzippedreg);
			free(mycreds->jsonreg);
			free(mycreds_like);
			u_map_clean(&map_header);
			ulfius_clean_request(request);
			ulfius_clean_response(response);
			return NULL;
		}
		regchar = (char *) gunzippedreg;
		regchar[gzipint] = '\0';
		event_reg = json_loads(regchar, 0, &myjsonerr);
	} else if (contentencoding != NULL && 0 == strcasecmp(contentencoding,
							"gzip")) {
		mycreds->jsonreg = response->binary_body;
		mycreds->jsonreg_len = response->binary_body_length;
		strcpy(mycreds->jsonetag, etagheader);
		if (update_creds(mycreds, db_path)){
			CRIT( "A problem update the DB\n");
			u_map_clean(&map_header);
			free(mycreds_like);
			ulfius_clean_request(request);
			ulfius_clean_response(response);
			return NULL;
		}
		gunzippedreg = malloc(INFLATEBUFLEN);
		if (gunzippedreg == NULL) {
			CRIT( "Could not allocate memory for gunzip "
								"buffer\n");
			u_map_clean(&map_header);
			free(mycreds_like);
			ulfius_clean_request(request);
			ulfius_clean_response(response);
			return NULL;
		}
		gzipint = ourgunzip(mycreds->jsonreg,
				mycreds->jsonreg_len, gunzippedreg, 262144);
		if(gzipint < 0) {
			CRIT( "Something went wrong when trying to "
						"inflate registry data\n");
			free(gunzippedreg);
			free(mycreds_like);
			u_map_clean(&map_header);
			ulfius_clean_request(request);
			ulfius_clean_response(response);
			return NULL;
		}
		regchar = (char *) gunzippedreg;
		regchar[gzipint] = '\0';
		event_reg = json_loads(regchar, 0, &myjsonerr);
	} else {
		// No gzip, just get the JSON body
		event_reg = ulfius_get_json_body_response(response,
							  &myjsonerr);
		i = json_object_size(event_reg);
		// Allocate space to the deflated data
		mycreds->jsonreg = malloc(DEFLATEBUFLEN);
		if (mycreds->jsonreg == NULL) {
			CRIT( "Could not allocate memory for gzip "
								"buffer\n");
			json_decref(event_reg);
			free(mycreds_like);
			u_map_clean(&map_header);
			ulfius_clean_request(request);
			ulfius_clean_response(response);
			return NULL;
		}
		mycreds->jsonreg_len = ourgzip(event_reg, i, mycreds->jsonreg,
					       DEFLATEBUFLEN);
		if (mycreds->jsonreg_len < 0) {
			CRIT( "Something went wrong when trying to "
				"deflate registry data for the DB\n");
			free(mycreds->jsonreg);
			free(mycreds_like);
			u_map_clean(&map_header);
			json_decref(event_reg);
			ulfius_clean_request(request);
			ulfius_clean_response(response);
			return NULL;
		}
		strcpy(mycreds->jsonetag, etagheader);
		if (update_creds(mycreds, db_path)){
			CRIT( "A problem update the DB\n");
			free(mycreds->jsonreg);
			free(mycreds_like);
			u_map_clean(&map_header);
			json_decref(event_reg);
			ulfius_clean_request(request);
			ulfius_clean_response(response);
			return NULL;
		}
	}
	if (!json_is_object(event_reg)) {
		CRIT( "Could not convert to json object\n");
		// Do we need to free stuff here? Probably more than this...
		json_decref(event_reg);
		u_map_clean(&map_header);
		free(mycreds_like);
		ulfius_clean_request(request);
		ulfius_clean_response(response);
		return NULL;
	}

	// Cleanup, cleanup, everybody cleanup

	// Only needed if 304 as otherwise freed in ulfius_clean_response
	if (304 == response->status)
		free(mycreds->jsonreg);
	if (!u_map_clean(&map_header) == U_OK) {
		CRIT( "Cold not clean up map_header\n");
	}

	free(mycreds_like);
	free(eventslink);
	free(gunzippedreg);
	// json_decref(event_reg); Can't do this as it kills the json object

	return event_reg;
}

/**
 * Function that will take a char and a char array and return a message
 * This will be used for producing an event message for the DB
 * The input is based on Redfish message text from the registry and
 * parameters from the event (the array).
 * The return value has to be freed
**/
char *regarg2msg (char *eventmsg, char **argarray, int arraysize) {
	char *outchar = NULL, *pointchar = NULL, *left = NULL;
	int i = 0, size=0;
	size = strlen(eventmsg) - arraysize; // No need to account for the %
	for (i=0; i < arraysize; i++) {
		size = size + strlen(argarray[i]);
	}
	size++;
	outchar = malloc(size);
	pointchar = eventmsg;
	left = eventmsg;
	strcpy(outchar, "");
	for (i=0; i < arraysize; i++) {
		pointchar = strchr(pointchar, '%');
		strncat(outchar, left, (pointchar - left));
		strcat(outchar, argarray[i]);
		pointchar = pointchar + strlen(argarray[i]) + 1;
		left = pointchar;
	}
	if (strlen(left) > 0)
		strcat(outchar, left);
	return outchar;
}

/**
 * Function to convert a time string to integer (number of seconds since 1970)
 * Takes and input like: 2018-09-17T16:12:06Z and output char representation
 * of the integer. Space in output has to have been allocated
**/

int string2epoch(char *input, char *output) {
	struct tm localtm;
	int ret = 0;
	localtm.tm_isdst = 0;
	if (NULL == strptime(input, "%Y-%m-%dT%H:%M:%S", &localtm))
		return 0;
	ret = strftime(output, EPOCHCHARSIZE, "%s", &localtm);
	if (ret == 0)
		return 0;

	return ret;
}

/**
 * Function to delete entries from the event table based on ClearMessages
 * in a clear event
**/

int deleteclearing(struct Clearing *input, const char* db_path) {
	char messageid2clear[256]="";
	sqlite3 *db = NULL;
	int rc = 0;
	char *zErrMsg = NULL;
	char *sql = NULL;

	strncpy(messageid2clear, input->messageid,
			get_last_dot_pos(input->messageid)+1);
	strncat(messageid2clear, input->clearmessage,
		strlen(input->clearmessage));

	/* Open database */
	rc = sqlite3_open(db_path, &db);
	if( rc ) {
		CRIT("Can't open database: %s\n", sqlite3_errmsg(db));
		return 1;
	}

	/* Create SQL statement */
	sql = sqlite3_mprintf("PRAGMA foreign_keys=ON");
	if(!sql){
		CRIT( "Failed to allocate enough memory");
		sqlite3_close(db);
		return 1;
	}
	rc = sqlite3_exec(db, sql, 0, 0, &zErrMsg);
	sqlite3_free(sql);

	if( rc != SQLITE_OK ){
		CRIT( "SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
		sqlite3_close(db);
		return 1;
	}


	/* Create SQL statement */
	sql = sqlite3_mprintf("DELETE FROM events WHERE host='%s' AND "
			      "originofcondition='%s' AND messageid='%s';",
			      input->host, input->originofcondition,
			      messageid2clear);
	if(!sql){
		CRIT( "Failed to allocate enough memory");
		sqlite3_close(db);
		return 1;
	}
	rc = sqlite3_exec(db, sql, 0, 0, &zErrMsg);

	if( rc != SQLITE_OK ){
		CRIT( "SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
		sqlite3_close(db);
		sqlite3_free(sql);
		return 1;
	}
	sqlite3_close(db);
	sqlite3_free(sql);
	return 0;
}

/**
 * Function to commit a clearing event entry to the DB
 * Takes an Struct Clearing and returns 0 on success and 1 if failure
**/

int commitclearing2db(struct Clearing *input, const char* db_path) {
	sqlite3 *db = NULL;
	int rc = 0;
	char *zErrMsg = NULL;
	char *sql = NULL;

	/* Open database */
	rc = sqlite3_open(db_path, &db);
	if( rc ) {
		CRIT("Can't open database: %s\n", sqlite3_errmsg(db));
		return 1;
	}

	/* Create SQL statement */
	sql = sqlite3_mprintf("PRAGMA foreign_keys=ON");
	if(!sql){
		CRIT( "Failed to allocate enough memory");
		sqlite3_close(db);
		return 1;
	}
	rc = sqlite3_exec(db, sql, 0, 0, &zErrMsg);
	sqlite3_free(sql);

	if( rc != SQLITE_OK ){
		CRIT( "SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
		sqlite3_close(db);
		return 1;
	}
	/* Create SQL statement */
	sql = sqlite3_mprintf("INSERT INTO clearing (host,originofcondition,"
			"messageid,time,clearmessage) "
			"VALUES ('%s','%s','%s','%d','%s');",
			input->host, input->originofcondition, input->messageid,
			input->time, input->clearmessage);

	if(!sql){
		CRIT( "Failed to allocate enough memory");
		sqlite3_close(db);
		return 1;
	}
	rc = sqlite3_exec(db, sql, 0, 0, &zErrMsg);

	if( rc != SQLITE_OK ){
		CRIT( "SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
		sqlite3_close(db);
		sqlite3_free(sql);
		return 1;
	}
	sqlite3_close(db);
	sqlite3_free(sql);

	return 0;
}

/**
 * Function to commit an event entry to the DB
 * Takes an Struct Event and returns 0 on success and 1 if failure
**/

int commitevent2db(struct Events *input, const char* db_path) {
	sqlite3 *db = NULL;
	int rc = 0;
	char *zErrMsg = NULL;
	char *sql = NULL;

	/* Open database */
	rc = sqlite3_open(db_path, &db);
	if( rc ) {
		CRIT("Can't open database: %s\n", sqlite3_errmsg(db));
		return 1;
	}

	/* Create SQL statement */
	sql = sqlite3_mprintf("INSERT INTO events (host,severity,message,"
			"resolution,time,isclearing,originofcondition,"
			"messageid,category) VALUES "
			"('%s','%s','%s','%s','%d','%d','%s','%s','%s');",
			input->host, input->severity, input->message,
			input->resolution, input->time, input->isclearmessage,
			input->originofcondition, input->messageid,
			input->category);

	if(!sql){
		CRIT( "Failed to allocate enough memory");
		sqlite3_close(db);
		return 1;
	}
	rc = sqlite3_exec(db, sql, 0, 0, &zErrMsg);

	if( rc != SQLITE_OK ){
		CRIT( "SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
		sqlite3_close(db);
		sqlite3_free(sql);
		return 1;
	}
	sqlite3_close(db);
	sqlite3_free(sql);

	return 0;
}

/**
 * Function to produce an Event struct that can be used to commit to the DB.
 * The Event struct event needs to have been allocated prior to a call
 * to this function and the clearmessages variable needs to be freed
 */
int preparedbmessage (json_t *eventobj, json_t *event_reg, char *host,
		     struct Events *event, json_t **clearmsgs) {

	char *registryentryname, *tmpchar, *messageidchar,
	     **messageargsarray, *retchar, *timechar, timeret[EPOCHCHARSIZE];
	json_t *regitem, *regitemmessage, *resolution, *severity,
	       *oem, *oemhpe, *healthcategory, *eventmsg, *timeentry,
	       *originofcondition, *messageargs, *messagearg,
	       *clearinglogic, *tmpclearingarray;
	registryentryname = tmpchar = messageidchar = retchar = timechar = NULL;
	// struct Events event;
	int i = 0, j = 0;
	regitem = regitemmessage = resolution = clearinglogic = NULL;
	severity = oem = oemhpe = healthcategory = eventmsg = NULL;
	originofcondition = NULL;

	eventmsg = json_object_get(eventobj, "MessageId");
	if (eventmsg == NULL) {
		return 1;
	}
	timeentry = json_object_get(eventobj, "EventTimestamp");
	if (timeentry == NULL) {
		return 1;
	}
	timechar = strdup(json_string_value(timeentry));
	if (timechar == NULL) {
		return 1;
	}
	if (string2epoch(timechar, timeret) == 0) {
		CRIT( "error: we couldn't convert the time "
			"entry: %s\n", timechar);
		free(timechar);
		return 1;
	}
	messageidchar = strdup(json_string_value(eventmsg));
	strcpy(event->messageid, messageidchar);
	// First get the part of event obj that we need to parse out from the
	// registry
	tmpchar = strtok(messageidchar, ".");
	while (tmpchar != NULL) {
		registryentryname = tmpchar;
		tmpchar = strtok(0, ".");
	}
	// Now we need to get all the objects out for the DB Message
	// Add error check!
	regitem = json_object_get(event_reg, registryentryname);
	if (regitem == NULL) {
		free(messageidchar);
		free(timechar);
		return 1;
	}
	regitemmessage = json_object_get(regitem, "Message");
	if (regitemmessage == NULL) {
		free(messageidchar);
		free(timechar);
		json_decref(regitem);
		return 1;
	}
	resolution = json_object_get(regitem, "Resolution");
	if (resolution == NULL) {
		free(messageidchar);
		free(timechar);
		json_decref(regitem);
		json_decref(resolution);
		return 1;
	}
	severity = json_object_get(regitem, "Severity");
	if (severity == NULL) {
		free(messageidchar);
		free(timechar);
		json_decref(regitem);
		json_decref(resolution);
		json_decref(severity);
		return 1;
	}
	oem = json_object_get(regitem, "Oem");
	if (oem == NULL) {
		free(messageidchar);
		free(timechar);
		json_decref(regitem);
		json_decref(resolution);
		json_decref(severity);
		json_decref(oem);
		return 1;
	}
	oemhpe = json_object_get(oem, "Hpe");
	if (oemhpe == NULL) {
		free(messageidchar);
		free(timechar);
		json_decref(regitem);
		json_decref(resolution);
		json_decref(severity);
		json_decref(oem);
		json_decref(oemhpe);
		return 1;
	}
	healthcategory = json_object_get(oemhpe, "HealthCategory");
	if (healthcategory == NULL) {
		free(messageidchar);
		free(timechar);
		json_decref(regitem);
		json_decref(resolution);
		json_decref(severity);
		json_decref(oem);
		json_decref(oemhpe);
		json_decref(healthcategory);
		return 1;
	}
	// Is this event an event that clear others?
	clearinglogic = json_object_get(oemhpe, "ClearingLogic");
	if (clearinglogic != NULL) {
		event->isclearmessage = 1;
		tmpclearingarray = json_object_get(clearinglogic, "ClearsMessages");
		if (tmpclearingarray == NULL) {
			free(messageidchar);
			free(timechar);
			json_decref(regitem);
			json_decref(resolution);
			json_decref(severity);
			json_decref(oem);
			json_decref(oemhpe);
			json_decref(healthcategory);
			json_decref(clearinglogic);
			return 1;
		}
		clearmsgs[0] = tmpclearingarray;
	}
	originofcondition = json_object_get(eventobj, "OriginOfCondition");
	if (originofcondition == NULL) {
		free(messageidchar);
		free(timechar);
		json_decref(regitem);
		json_decref(resolution);
		json_decref(severity);
		json_decref(oem);
		json_decref(oemhpe);
		json_decref(healthcategory);
		json_decref(clearinglogic);
		json_decref(originofcondition);
		return 1;
	}
	messageargs = json_object_get(eventobj, "MessageArgs");
	if (NULL != messageargs) {
		if (json_is_array(messageargs)) {
			messageargsarray = malloc(sizeof(char*) *
						  json_array_size(messageargs));
			for (i=0; i<json_array_size(messageargs); i++) {
				messagearg = json_array_get(messageargs, i);
				messageargsarray[i] =
					strdup(json_string_value(messagearg));
			}
		} else {
			messageargsarray = malloc(sizeof(char*));
			messageargsarray[0] =
				strdup(json_string_value(messageargs));
		}
		tmpchar = strdup(json_string_value(regitemmessage));
		retchar = regarg2msg(tmpchar, messageargsarray,
			    json_array_size(messageargs));
		strcpy(event->message, retchar);
		free(retchar);
		// Need to also potentially free the array allocation
		if (i != 0) {
			for (j=0; j<i; j++) {
				free(messageargsarray[j]);
			}
		} else {
			free(messageargsarray[0]);
		}
		free(messageargsarray);
	} else {
		// So we didn't get an argument? The only thing we can do is
		// copy the message
		// This is not a normal condition but HPE Proliant testevent has
		// a bug where it doesn't send arguments
		strcpy(event->message,
		       json_string_value(regitemmessage));
	}

	// Populate the DB Events object
	strcpy(event->host, host);
	strcpy(event->severity, json_string_value(severity));
	strcpy(event->resolution, json_string_value(resolution));
	strcpy(event->originofcondition,
	       json_string_value(originofcondition));
	strcpy(event->category, json_string_value(healthcategory));
	event->time = atoi(timeret);

	// Cleanup
	if(!severity)
		json_decref(severity);
	if(!oem)
		json_decref(oem);
	if(!oemhpe)
		json_decref(oemhpe);
	if(!healthcategory)
		json_decref(healthcategory);
	if(!clearinglogic)
		json_decref(clearinglogic);
	if(!originofcondition)
		json_decref(originofcondition);
	free(messageidchar); // Will this be dangerous?
	free(timechar);

	return 0;
}

/**
 * Callback function that goes through the event and output it to std output
 */
int callback_post (const struct _u_request *request,
		   struct _u_response *response, void *user_data) {
	json_t *json_body, *event_reg_body,*event_reg, *events, *eventsobj, *messageid,
					**clrmsgs, *clearingmessage;
	json_body = event_reg_body = event_reg = events = eventsobj = messageid =
				clearingmessage = NULL;
	struct _u_request reg_request;
	struct _u_response reg_response;
	int i = 0, ret = 0, sockaddrlen = 0, fail = 0, j = 0;
	char *messageidchar = NULL, hostname[256]="", *tmpchar;
	struct Events event = {0};
	struct Clearing clearing ={0};
	event.isclearmessage = 0; // Need to be initialized
	struct userdata* input_action = (struct userdata*) user_data;
	json_body = ulfius_get_json_body_request(request, NULL);
	if(!json_is_object(json_body))
	{
		CRIT( "error: commit data is not an object\n");
		json_decref(json_body);
		return 1;
	}
	// Added for debug - Remove
	/*
	tmpchar = json_dumps(json_body, 8);
	fprintf(stderr, "DEBUG: Full body\n %s \nDONE\n", tmpchar);
	*/

	// Check if this is an Array and process
	if(json_is_array(json_body)) {
		CRIT( "Error, the callback function did not expect "
							"an array here\n");
		json_decref(json_body);
		return U_CALLBACK_ERROR;
	}

	// We need the hostname for the DB
	if (request->client_address->sa_family == AF_INET) {
		sockaddrlen = sizeof(struct sockaddr);
	} else if (request->client_address->sa_family == AF_INET6) {
		sockaddrlen = sizeof(struct sockaddr_in);
	} else {
		// We only support IPv4 and IPv6
		CRIT( "Error, the callback function did not "
					"expect this address family\n");
		json_decref(json_body);
		return U_CALLBACK_ERROR;
	}
	ret = getnameinfo(request->client_address, sockaddrlen,
			  hostname, 256, NULL, 0, 0);
	if (0 != ret) {
		CRIT( "getnameinfo couldn't get a hostname \n");
		CRIT( "will go with ip address instead\n");
	}
	// Need to get the message(s) out of the json_body and commit them to
	// the DB
	events = json_object_get(json_body, "Events");
	if (events == NULL) {
		json_decref(json_body);
		return 1;
	}
	i = json_array_size(events);
	// Go through the events array
	// Lock the mutex first
	g_mutex_lock(input_action->ulfius_lock);
	for (i=0; i < json_array_size(events); i++) {
		// Need to add some checking here
		eventsobj = json_array_get(events, i);
		messageid = json_object_get(eventsobj, "MessageId");
		if (messageid == NULL) {
			json_decref(eventsobj);
			json_decref(events);
			json_decref(json_body);
			return 1;
		}
		messageidchar = strdup(json_string_value(messageid));
		tmpchar = strtok(messageidchar, ".");
		event_reg_body = get_event_registry(hostname, tmpchar, DB_PATH,
				&reg_request, &reg_response);
		if (event_reg_body == NULL) {
			CRIT( "The callback function failed to "
				       "get the event_registry\n");
			json_decref(messageid);
			json_decref(eventsobj);
			json_decref(events);
			json_decref(json_body);
			free(messageidchar);
			ulfius_clean_request(&reg_request);
			ulfius_clean_response(&reg_response);
			return U_CALLBACK_ERROR;
		}
		event_reg = json_object_get(event_reg_body, "Messages");
		if(!json_is_object(event_reg)){
			CRIT( "The callback function failed to "
				       "get the event_registry\n");
			json_decref(event_reg_body);
			json_decref(messageid);
			json_decref(eventsobj);
			json_decref(events);
			json_decref(json_body);
			free(messageidchar);
			ulfius_clean_request(&reg_request);
			ulfius_clean_response(&reg_response);
			return U_CALLBACK_ERROR;

		}
		clrmsgs = malloc(sizeof(json_t *));
		ret = preparedbmessage(eventsobj, event_reg, hostname,
				       &event, clrmsgs);
		if (ret != 0 ) {
			CRIT("We got an event we cannot handle\n");
			fail = 1;
		}
		// Commit to DB and check return code
		if(!ISCLEARMODE || (event.isclearmessage != 1)) {
			if (commitevent2db(&event, DB_PATH) != 0) {
				CRIT("We couln't commit an Event to the "
				     "database\n");
				fail = 1;
			}
		}
		if (event.isclearmessage == 1) {
			// Insert logic to populate a bunch of Clearing Structs
			strcpy(clearing.host, event.host);
			strcpy(clearing.originofcondition,
			       event.originofcondition);
			strcpy(clearing.messageid, event.messageid);
			clearing.time = event.time;
			for (j=0; j < json_array_size(*clrmsgs); j++) {
				clearingmessage =
					json_array_get(*clrmsgs, j);
				if (NULL == clearingmessage){
					free(messageidchar);
					json_decref(event_reg);
					json_decref(event_reg_body);
					json_decref(messageid);
					json_decref(eventsobj);
					json_decref(events);
					json_decref(json_body);
					ulfius_clean_request(&reg_request);
					ulfius_clean_response(&reg_response);
					return 1;
				}
				strcpy(clearing.clearmessage,
				       json_string_value(clearingmessage));
				if(ISCLEARMODE)
					deleteclearing(&clearing, DB_PATH);
				else
					commitclearing2db(&clearing, DB_PATH);
			}
			// json_decref(*clrmsgs); // Causes a seg fault, likely
			// because another object has been decreffed
		}
		free(clrmsgs); // verify
	}

	ulfius_set_string_body_response(response, 200, "Created");
	free(messageidchar);
	json_decref(event_reg);
	json_decref(event_reg_body);
	json_decref(messageid);
	json_decref(events);
	json_decref(eventsobj);
	json_decref(json_body);
	ulfius_clean_request(&reg_request);
	ulfius_clean_response(&reg_response);
	// The below can probably be moved up to speed up things
	g_mutex_unlock(input_action->ulfius_lock);
	if (fail == 1)
		return U_CALLBACK_ERROR;
	else
		return U_CALLBACK_CONTINUE;
}

/**
 * Main listener Thread
 */

void *listener(void *input) {
	int ret;
	struct _u_instance instance;
	struct userdata* input_action = (struct userdata*) input;

	// Initialize instance with the port number
	if (ulfius_init_instance(&instance, PORT, NULL, NULL) != U_OK) {
		CRIT( "Error ulfius_init_instance, abort\n");
		ulfius_stop_framework(&instance);
		ulfius_clean_instance(&instance);
		pthread_exit(NULL);
	}

	// Endpoint list declaration
	ulfius_add_endpoint_by_val(&instance, "POST",
				   "/redfish/v1/EventService/Subscriptions",
				   NULL, 0, &callback_post, input);

	// Start the framework
	char * key_pem = read_file(input_action->key_path);
	char *cert_pem = read_file(input_action->cert_path);
	if ((key_pem == NULL) || (cert_pem == NULL)) {
		CRIT( "Couldn't read the cert/key files\n");
		ulfius_stop_framework(&instance);
		ulfius_clean_instance(&instance);
		// pthread_exit(NULL);
		exit(1);
	}
	ret = ulfius_start_secure_framework(&instance, key_pem, cert_pem);
	o_free(key_pem);
	o_free(cert_pem);
	if (ret == U_OK) {
		y_log_message(Y_LOG_LEVEL_DEBUG, "Start framework on port %d",
			      PORT);
		// Wait for the user to press <enter> on the console to quit
		// the application
		// getchar();
		while (1) {
			if(input_action->shutdown){
				break;
			}
			sleep(1);
		}

	} else {
		y_log_message(Y_LOG_LEVEL_DEBUG, "Error starting framework");
		CRIT("Error starting framework");
	}

	CRIT("End framework\n");

	ulfius_stop_framework(&instance);
	ulfius_clean_instance(&instance);
	pthread_exit(NULL);
}

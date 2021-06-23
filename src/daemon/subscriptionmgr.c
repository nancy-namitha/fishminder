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
 *      Hemantha Beecherla <hemantha.beecherla@hpe.com>
 *
 **/


#include "rfeventrec.h"
#include "subscriptionmgr.h"
#include "credentialmgr.h"
#include "listener.h"


/*
 * update_subscription
 * returns: 0 on success 1 on failure
 * takes: struct Credentials pointer
 *
 * */
int update_subscription(struct Subscriptions* input_subscription, const char* db_path){
	sqlite3 *db = NULL;
	char *zErrMsg = 0;
	int rc = 0;
	char *sql = NULL;
	sqlite3_stmt *pstmt = NULL;
	//const char insertblob[] = "oijfoiwjefoijoeifowfjweofhueivbb";
	/* Open database */
	rc = sqlite3_open(db_path, &db);

	if( rc ) {
		CRIT( "Can't open database: %s\n",
				sqlite3_errmsg(db));
		return(1);
	} else {
		DBG( "Opened database successfully\n");
	}

	/* Create merged SQL statement */
	sql = sqlite3_mprintf("UPDATE subscriptions set "
			"subscription_url= ifnull('%s',subscription_url) "
			"where host = '%s' and subscription_type = '%s';", 
			input_subscription->subscription_url,
			input_subscription->host,
			input_subscription->subscription_type);
	if(!sql){
		CRIT( "Failed to allocate enough memory");
		sqlite3_free(sql);
		sqlite3_close(db);
		return 1;
	}
	/* Execute SQL statement */
	rc = sqlite3_exec(db, sql, 0, 0, &zErrMsg);
	sqlite3_free(sql);

	if( rc != SQLITE_OK ) {
		CRIT( "SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
		sqlite3_close(db);
		return 1;
	} else {
		DBG( "Operation done successfully\n");
	}
	// Clean up DB and close it.
	sqlite3_close(db);
	return 0;
}


/**
 * get_all_creds_callback
 * returns: 1 on failure 0 on success.
 * takes: Void* data_head (Credentials_list* pointer as void*)
 * Needs to be freed
 */

int get_all_subs_callback(void* data_head, int argc, char **argv,
                char **azColName) {

	struct Subscription_list *head = (struct Subscription_list*) data_head;
	if(!head){
		return 1;
	}
	struct Subscription_list* tmp = (struct Subscription_list*)
					calloc(1,sizeof(struct Subscription_list));
	tmp->next = NULL;
	strcpy(tmp->subscription.host, argv[0]);
	strcpy(tmp->subscription.subscription_type, argv[1]);
	if(argv[2] != NULL){
		strcpy(tmp->subscription.subscription_url, argv[2]);
	}else{
		strcpy(tmp->subscription.subscription_url, "");
	}
	while(head->next){
		head = head->next;
	}
	head->next = tmp;
	/*
	   for (int i = 0; i < argc; i++) {

	   printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
	   }

	   printf("\n");
	   */
	return 0;
}

struct Subscription_list *get_subscription_for_host(char* input_host ,
		const char* db_path) 
{

	sqlite3 *db;
	char *err_msg = 0, *sql = NULL;
	struct Subscription_list subs_head = {{{0}}};
	int rc = sqlite3_open(db_path, &db);

	if (rc != SQLITE_OK) {

		CRIT( "Cannot open database: %s\n",
				sqlite3_errmsg(db));
		sqlite3_close(db);

		return NULL;
	}

	ASPRINTF(&sql, "SELECT * FROM subscriptions WHERE host LIKE '%s%%'", input_host);

	rc = sqlite3_exec(db, sql, get_all_subs_callback, &subs_head,
			&err_msg);
	free(sql);
	if (rc != SQLITE_OK ) {

		CRIT( "Failed to select data\n");
		CRIT( "SQL error: %s\n", err_msg);

		sqlite3_free(err_msg);
		sqlite3_close(db);

		return NULL;
	}

	sqlite3_close(db);

	return subs_head.next;
}

struct Subscriptions *get_subscription(char *input_host, char *subs_type, const char* db_path) 
{
	struct Subscriptions *mysubscriptions = NULL;
	sqlite3 *db;
	sqlite3_stmt *res;
	// Open the DB and populate the Credential object
	int rc = sqlite3_open(db_path, &db);
	if (rc != SQLITE_OK) {
		printf("Couldn't open database sqlite3");
		return NULL;
	}
	char *sql = "SELECT host,subscription_type,subscription_url "
				" FROM subscriptions WHERE host = ? and subscription_type = ?";
	rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
	if (rc == SQLITE_OK) {
		sqlite3_bind_text(res, 1, input_host,
				  strlen(input_host), NULL);
		sqlite3_bind_text(res, 2, subs_type,
				  strlen(subs_type), NULL);
	} else {
		CRIT( "Failed to execute statement: %s\n",
			sqlite3_errmsg(db));
	}
	int step = sqlite3_step(res);
	mysubscriptions = g_malloc0(sizeof(struct Subscriptions));
	if(!mysubscriptions){
		CRIT( "Failed to allocate enough memory");
		sqlite3_finalize(res);
		sqlite3_close(db);
		return NULL;
	}
	// NULL the creds
	if (step == SQLITE_ROW) {
		// Yay, we got a row back. We know about this guy
		strcpy(mysubscriptions->host,
		       (const char *)sqlite3_column_text(res, 0));
		strcpy(mysubscriptions->subscription_type,
		       (const char *)sqlite3_column_text(res, 1));
		// Could be NULL
		if (NULL !=  sqlite3_column_text(res, 2)) {
			strcpy(mysubscriptions->subscription_url,
			       (const char *)sqlite3_column_text(res, 2));
		} else {
			strcpy(mysubscriptions->subscription_url, "");
		}
	} else {
		// This guy is not known to us. We will return NULL
		free(mysubscriptions);
		sqlite3_finalize(res);
		sqlite3_close(db);
		return NULL;
	}
	// Clean up DB and close it.
	sqlite3_finalize(res);
	sqlite3_close(db);


	return mysubscriptions;
}


/*
 * insert_subscription
 * returns: 0 on success 1 on failure
 * takes: struct Subscriptions pointer
 *
 * */
int insert_subscription(struct Subscriptions* input_subs, const char* db_path){
	sqlite3 *db = NULL;
	char *zErrMsg = 0;
	int rc = 0;
	char *sql = NULL;

	/* Open database */
	rc = sqlite3_open(db_path, &db);
	if( rc ) {
		CRIT("Can't open database: %s\n", sqlite3_errmsg(db));
		return 1;
	} else {
		CRIT( "Opened database successfully\n");
	}

	/* Create SQL statement */
	sql = sqlite3_mprintf("INSERT INTO subscriptions (host,subscription_type, subscription_url) VALUES"
			"('%s','%s','%s');",
			input_subs->host, input_subs->subscription_type,
			input_subs->subscription_url);

	if(!sql){
		CRIT( "Failed to allocate enough memory");
		sqlite3_close(db);
		return 1;
	}
	/* Execute SQL statement */
	rc = sqlite3_exec(db, sql, 0, 0, &zErrMsg);

	if( rc != SQLITE_OK ){
		CRIT( "SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
		sqlite3_close(db);
		sqlite3_free(sql);
		return 1;
	} else {
		DBG( "Records created successfully\n");
	}
	sqlite3_close(db);
	sqlite3_free(sql);
	return 0;
}

/*
 * delete_subscription
 * returns: 0 on success 1 on failure
 * takes: char ponter to hostname
 *
 * */
int delete_subscription (char *hostname, char  *subs_type, const char* db_path){
	sqlite3 *db = NULL;
	char *zErrMsg = 0;
	int rc = 0;
	char *sql = NULL;

	/* Open database */
	rc = sqlite3_open(db_path, &db);

	if( rc ) {
		CRIT( "Can't open database: %s\n",
				sqlite3_errmsg(db));
		return(1);
	} else {
		CRIT( "Opened database successfully\n");
	}

	/* Create merged SQL statement */
	sql = sqlite3_mprintf("DELETE FROM subscriptions WHERE host = '%s' and subscription_type = '%s';",
			hostname, subs_type);

	if(!sql){
		CRIT( "Failed to allocate enough memory");
		sqlite3_close(db);
		return 1;
	}
	/* Execute SQL statement */
	rc = sqlite3_exec(db, sql, 0, 0, &zErrMsg);
	sqlite3_free(sql);

	if( rc != SQLITE_OK ) {
		CRIT( "SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
		sqlite3_close(db);
		return 1;
	} else {
		DBG( "Operation done successfully\n");
	}
	sqlite3_close(db);
	return 0;
}


char* get_event_service_subscription_uri(struct Credentials *cred)
{
	struct _u_request request;
	struct _u_response response;
	struct _u_map map_header;
	json_error_t myjsonerr;
	char* eventService_url = NULL;
	int res = 0;
	char* url = NULL;
	ulfius_init_request(&request);
	ulfius_init_response(&response);
	request.http_verb = o_strdup("GET");
	ASPRINTF(&url, REDFISH_ROOT_URI, cred->host);
	request.http_url = o_strdup(url);
	free(url);
	url = NULL;
	request.check_server_certificate = 0;
	/*Set up header */
	u_map_init(&map_header);
	u_map_put(&map_header, "X-Auth-Token", cred->x_auth_token);
	u_map_copy_into(request.map_header, &map_header);
	res = ulfius_send_http_request(&request, &response);
	if(res != U_OK){
		u_map_clean(&map_header);
		ulfius_clean_request(&request);
		ulfius_clean_response(&response);
		return NULL;
	}
	u_map_clean(&map_header);
	if(response.status == 200){
		json_t *json_body =
			ulfius_get_json_body_response(&response,
					&myjsonerr);
		if(!json_is_object(json_body)){
			CRIT("error: data is not an object \n");
			json_decref(json_body);
			ulfius_clean_request(&request);
			ulfius_clean_response(&response);
			return NULL;
		}
		json_t *json_eventService =
			json_object_get(json_body, "EventService");
		json_t *json_odataId = json_object_get(json_eventService, "@odata.id");
		char* eventService_odata = (char*) json_string_value(json_odataId);

		if(!eventService_odata){
			CRIT("error: EventService url is null");
			json_decref(json_body);
			ulfius_clean_request(&request);
			ulfius_clean_response(&response);
			return NULL;
		}
		ASPRINTF(&eventService_url, "%s", eventService_odata);
		json_decref(json_body);
	}else{
		ulfius_clean_request(&request);
		ulfius_clean_response(&response);
		return NULL;
	}
	ulfius_clean_request(&request);
	ulfius_clean_response(&response);
	ulfius_init_request(&request);
	ulfius_init_response(&response);
	request.http_verb = o_strdup("GET");
	ASPRINTF(&url, "https://%s%s",cred->host, eventService_url);
	printf("Subscription API : %s",url);
	free(eventService_url);
	request.http_url = o_strdup(url);
	free(url);
	url = NULL;
	request.check_server_certificate = 0;
	/* Set up header */
	u_map_init(&map_header);
	u_map_put(&map_header, "X-Auth-Token", cred->x_auth_token);
	u_map_copy_into(request.map_header, &map_header);
	res = ulfius_send_http_request(&request, &response);
	if(res != U_OK){
		u_map_clean(&map_header);
		ulfius_clean_request(&request);
		ulfius_clean_response(&response);
		return NULL;
	}
	u_map_clean(&map_header);
	if(response.status == 200){
		json_t *json_body =
			ulfius_get_json_body_response(&response, &myjsonerr);
		if(!json_is_object(json_body)){
			CRIT("error: data is not an object \n");
			ulfius_clean_request(&request);
			ulfius_clean_response(&response);
			return NULL;
		}
		json_t *json_subscriptions = json_object_get(json_body, "Subscriptions");
		json_t* json_odataId = json_object_get(json_subscriptions, "@odata.id");
		char* url_to_subscribe = (char*)json_string_value(json_odataId);
		DBG("url_to_subscribe : %s",url_to_subscribe);
		if(!url_to_subscribe){
			CRIT("error: Url to subscribe is NULL");
			json_decref(json_body);
			ulfius_clean_request(&request);
			ulfius_clean_response(&response);
			return NULL;
		}
		ASPRINTF(&url, "%s", url_to_subscribe);
		json_decref(json_body);

	}else {
		ulfius_clean_request(&request);
		ulfius_clean_response(&response);
		return NULL;
	}
	ulfius_clean_request(&request);
	ulfius_clean_response(&response);
	return url;

}
char *unsubscribe(char* input_host, char* subs_type, const char* db_path){
	struct Credentials *cred = NULL;
	struct Subscriptions *subs = NULL;
	struct _u_request request;
	struct _u_response response;
	struct _u_map map_header;
	char *returnstring = NULL;
	int res = 0;

	subs = get_subscription(input_host, subs_type,  DB_PATH);
	if (!subs) { 
		g_free(subs);
		subs = NULL;
		returnstring = (char *) g_malloc0(81*(sizeof(char)));
		strcpy(returnstring, "unsubscribe: no such subscription in the DB, "
		       "or other DB issues. Look in syslog.");
		return returnstring;

	}
	cred = get_creds(input_host, db_path);
	if(!cred){
		g_free(cred);
		cred = NULL;
		returnstring = (char *) g_malloc0(76*(sizeof(char)));
		strcpy(returnstring, "unsubscribe: no such server in the DB, "
		       "or other DB issues. Look in syslog.");
		return returnstring;
	}
	if(!subs->subscription_url || !cred->x_auth_token ||
			!strcmp(subs->subscription_url, "") ||
			!strcmp(cred->x_auth_token, "")){
		/* Subscription is not alive lets remove this record,
		 * by return NULL here*/
		g_free(cred);
		g_free(subs);
		return NULL;
	}
	ulfius_init_request(&request);
	ulfius_init_response(&response);
	request.http_verb = o_strdup("DELETE");
	request.http_url = o_strdup(subs->subscription_url);
	request.check_server_certificate = 0;
	/* make sure x_auth_token is valid, before trying to unsubscribe*/
	char *x_auth_token = get_session_token(cred, db_path);
	/* Set up header */
	u_map_init(&map_header);
	u_map_put(&map_header, "X-Auth-Token", x_auth_token);
	free(x_auth_token); // Dangerous?
	//request.map_header = &map_header; // Causes segfaults
	u_map_copy_into(request.map_header, &map_header);
	/* Send the request to delete the subscription */
	res = ulfius_send_http_request(&request, &response);
	g_free(cred);
	g_free(subs);
	cred = NULL;
	if (res != U_OK){
		CRIT("Could not send http request \n");
		returnstring = (char *) g_malloc0(40*(sizeof(char)));
		strcpy(returnstring, "Internal error in unsubscribe function");
		u_map_clean(&map_header);
		ulfius_clean_request(&request);
		ulfius_clean_response(&response);
		return returnstring;
	}
	if(200 == response.status){
		INFO("Successfully deleted/unsubscribed host %s",
				input_host);

	}else{
		CRIT("Failed to delete/unsbscribe with return code %ld",
				response.status);
		returnstring = (char *) g_malloc0(50*(sizeof(char)));
		sscanf(returnstring, "Failed to delete/unsbscribe with "
				       "return code %ld", &response.status);
		u_map_clean(&map_header);
		ulfius_clean_request(&request);
		ulfius_clean_response(&response);
		return returnstring;
	}
	u_map_clean(&map_header);
	ulfius_clean_request(&request);
	ulfius_clean_response(&response);
	return returnstring;
}
gboolean is_this_my_subscription(struct Credentials* cred, char *sub_url,
				 char* destination)
{

	struct _u_request request;
	struct _u_response response;
	struct _u_map map_header;
	json_error_t myjsonerr;
	int res = 0;
	gboolean myreturn = TRUE;

	ulfius_init_request(&request);
	ulfius_init_response(&response);

	request.http_verb = o_strdup("GET");
	request.http_url = o_strdup(sub_url);
	request.check_server_certificate = 0;
	/* Set up header */
	u_map_init(&map_header);
	u_map_put(&map_header, "X-Auth-Token", cred->x_auth_token);
	//request.map_header = &map_header; Causes seqfaults
	u_map_copy_into(request.map_header, &map_header);
	/* Send the request to get the registry */
	res = ulfius_send_http_request(&request, &response);
	if (res != U_OK){
		u_map_clean(&map_header);
		ulfius_clean_request(&request);
		ulfius_clean_response(&response);
		return FALSE;
	}
	if(response.status == 200){
		json_t *json_body =
			ulfius_get_json_body_response(&response,
					&myjsonerr);
		if(!json_is_object(json_body)){
			CRIT(
					"error: data is not an object \n");
			myreturn = FALSE;
		}
		json_t *json_dest = json_object_get(json_body, "Destination");
		char* dest_url = (char*) json_string_value(json_dest);
		if(!dest_url){
			CRIT("error: destination url is null");
			myreturn = FALSE;
		}
		if(!strstr(dest_url, destination)){
			INFO("Not our subscription");
			myreturn = FALSE;
		}
		json_decref(json_body);
	}
	u_map_clean(&map_header);
	ulfius_clean_request(&request);
	ulfius_clean_response(&response);
	return myreturn;
}

char *subscribe(struct Credentials* cred, struct Subscriptions* subs, char* destination, int port,
		const char* db_path, gboolean aggregatormode){
	struct _u_request request;
	struct _u_response response;
	struct Events *input = NULL;
	time_t action_time;
	struct _u_map map_header;
	struct _u_map *header = NULL;
	char *url = NULL, *postfields = NULL, *returnstring = NULL;
	char *x_auth_token = NULL, *url_link = NULL;
	json_error_t myjsonerr;
	int res = 0;
	/*Sucribe to the equipement using credetials,
	 * make the login post and subscribe*/
	json_error_t error;
	if(!cred->x_auth_token || !strcmp(cred->x_auth_token, "")){
		x_auth_token = get_session_token(cred, db_path);
		if(!x_auth_token){
			returnstring = (char *) g_malloc0(48*(sizeof(char)));
			strcpy(returnstring, "Failed to get the X_AUTH_TOKEN "
				"or login failed");
			CRIT("Failed to get the X_AUTH_TOKEN or login failed"
				    " for host %s", cred->host);
			return returnstring;
		}
		strcpy(cred->x_auth_token, x_auth_token);
		free(x_auth_token); // Needed as it is allocated
	}
	char* subscription_uri = get_event_service_subscription_uri(cred);
	if(subscription_uri == NULL){
		returnstring = (char *) g_malloc0(48*(sizeof(char)));
		strcpy(returnstring, "Failed to get the subscription uri ");
		CRIT("Failed to get the subscription URI"
			    " for host %s", cred->host);
		return returnstring;
	}
	ASPRINTF(&url, "https://%s%s", cred->host, subscription_uri);
	//CRIT("Complete Subscription API: %s\n",url);
	free(subscription_uri);
	/* Build the subscritpion request body according to
	 * aggregator mode flag */
	if (!strcmp(subs->subscription_type , "Alert")) {
		if (aggregatormode == TRUE){
			ASPRINTF(&postfields, REDFISH_AGGREGATOR_SUBSCRIPTION_POST,
					destination, port );
		}else{
			ASPRINTF(&postfields, REDFISH_SUBSCRIPTION_POST,
					destination, port );
		}
	} else {
		ASPRINTF(&postfields, REDFISH_METRICS_SUBSCRIPTION_POST,
				destination, port );
	}
	ulfius_init_request(&request);
	ulfius_init_response(&response);
	request.http_verb = o_strdup("POST");
	request.http_url = o_strdup(url);
	free(url);
	url = NULL;
	request.check_server_certificate = 0;
	/* Set up header */
	u_map_init(&map_header);
	u_map_put(&map_header, "X-Auth-Token", cred->x_auth_token);
	// request.map_header = &map_header; segfaults
	u_map_copy_into(request.map_header, &map_header);
	json_t* postbody = json_loads(postfields, JSON_REJECT_DUPLICATES,
				&error);
	if(postbody == NULL) {
		free(postfields);
		CRIT("json_loads returned NULL\n");
		u_map_clean(&map_header);
		ulfius_clean_request(&request);
		ulfius_clean_response(&response);
		returnstring = (char *) g_malloc0(32*(sizeof(char)));
		strcpy(returnstring, "json_loads failed in subscribe");
		free(postfields);
		return returnstring;
	}
	free(postfields);
	res = ulfius_set_json_body_request(&request, postbody);
	if (res != 0) {
		returnstring = (char *) g_malloc0(35*(sizeof(char)));
		strcpy(returnstring, "subscribe: Could not set authbody");
		CRIT("Could not set authbody\n");
		u_map_clean(&map_header);
		ulfius_clean_request(&request);
		ulfius_clean_response(&response);
		return returnstring;
	}
	/* Send the request */
	res = ulfius_send_http_request(&request, &response);
	json_decref(postbody); //DANGEROUS?
	//CRIT("response code : %d", res);
	if (res != U_OK){
		returnstring = (char *) g_malloc0(40*(sizeof(char)));
		strcpy(returnstring, "subscribe: Could not send http request");
		CRIT("Could not send http request \n");
		u_map_clean(&map_header);
		ulfius_clean_request(&request);
		ulfius_clean_response(&response);
		return returnstring;
	}
	//CRIT("response.status: %ld", response.status);
	// below check is a special check it has to be done before any of the check
	// here we try to get actual response and status code, and then continue as usual
	if (202 == response.status){
                // get the taskmon uri from location header
                // keep polling untill we get status code other than 202
                struct _u_map *header = NULL;
                header = response.map_header;
                const char* location = u_map_get(header, "Location");
                url = NULL;
                ASPRINTF(&url, "https://%s%s", cred->host, location);


//              get_request()
                u_map_clean(&map_header);
                ulfius_clean_request(&request);
                ulfius_clean_response(&response);
                ulfius_init_request(&request);
                ulfius_init_response(&response);
                request.http_verb = o_strdup("GET");
                request.http_url = o_strdup(url);
                request.check_server_certificate = 0;
                free(url);
                url = NULL;
                /* Set up header */
                u_map_init(&map_header);
                u_map_put(&map_header, "X-Auth-Token", cred->x_auth_token);
                // request.map_header = &map_header; segfaults
                u_map_copy_into(request.map_header, &map_header);
                /* Send the request to get the registry */
		while (1){
			ulfius_clean_response(&response);
			ulfius_init_response(&response);
			res = ulfius_send_http_request(&request, &response);
			if (res != U_OK){
				CRIT("ulfius_send_http_request failed");
				returnstring = (char *) g_malloc0(55*(sizeof(char)));
				strcpy(returnstring, "ulfius_send_http_request failed "
						"in subscribe function");
				goto CLEAN;
			}
			if (response.status != 202){
				break;
			}
		}


        }
	if(201 == response.status){
		header = response.map_header;
		if(0 == u_map_has_key(header, "Location")){
			returnstring = (char *) g_malloc0(32*(sizeof(char)));
			CRIT("\n We didn't get Subscription URL for"
					" host --> %s \n ", cred->host);
			strcpy(returnstring, "We didn't get Subscription URL");
			u_map_clean(&map_header);
			ulfius_clean_request(&request);
			ulfius_clean_response(&response);
			return returnstring;
		}
		const char* location = u_map_get(header, "Location");
		DBG("Subscription Url for host %s is %s for Event Type %s", cred->host,
					location, subs->subscription_type);
		memset(subs->subscription_url, 0, 256);
		DBG("In Subscribe function: %s",location);
		if (!strstr(location, "http")){
			char *loc_url;
			ASPRINTF(&loc_url,"https://%s%s",cred->host,location)
			strcpy(subs->subscription_url, loc_url);
		}else{
			strcpy(subs->subscription_url, location);
		}
		// free((char *)location); // Dangerous?
		/* Update DB with subscription URL below*/
		if(update_subscription(subs, db_path)){
			returnstring = (char *) g_malloc0(39*(sizeof(char)));
			CRIT("Failed to update the Subscription url"
				" %s in to db", cred->subscription_url);
			strcpy(returnstring, "Failed to update the "
			       "Subscription url");
			u_map_clean(&map_header);
			ulfius_clean_request(&request);
			ulfius_clean_response( &response);
			return returnstring;
		}else{
			/* Event in to db to tell the new subscription is 
			 * created*/
			input = g_malloc0(sizeof(struct Events));
			strcpy(input->host, cred->host);
			strcpy(input->severity, "Ok");
			strcpy(input->category,"subscription");
			strcpy(input->resolution,"");
			strcpy(input->message,
				"Subscription created");
			strcpy(input->messageid,"subscription");
			strcpy(input->originofcondition,
					"Subscription created");
			action_time = time(NULL);
			input->time =  action_time;
			commitevent2db(input, db_path);
			g_free(input);
			input = NULL;
		}
	}
	if(409 == response.status){
		CRIT("Subscription is alive but some how subscription url"
				" is missing in the DB for host %s",
				cred->host);
		u_map_clean(&map_header);
		ulfius_clean_request(&request);
		ulfius_clean_response(&response);
		ulfius_init_request(&request);
		ulfius_init_response(&response);
		url = NULL;
		char* subscription_uri = get_event_service_subscription_uri(cred);
		if(subscription_uri == NULL){
			returnstring = (char *) g_malloc0(48*(sizeof(char)));
			strcpy(returnstring, "Failed to get the subscription "
					"uri.");
			CRIT("Failed to get the subscription URI"
				    " for host %s", cred->host);
			return returnstring;
		}
		ASPRINTF(&url, "https://%s%s", cred->host, subscription_uri);
		free(subscription_uri);
		request.http_verb = o_strdup("GET");
		request.http_url = o_strdup(url);
		request.check_server_certificate = 0;
		free(url);
		url = NULL;
		/* Set up header */
		u_map_init(&map_header);
		u_map_put(&map_header, "X-Auth-Token", cred->x_auth_token);
		// request.map_header = &map_header; segfaults
		u_map_copy_into(request.map_header, &map_header);
		/* Send the request to get the registry */
		res = ulfius_send_http_request(&request, &response);
		if (res != U_OK){
			CRIT("ulfius_send_http_request failed");
			returnstring = (char *) g_malloc0(55*(sizeof(char)));
			strcpy(returnstring, "ulfius_send_http_request failed "
			       "in subscribe function");
			goto CLEAN;
		}
		if(response.status == 200){
			json_t *json_body =
				ulfius_get_json_body_response(&response,
						&myjsonerr);
			if(!json_is_object(json_body)){
				CRIT("error: data is not an object \n");
				returnstring = (char *)
						g_malloc0(40*(sizeof(char)));
				strcpy(returnstring, "Internal error in "
				       "subscribe function");
				json_decref(json_body);
				goto CLEAN;
			}
			json_t *members =
				json_object_get(json_body, "Members");
			if(members == NULL){
				CRIT("error: No members in JSON body\n");
				returnstring = (char *)
						g_malloc0(40*(sizeof(char)));
				strcpy(returnstring, "Internal error in "
				       "subscribe function");
				json_decref(json_body);
				goto CLEAN;
			}
			int count = json_array_size(members);

			for(int i=0; i< count; i++){
				json_t *sub_obj = json_array_get(members, i);
				if(!json_is_object(sub_obj)){
					continue;
				}

				json_t *odata_id = json_object_get(sub_obj, "@odata.id");


				/*if(!json_is_object(odata_id)){
					continue;
				} */
				url_link = (char*)json_string_value(odata_id);
				if(!url_link){
					continue;
				}
				ASPRINTF(&url_link, "https://%s%s", cred->host,
					(char*)json_string_value(odata_id));
				if(is_this_my_subscription(cred, url_link,
						destination)){
					memset(subs->subscription_url, 0, 256);
					strcpy(subs->subscription_url,
							url_link);
					if(update_subscription(subs, db_path)){
						CRIT(
						"Failed to update the "
						"Subscription url %s in to db",
						subs->subscription_url);
						returnstring = (char *)
						g_malloc0(40*(sizeof(char)));
						strcpy(returnstring, "Internal "
						"error in subscribe function");
						json_decref(json_body);
						goto CLEAN;
					}else{
					/* Event in to db to tell the existing
					 * subscription is inserted*/
						input = g_malloc0(
							sizeof(struct Events));
						strcpy(input->host,
								cred->host);
						strcpy(input->severity, "Ok");
						strcpy(input->category,
							"subscription");
						strcpy(input->resolution,"");
						strcpy(input->message,
						"Subscription inserted");
						strcpy(input->messageid,
							"subscription");
						strcpy(
						input->originofcondition,
						"Subscription inserted");
						action_time = time(NULL);
						input->time =  action_time;
						commitevent2db(input, db_path);
						g_free(input);
						input = NULL;
						json_decref(json_body);
						goto CLEAN;
					}
				}
				g_free(url_link);
			}
			json_decref(json_body);
		}
	}
	if(400 == response.status){
		returnstring = (char *) g_malloc0(32*(sizeof(char)));
		CRIT("\n We received bad request Error"
				" host --> %s \n ", cred->host);
		strcpy(returnstring, "We received 400 Error");
		ulfius_clean_request(&request);
		ulfius_clean_response(&response);
		return returnstring;
	}
CLEAN:
	u_map_clean(&map_header);
	ulfius_clean_request(&request);
	ulfius_clean_response(&response);
	return returnstring;
}

char *subscribe_events (  struct Credentials* cred, char *host,char *subs_type, gboolean aggregatormode)
{
	struct Subscriptions* subs = NULL;
	struct Events *event = NULL;
	time_t action_time;
	char *returnstring = NULL;

	subs = get_subscription(host, subs_type,  DB_PATH);
	if (!subs) {
		subs = NULL;
		subs = g_malloc0(sizeof( struct Subscriptions));
		strcpy(subs->host, host);
		strcpy(subs->subscription_type, subs_type);
		if(!insert_subscription(subs, DB_PATH)){
			INFO("Successfully inserted "
		     		"the subscription in to "
		     		"database");

			returnstring = subscribe(cred, subs, DESTINATION,
					LPORT, DB_PATH, aggregatormode);
			if (NULL != returnstring) {
				g_free(subs);
				subs = NULL;
				return returnstring;
			}
			event = g_malloc0(sizeof(struct Events));
			strcpy(event->host, host);
			strcpy(event->severity, "OK");
			strcpy(event->category, "subscription");
			strcpy(event->resolution,"");
			strcpy(event->message, "New credentials added by the "
	       		"user");
			strcpy(event->messageid, "subscription");
			strcpy(event->originofcondition ,"User Action");
			action_time = time(NULL);
			event->time =  action_time;
			commitevent2db(event, DB_PATH);
			g_free(event);
			event = NULL;
		} else {
			CRIT("Failed to insert the "
	     			"subscription in to database");
			returnstring = malloc(43*sizeof(char));
			strcpy(returnstring, "Internal error in "
					"subscribe_event function");
		}
	} else {
		CRIT("Failed to insert the subscription in to "
     		"the database as the subscription already "
     		"existed");
		returnstring = malloc(43*sizeof(char));
		strcpy(returnstring, "Internal error in "
			 "subscribe_event function");
	}
	g_free (subs);
	return returnstring;
}

char *fminder_action(char *subs_type, char * action, char *host, char *username,
		     char *password, gboolean aggregatormode) {
	struct Credentials* cred = NULL;
	struct Subscriptions* subs = NULL;
	struct Subscription_list *Subs_list = NULL;
	char* x_auth_token = NULL, *returnstring = NULL;
	struct Events *event = NULL;
	time_t action_time;
	// Lock mutex
	if(!strncasecmp(action, "add", 3)){
		// Check if host is already added
		cred = get_creds(host, DB_PATH);
		if(!cred){
		//	g_free(cred);
			cred = NULL;
			cred = g_malloc0(sizeof( struct Credentials));
			strcpy(cred->host, host);
			strcpy(cred->username, username);
			strcpy(cred->password, password);
			x_auth_token = get_session_token(cred, DB_PATH);
			if(x_auth_token){
				strcpy(cred->x_auth_token,
				       x_auth_token);
				free(x_auth_token);
			} else {
				returnstring = malloc(78*sizeof(char));
				strcpy(returnstring, "Couln't authenticate "
					"with server. Wrong credentials "
					"or server not reachable?");
				free(x_auth_token); // Needed?
				g_free(cred);
				return returnstring;
			}
			if(!insert_creds(cred, DB_PATH)){
				INFO("Successfully inserted "
				     "the credentials in to "
				     "database");
				returnstring = subscribe_events (cred, host, subs_type, aggregatormode);
				if (NULL != returnstring) {
					g_free(cred);
					cred = NULL;
					return returnstring;
				}
			}else{
				CRIT("Failed to insert the "
				     "credentials in to database");
				returnstring = malloc(43*sizeof(char));
				strcpy(returnstring, "Internal error in "
						"fminder_action function");
				//free(cred);
				//cred = NULL;
				//return returnstring;
			}
		}else{
			INFO(" Credential already present in DB ");
			returnstring = subscribe_events (cred, host, subs_type, aggregatormode);
			if (NULL != returnstring) {
				g_free(cred);
				cred = NULL;
				return returnstring;
			}

			//free(cred);
			//cred = NULL;
			//return returnstring;
		}
		g_free(cred);
		cred = NULL;
		return returnstring;
	}
	if(!strncasecmp(action, "remove", 6)){
		returnstring = unsubscribe(host, subs_type, DB_PATH);
		if(NULL == returnstring){

			if (delete_subscription (host, subs_type,  DB_PATH)) {
				CRIT("Failed to delete the "
				     "subscription from Database");
				returnstring = malloc(43*sizeof(char));
				strcpy(returnstring, "Internal error in "
			       		"fminder_action function");
				return returnstring;
			} else {
				Subs_list = get_subscription_for_host(host , DB_PATH);
				if (!Subs_list) { 
					if(delete_creds(host, DB_PATH)){
						CRIT("Failed to delete the "
					     	"credentials from Database");
						returnstring = malloc(43*sizeof(char));
						strcpy(returnstring, "Internal error in "
				       			"fminder_action function");
						return returnstring;
					}else{
						INFO("Successfully deleted "
				     		"the credentials from Database");
					}	
				}
				event = g_malloc0(
					  	sizeof(struct Events));
				strcpy(event->host, host);
				strcpy(event->severity, "Warning");
				strcpy(event->category,"subscription");
				strcpy(event->resolution,"");
				strcpy(event->message,
			       	"Credentials/subscription deleted by "
			       	"the user");
				strcpy(event->messageid,
			       	"subscription");
				strcpy(event->originofcondition,
			       	"User Action");
				action_time = time(NULL);
				event->time = action_time;
				commitevent2db(event, DB_PATH);
				g_free(event);
				event = NULL;
			}
		}else{
			CRIT("Subscriptions not found "
			     "or Failed to unsubscribe");
			return returnstring;
		}
		return returnstring;
	}
	CRIT("Action: %s not suppored", action);
	returnstring = malloc(30*sizeof(char));
	strcpy(returnstring, "Action not supported");
	return returnstring;
}

gboolean check_subscription_status(struct Credentials* cred, struct Subscriptions* subs, char *destination,
				   const char* db_path){
	struct _u_request request;
	struct _u_response response;
	struct Events *input = NULL;
	struct _u_map map_header;
	time_t action_time;
	json_error_t myjsonerr;
	char *url = NULL, *x_auth_token = NULL;
	int res = 0;
	ulfius_init_request(&request);
	ulfius_init_response(&response);
	if(!subs->subscription_url || !cred->x_auth_token ||
	   !strcmp(subs->subscription_url, "") ||
			!strcmp(cred->x_auth_token, "")){
		CRIT("First No Live Subscriptions for host %s", cred->host);
		ulfius_clean_request(&request);
		ulfius_clean_response(&response);
		return FALSE;
	}
	request.http_verb = o_strdup("GET");
//	ASPRINTF(&url, "https://%s%s/", cred->host,cred->subscription_url);
//	CRIT("check_subscription_status : %s \n",url);
	request.http_url = o_strdup(subs->subscription_url);
//	free(url); // Looks like url is not needed?
	request.check_server_certificate = 0;
	/* Set up header */
	u_map_init(&map_header);
	u_map_put(&map_header, "X-Auth-Token", cred->x_auth_token);
	// request.map_header = &map_header; segfaults
	u_map_copy_into(request.map_header, &map_header);
	/* Send the request to get the registry */
	res = ulfius_send_http_request(&request, &response);
	if (res != U_OK){
		u_map_clean(&map_header);
		ulfius_clean_request(&request);
		ulfius_clean_response(&response);
		return FALSE;
	}
	/* If we are not authorized we need a new x_auth_token
	 and try again */
	if (response.status == 401) {
		x_auth_token = get_session_token(cred, db_path);
		strcpy(cred->x_auth_token, x_auth_token);
		u_map_put(&map_header, "X-Auth-Token", x_auth_token);
		u_map_copy_into(request.map_header, &map_header);
		res = ulfius_send_http_request(&request, &response);
		if (response.status == 401){
			input = g_malloc0(sizeof(struct Events));
			strcpy(input->host, cred->host);
			strcpy(input->severity, "Critical");
			strcpy(input->category,"subscription");
			strcpy(input->resolution,"");
			strcpy(input->message,"Subscription expired");
			strcpy(input->messageid,"subscription");
			strcpy(input->originofcondition,
					"Subscription Expired");
			action_time = time(NULL);
			input->time =  action_time;
			commitevent2db(input, db_path);
			CRIT("Not Authorized to login to host %s",
					cred->host);
			g_free(input);
			input = NULL;
			u_map_clean(&map_header);
			ulfius_clean_request(&request);
			ulfius_clean_response(&response);
			return FALSE;
		}
	}
	if(response.status == 404){
		CRIT("Subscription was deleted, will be added back");
		input = g_malloc0(sizeof(struct Events));
		strcpy(input->host, cred->host);
		strcpy(input->severity, "Critical");
		strcpy(input->category,"subscription");
		strcpy(input->resolution,"");
		strcpy(input->message,"Subscription expired/deleted by user");
		strcpy(input->messageid,"subscription");
		strcpy(input->originofcondition,
				"Subscription Expired");
		action_time = time(NULL);
		input->time =  action_time;
		commitevent2db(input, db_path);
		g_free(input);
		input = NULL;
		u_map_clean(&map_header);
		ulfius_clean_request(&request);
		ulfius_clean_response(&response);
		return FALSE;
	}
	/* Check if we got something back or if the json has not changed */
	if (304 == response.status) {
		/* No change since last seen, So subscription is alive */
		INFO("No Change,Subscription is alive for host %s ",
				cred->host);
		u_map_clean(&map_header);
		ulfius_clean_request(&request);
		ulfius_clean_response(&response);
		return TRUE;
	}
	if(200 == response.status){
		/* Subscription is alive*/
		return TRUE;
		json_t *json_body =
			ulfius_get_json_body_response(&response, &myjsonerr);
		if(!json_is_object(json_body)){
			CRIT( "error: response data is not "
					"an object\n");
			u_map_clean(&map_header);
			json_decref(json_body);
			ulfius_clean_request(&request);
			ulfius_clean_response(&response);
			return FALSE;
		}
		json_t *json_dest = json_object_get(json_body, "Destination");
		const char* dest = json_string_value(json_dest);
		// Error checking on the above???
		if (dest == NULL) {
			WARN("subscriptionmgr check_subscription: couldn't "
			     "get a destination from js_string_value");
			u_map_clean(&map_header);
			json_decref(json_body);
			ulfius_clean_request(&request);
			ulfius_clean_response(&response);
			return FALSE;
		}
		if(!strstr(dest, destination)){
			/* No live subscriptions
			 * return FALSE here */
			WARN("Subscription for host %s is expired",
					cred->host);
			u_map_clean(&map_header);
			json_decref(json_body);
			ulfius_clean_request(&request);
			ulfius_clean_response(&response);
			return FALSE;
		}
		json_decref(json_body);
	}
	u_map_clean(&map_header);
	ulfius_clean_request(&request);
	ulfius_clean_response(&response);
	return TRUE;
}

void* subscription_mgr_thread( void *data){
	struct Credentials_list* Cred_list = NULL, *tmp = NULL;
	struct Credentials* cred = NULL;
	struct Subscription_list *Subs_list = NULL, *tmp_subs = NULL;
	struct Subscriptions* subs = NULL;
	struct Events *event = NULL;
	time_t action_time;
	gint64 end_time;
	char* x_auth_token = NULL;
	gboolean rv;
	struct userdata* input_action = (struct userdata*) data;

	while(1){
		if(input_action->shutdown){
			g_thread_exit(NULL);
		}
		/* g_con_wait unlocks mutex before going to sleep and then
		 * locks it after wake up*/
		g_mutex_lock(input_action->mutex_lock);
		end_time = g_get_monotonic_time () +  60 * G_TIME_SPAN_SECOND;
		if(g_cond_wait_until(&input_action->data_flag,
				input_action->mutex_lock, end_time)){
			if(input_action->shutdown){
				g_mutex_unlock(input_action->mutex_lock);
				g_thread_exit(NULL);
			}
		}
		/* Unlock the mutex once done with accessing userdata*/
		g_mutex_unlock(input_action->mutex_lock);
		g_mutex_lock(input_action->ulfius_lock);
		Cred_list = get_all_creds(DB_PATH);
		while(Cred_list){
			cred = &Cred_list->cred;
			Subs_list = get_subscription_for_host(cred->host , DB_PATH);
			while (Subs_list) {
				subs = &Subs_list->subscription;
				rv = check_subscription_status(cred, subs,
						DESTINATION, DB_PATH);
				if(!rv){
					if(NULL != subscribe(cred, subs, DESTINATION, LPORT,
					      	DB_PATH, input_action->aggregationmode)){
						/* Error Handling goes here*/
						/*update db with an event*/
						event = g_malloc0(sizeof(
								struct Events));
						strcpy(event->host, cred->host);
						strcpy(event->severity, "Critical");
						strcpy(event->category,"subscription");
						strcpy(event->resolution,
							"Network Access");
						strcpy(event->message,
							"Check Network connection");
						strcpy(event->messageid,
							"subscription");
						strcpy(event->originofcondition,
							"Connection to host lost");
						action_time = time(NULL);
						event->time = action_time;
						commitevent2db(event, DB_PATH);
						g_free(event);
						event = NULL;
					}
				}	
				tmp_subs=Subs_list;
				Subs_list=Subs_list->next;
				free(tmp_subs);
			}
			tmp = Cred_list;
			Cred_list = Cred_list->next;
			free(tmp);
		}
		g_mutex_unlock(input_action->ulfius_lock);
	}

}


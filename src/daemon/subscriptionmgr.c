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
char *unsubscribe(char* input_host, const char* db_path){
	struct Credentials *cred = NULL;
	struct _u_request request;
	struct _u_response response;
	struct _u_map map_header;
	char *returnstring = NULL;
	int res = 0;
	cred = get_creds(input_host, db_path);
	if(!cred){
		g_free(cred);
		cred = NULL;
		returnstring = (char *) g_malloc0(76*(sizeof(char)));
		strcpy(returnstring, "unsubscribe: no such server in the DB, "
		       "or other DB issues. Look in syslog.");
		return returnstring;
	}
	if(!cred->subscription_url || !cred->x_auth_token ||
			!strcmp(cred->subscription_url, "") ||
			!strcmp(cred->x_auth_token, "")){
		/* Subscription is not alive lets remove this record,
		 * by return NULL here*/
		g_free(cred);
		return NULL;
	}
	ulfius_init_request(&request);
	ulfius_init_response(&response);
	request.http_verb = o_strdup("DELETE");
	request.http_url = o_strdup(cred->subscription_url);
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

char *subscribe(struct Credentials* cred, char* destination, int port,
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
	CRIT("Complete Subscription API: %s\n",url);
	free(subscription_uri);
	/* Build the subscritpion request body according to
	 * aggregator mode flag */
	if (aggregatormode == TRUE){
		ASPRINTF(&postfields, REDFISH_AGGREGATOR_SUBSCRIPTION_POST,
				destination, port );
	}else{
		ASPRINTF(&postfields, REDFISH_SUBSCRIPTION_POST,
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
	CRIT("response code : %d", res);
	if (res != U_OK){
		returnstring = (char *) g_malloc0(40*(sizeof(char)));
		strcpy(returnstring, "subscribe: Could not send http request");
		CRIT("Could not send http request \n");
		u_map_clean(&map_header);
		ulfius_clean_request(&request);
		ulfius_clean_response(&response);
		return returnstring;
	}
	CRIT("response.status: %ld", response.status);
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
		DBG("Subscription Url for host %s is %s", cred->host,
					location);
		memset(cred->subscription_url, 0, 256);
		DBG("In Subscribe function: %s",location);
		if (!strstr(location, "http")){
			char *loc_url;
			ASPRINTF(&loc_url,"https://%s%s",cred->host,location)
			strcpy(cred->subscription_url, loc_url);
		}else{
			strcpy(cred->subscription_url, location);
		}
		// free((char *)location); // Dangerous?
		/* Update DB with subscription URL below*/
		if(update_creds(cred, db_path)){
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
				json_t *odata_id = json_object_get(sub_obj,
								   "@odata.id");
				if(!json_is_object(odata_id)){
					continue;
				}
				url_link = (char*)json_string_value(odata_id);
				if(!url_link){
					continue;
				}
				ASPRINTF(&url_link, "https://%s%s", cred->host,
					(char*)json_string_value(odata_id));
				if(is_this_my_subscription(cred, url_link,
						destination)){
					memset(cred->subscription_url, 0, 256);
					strcpy(cred->subscription_url,
							url_link);
					if(update_creds(cred, db_path)){
						CRIT(
						"Failed to update the "
						"Subscription url %s in to db",
						cred->subscription_url);
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
				free(url_link);
			}
			json_decref(json_body);
		}
	}
CLEAN:
	u_map_clean(&map_header);
	ulfius_clean_request(&request);
	ulfius_clean_response(&response);
	return returnstring;
}


char *fminder_action(char * action, char *host, char *username,
		     char *password, gboolean aggregatormode) {
	struct Credentials* cred = NULL;
	char* x_auth_token = NULL, *returnstring = NULL;
	struct Events *event = NULL;
	time_t action_time;
	// Lock mutex
	if(!strncasecmp(action, "add", 3)){
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
				returnstring = subscribe(cred, DESTINATION,
							LPORT, DB_PATH, aggregatormode);
				if (NULL != returnstring) {
					g_free(cred);
					cred = NULL;
					return returnstring;
				}
				event = g_malloc0(sizeof(
							 struct Events));
				strcpy(event->host,
				       host);
				strcpy(event->severity, "OK");
				strcpy(event->category,
				       "subscription");
				strcpy(event->resolution,"");
				strcpy(event->message,
				       "New credentials added by the "
				       "user");
				strcpy(event->messageid,
				       "subscription");
				strcpy(event->originofcondition
				       ,"User Action");
				action_time = time(NULL);
				event->time =  action_time;
				commitevent2db(event, DB_PATH);
				g_free(event);
				event = NULL;
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
			CRIT("Failed to insert the credentials in to "
			     "the database as the server already "
			     "existed");
			returnstring = malloc(43*sizeof(char));
			strcpy(returnstring, "Internal error in "
						 "fminder_action function");

			//free(cred);
			//cred = NULL;
			//return returnstring;
		}
		g_free(cred);
		cred = NULL;
		return returnstring;
	}
	if(!strncasecmp(action, "remove", 6)){
		returnstring = unsubscribe(host, DB_PATH);
		if(NULL == returnstring){
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
		}else{
			CRIT("Credentials not found "
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
gboolean check_subscription_status(struct Credentials* cred, char *destination,
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
	if(!cred->subscription_url || !cred->x_auth_token ||
	   !strcmp(cred->subscription_url, "") ||
			!strcmp(cred->x_auth_token, "")){
		CRIT("First No Live Subscriptions for host %s", cred->host);
		ulfius_clean_request(&request);
		ulfius_clean_response(&response);
		return FALSE;
	}
	request.http_verb = o_strdup("GET");
//	ASPRINTF(&url, "https://%s%s/", cred->host,cred->subscription_url);
//	CRIT("check_subscription_status : %s \n",url);
	request.http_url = o_strdup(cred->subscription_url);
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
			rv = check_subscription_status(cred,
					DESTINATION, DB_PATH);
			if(!rv){
				if(NULL != subscribe(cred, DESTINATION, LPORT,
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
			tmp = Cred_list;
			Cred_list = Cred_list->next;
			free(tmp);
		}
		g_mutex_unlock(input_action->ulfius_lock);
	}

}


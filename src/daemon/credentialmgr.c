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

#include "rfeventrec.h"
#include "credentialmgr.h"
#include "subscriptionmgr.h"
/**
 * get_session_url
 * returns: char *session_url like http://<ip>/v1/SessionService/Sessions/
 * input: char *ip
 */

char *get_session_url(char *host) {
	struct _u_request request;
	struct _u_response response;
	char *url = NULL;
	char *returnurl;
	int res;
	json_t *json_body, *links, *sessions, *odata_session_link;
	json_error_t myjsonerr;

	ulfius_init_request(&request);
	ulfius_init_response(&response);

	ASPRINTF(&url, REDFISH_ROOT_URI, host);
	request.http_verb = o_strdup("GET");
	request.http_url = o_strdup(url);
	free(url);
	url = NULL;
	request.check_server_certificate = 0;

	// Send the request to get the root
	res = ulfius_send_http_request(&request, &response);
	if (res != U_OK){
		ulfius_clean_response(&response);
		ulfius_clean_request(&request);
		return NULL;
	}
	json_body = ulfius_get_json_body_response(&response, &myjsonerr);
	if(!json_is_object(json_body))
	{
		CRIT( "error: commit data is not an object\n");
		json_decref(json_body);
		if (U_OK != ulfius_clean_response(&response)){
			CRIT( "error: could not clean response\n");
		}
		if (U_OK != ulfius_clean_request(&request)){
			CRIT( "error: could not clean request\n");
		}
		return NULL;
	}
	if(json_is_array(json_body)) {
		CRIT("JSON Object is Array, which we didn't expect\n");
		json_decref(json_body);
		if (U_OK != ulfius_clean_response(&response)){
			CRIT( "error: could not clean response\n");
		}
		if (U_OK != ulfius_clean_request(&request)){
			CRIT( "error: could not clean request\n");
		}
		return NULL;
	}
	links = json_object_get(json_body, "Links");
	if(!json_is_object(links))
	{
		CRIT( "error: commit data is not an object\n");
		json_decref(links);
		json_decref(json_body);
		if (U_OK != ulfius_clean_response(&response)){
			CRIT( "error: could not clean response\n");
		}
		if (U_OK != ulfius_clean_request(&request)){
			CRIT( "error: could not clean request\n");
		}
		return NULL;
	}
	sessions = json_object_get(links, "Sessions");
	if(!json_is_object(sessions))
	{
		CRIT( "error: commit data is not an object\n");
		json_decref(sessions);
		json_decref(links);
		json_decref(json_body);
		if (U_OK != ulfius_clean_response(&response)){
			CRIT( "error: could not clean response\n");
		}
		if (U_OK != ulfius_clean_request(&request)){
			CRIT( "error: could not clean request\n");
		}
		return NULL;
	}
	odata_session_link = json_object_get(sessions, "@odata.id");
	// This should be the session URI (a string)
	if(!json_is_string(odata_session_link))
	{
		CRIT( "error: commit data is not an object\n");
		json_decref(odata_session_link);
		json_decref(sessions);
		json_decref(links);
		json_decref(json_body);
		if (U_OK != ulfius_clean_response(&response)){
			CRIT( "error: could not clean response\n");
		}
		if (U_OK != ulfius_clean_request(&request)){
			CRIT( "error: could not clean request\n");
		}
		return NULL;
	}

	// Fix the return value
	returnurl = strdup(json_string_value(odata_session_link));

	// Clean up
	json_decref(json_body);
	if (U_OK != ulfius_clean_response(&response)){
		CRIT( "error: could not clean response\n");
	}
	if (U_OK != ulfius_clean_request(&request)){
		CRIT( "error: could not clean request\n");
	}

	return returnurl;

}

/**
 * get_session_token
 * This function post a new session
 * Returns: char *x-auth-token that can be used. It will also save this token to
 * the database
 * input: struct Credentials *mycreds
 */
char *get_session_token(struct Credentials *mycreds, const char* db_path) {
	struct _u_request request;
	struct _u_response response;
	char *url = NULL, *session = NULL;
	int res;
	const struct _u_map *header;
	const char *xauthtok;
	char *rettoken = NULL;
	json_t *authbody, *password, *username;
	sqlite3 *db;
	sqlite3_stmt *result;


	// Build the JSON body request
	authbody = json_object();
	password = json_string(mycreds->password);
	username = json_string(mycreds->username);
	res = json_object_set(authbody, "UserName", username);
	if (res != 0) {
		printf("Could not create authbody\n");
		exit(1);
	}
	res= json_object_set(authbody, "Password", password);
	if (res != 0) {
		printf("Could not create authbody\n");
		exit(1);
	}

	session = get_session_url(mycreds->host);
	if(!session){
		CRIT("Session is Null for host %s\n",mycreds->host);
		return NULL;
	}
	ulfius_init_request(&request);
	ulfius_init_response(&response);

	// Put together URL
	ASPRINTF(&url, "https://%s%s", mycreds->host, session);
	free(session);
	// Prepare the request further
	request.http_verb = o_strdup("POST");
	request.http_url = o_strdup(url);
	free(url);
	url = NULL;
	request.check_server_certificate = 0;
	res = ulfius_set_json_body_request(&request, authbody);
	if (res != 0) {
		printf("Could not set authbody\n");
		ulfius_clean_request(&request);
		return NULL;
	}
	res = ulfius_send_http_request(&request, &response);
	
	if (res != U_OK) {
		printf("Could not send the http request\n");
		ulfius_clean_response(&response);
		ulfius_clean_request(&request);
		return NULL;
	}
	header = response.map_header;
	if (0 == u_map_has_key(header, "X-Auth-Token")) {
		printf("We didn't get an X-Auth-Token for host %s ", mycreds->host);
		ulfius_clean_response(&response);
		ulfius_clean_request(&request);
		return NULL;
	}
	xauthtok = u_map_get(header, "X-Auth-Token");
	if (xauthtok == NULL) {
		CRIT( "We didn't get an X-Auth-Token");
		ulfius_clean_response(&response);
		ulfius_clean_request(&request);
		return NULL;
	}

	// Update the database
	int rc = sqlite3_open(db_path, &db);
	if (rc != SQLITE_OK) {
		CRIT("Couldn't open database sqlite3");
		ulfius_clean_response(&response);
		ulfius_clean_request(&request);
		return NULL;
	}
	char *sql = "UPDATE credentials SET x_auth_token = ? where host = ?";
	rc = sqlite3_prepare_v2(db, sql, -1, &result, 0);
	if (rc == SQLITE_OK) {
		sqlite3_bind_text(result, 1, xauthtok,
				  strlen(xauthtok), NULL);
		sqlite3_bind_text(result, 2, mycreds->host,
				  strlen(mycreds->host), NULL);
	} else {
		CRIT( "Failed to execute statement: %s\n",
			sqlite3_errmsg(db));
	}
	int step = sqlite3_step(result);
	if (!(SQLITE_DONE == step || SQLITE_ROW == step)) {
		CRIT( "The DB Update statement failed: %s\n",
			sqlite3_errmsg(db));
		ulfius_clean_response(&response);
		ulfius_clean_request(&request);
		sqlite3_finalize(result);
		sqlite3_close(db);
		return NULL;
	}
	rettoken = strdup(xauthtok);

	// Clean up DB and close it.
	sqlite3_finalize(result);
	sqlite3_close(db);

	// Clean up ulfius
	if (!(U_OK == ulfius_clean_request(&request)))
		CRIT( "failed to run ulfius_clean_request()");
	if (!(U_OK == ulfius_clean_response(&response)))
		CRIT( "failed to run ulfius_clean_response()");

	// Clean up Jansson
	json_decref(username);
	json_decref(password);
	json_decref(authbody);

	return rettoken;
}

/**
 * get_creds_like
 * returns: credentials_list struct
 * takes: a *char for an IP address or hostname
 * returned memory needs to be freed by the caller
 * if no records matches then creds_list->creds member variable points to NULL.
 */

struct Credentials_list *get_creds_like(char* input_host ,
		const char* db_path) {

	sqlite3 *db;
	char *err_msg = 0, *sql = NULL;
	struct Credentials_list cred_head = {{{0}}};
	int rc = sqlite3_open(db_path, &db);

	if (rc != SQLITE_OK) {

		CRIT( "Cannot open database: %s\n",
				sqlite3_errmsg(db));
		sqlite3_close(db);

		return NULL;
	}

	ASPRINTF(&sql, "SELECT * FROM credentials WHERE host LIKE '%s%%'", input_host);

	rc = sqlite3_exec(db, sql, get_all_creds_callback, &cred_head,
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

	return cred_head.next;
}

/**
 * get_creds
 * returns: credentials struct
 * takes: a *char for an IP address
 * Needs to be freed
 */

struct Credentials *get_creds(char *input_host, const char* db_path) {
	struct Credentials *mycreds = NULL;
	sqlite3 *db;
	sqlite3_stmt *res;
	// Open the DB and populate the Credential object
	int rc = sqlite3_open(db_path, &db);
	if (rc != SQLITE_OK) {
		printf("Couldn't open database sqlite3");
		return NULL;
	}
	char *sql = "SELECT username,password,subscription_url,x_auth_token,"
				"jsonetag, host FROM credentials WHERE host = ?";
	rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
	if (rc == SQLITE_OK) {
		sqlite3_bind_text(res, 1, input_host,
				  strlen(input_host), NULL);
	} else {
		CRIT( "Failed to execute statement: %s\n",
			sqlite3_errmsg(db));
	}
	int step = sqlite3_step(res);
	mycreds = g_malloc0(sizeof(struct Credentials));
	if(!mycreds){
		CRIT( "Failed to allocate enough memory");
		sqlite3_finalize(res);
		sqlite3_close(db);
		return NULL;
	}
	// NULL the creds
	mycreds->jsonreg = NULL;
	if (step == SQLITE_ROW) {
		// Yay, we got a row back. We know about this guy
		strcpy(mycreds->username,
		       (const char *)sqlite3_column_text(res, 0));
		strcpy(mycreds->password,
		       (const char *)sqlite3_column_text(res, 1));
		// Could be NULL
		if (NULL !=  sqlite3_column_text(res, 2)) {
			strcpy(mycreds->subscription_url,
			       (const char *)sqlite3_column_text(res, 2));
		} else {
			strcpy(mycreds->subscription_url, "");
		}
		if (NULL !=  sqlite3_column_text(res, 3)) {
			strcpy(mycreds->x_auth_token,
			       (const char *)sqlite3_column_text(res, 3));
		} else {
			strcpy(mycreds->x_auth_token, "");
		}
		if (NULL !=  sqlite3_column_text(res, 4)) {
			strcpy(mycreds->jsonetag,
			       (const char *)sqlite3_column_text(res, 4));
		} else {
			strcpy(mycreds->jsonetag, "");
		}
		strcpy(mycreds->host,
		       (const char *)sqlite3_column_text(res, 5));
	} else {
		// This guy is not known to us. We will return NULL
		free(mycreds);
		sqlite3_finalize(res);
		sqlite3_close(db);
		return NULL;
	}
	// Clean up DB and close it.
	sqlite3_finalize(res);
	sqlite3_close(db);

	// So do we need to get an X-Auth-Token
	if (strlen(mycreds->x_auth_token) == 0) {
		// We don't have an auth token, need to post a new session and
		// retrieve the returned token

	}

	return mycreds;
}

/**
 * get_all_creds_callback
 * returns: 1 on failure 0 on success. 
 * takes: Void* data_head (Credentials_list* pointer as void*)
 * Needs to be freed
 */
int get_all_creds_callback(void* data_head, int argc, char **argv,
		char **azColName) {

	struct Credentials_list *head = (struct Credentials_list*) data_head;
	if(!head){
		return 1;
	}
	struct Credentials_list* tmp = (struct Credentials_list*)
					calloc(1,sizeof(struct Credentials_list));
	tmp->next = NULL;
	strcpy(tmp->cred.host, argv[0]);
	strcpy(tmp->cred.username, argv[1]);
	strcpy(tmp->cred.password, argv[2]);
	if(argv[3] != NULL){
		strcpy(tmp->cred.subscription_url, argv[3]);
	}else{
		strcpy(tmp->cred.subscription_url, "");
	}
	if(argv[4] != NULL){
		strcpy(tmp->cred.x_auth_token, argv[4]);
	}else{
		strcpy(tmp->cred.x_auth_token, "");
	}
	if(argv[5] != NULL){
		strcpy(tmp->cred.jsonetag, argv[5]);
	}else{
		strcpy(tmp->cred.jsonetag, "");
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
/**
 * get_all_creds
 * returns: Pointer Credentials_list struct
 * takes: Nothing/void
 * return value needs to be freed by the caller.
 */
struct Credentials_list *get_all_creds(const char* db_path) {

	sqlite3 *db;
	char *err_msg = 0;
	struct Credentials_list cred_head = {{{0}}};
	int rc = sqlite3_open(db_path, &db);

	if (rc != SQLITE_OK) {

		CRIT( "Cannot open database: %s\n",
				sqlite3_errmsg(db));
		sqlite3_close(db);

		return NULL;
	}

	char *sql = "SELECT * FROM credentials";

	rc = sqlite3_exec(db, sql, get_all_creds_callback, &cred_head, 
			&err_msg);

	if (rc != SQLITE_OK ) {

		CRIT( "Failed to select data\n");
		CRIT( "SQL error: %s\n", err_msg);

		sqlite3_free(err_msg);
		sqlite3_close(db);

		return NULL;
	}

	sqlite3_close(db);

	return cred_head.next;
}
/**
 * get_json_registry
 * returns: return number of bytes copied to o_jsonreg buffer
 * takes: a *char for an IP address and void** for sending the 
 * o_jsonreg buffer to caller.
 * Needs to be freed
 */

int get_json_registry(char *input_host, void** o_jsonreg, const char* db_path) {
	sqlite3 *db = NULL;
	int rc = 0;
	char *sql = NULL;
	sqlite3_stmt *pStmt = NULL;

	/* Open Database */
	rc = sqlite3_open(db_path, &db);

	if (rc != SQLITE_OK) {

		CRIT( "Cannot open database: %s\n",
				sqlite3_errmsg(db));
		sqlite3_close(db);
		return 0;
	}
	sql = sqlite3_mprintf("SELECT jsonreg FROM credentials "
			"WHERE host = '%s';", input_host);
	//rc = sqlite3_prepare_v3(db, sql, -1, 0, &pStmt, 0);
	rc = sqlite3_prepare_v2(db, sql, -1, &pStmt, 0);
	if (rc != SQLITE_OK ) {

		CRIT( "Failed to prepare statement\n");
		CRIT( "Cannot open database: %s\n",
				sqlite3_errmsg(db));
		sqlite3_free(sql);
		sqlite3_close(db);

		return 0;
	}
	rc = sqlite3_step(pStmt);

	int bytes = 0;

	if (rc == SQLITE_ROW) {

		bytes = sqlite3_column_bytes(pStmt, 0);
	}
	*o_jsonreg = (void*) malloc(bytes);
	if(!o_jsonreg){
		CRIT( "Failed to allocate enough memory");
		sqlite3_finalize(pStmt);
		sqlite3_free(sql);
		sqlite3_close(db);
		return 0;
	}
	memcpy(*o_jsonreg, sqlite3_column_blob(pStmt, 0), bytes);
	rc = sqlite3_finalize(pStmt);
	sqlite3_close(db);
	sqlite3_free(sql);
	return bytes;
}


/*
 * insert_creds
 * returns: 0 on success 1 on failure
 * takes: struct Credentials pointer
 *
 * */
int insert_creds(struct Credentials* input_creds, const char* db_path){
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
	sql = sqlite3_mprintf("INSERT INTO credentials (host,username,password,"
			"x_auth_token,jsonetag) VALUES "
			"('%s','%s','%s','%s','%s');",
			input_creds->host, input_creds->username,
			input_creds->password, input_creds->x_auth_token,
			input_creds->jsonetag);

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
 * update_creds
 * returns: 0 on success 1 on failure
 * takes: struct Credentials pointer
 *
 * */
int update_creds(struct Credentials* input_creds, const char* db_path){
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
	sql = sqlite3_mprintf("UPDATE credentials set "
			"username = '%s', password = '%s',"
			"x_auth_token = ifnull('%s',x_auth_token),"
			"subscription_url= ifnull('%s',subscription_url),"
			"jsonetag = ifnull('%s', jsonetag)"
			"where host = '%s'; ", input_creds->username,
			input_creds->password,
			input_creds->x_auth_token,
			input_creds->subscription_url,
			input_creds->jsonetag,input_creds->host);
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
	if(!input_creds->jsonreg){
		DBG( "jsonreg input is NULL. That is ok, "
				"returning success for now");
		sqlite3_close(db);
		return 0;
	}
	sql = sqlite3_mprintf("UPDATE credentials SET jsonreg = ? "
			"where host = '%s';", input_creds->host);
	rc = sqlite3_prepare_v2(db, sql, -1, &pstmt, 0);
	if (rc == SQLITE_OK) {
		sqlite3_bind_blob(pstmt, 1, input_creds->jsonreg,
				input_creds->jsonreg_len,
				SQLITE_STATIC);
	}
	int step = sqlite3_step(pstmt);
	if (!(SQLITE_DONE == step || SQLITE_ROW == step)) {
		CRIT( "The DB Update statement failed: %s\n",
				sqlite3_errmsg(db));
		sqlite3_free(sql);
		sqlite3_finalize(pstmt);
		sqlite3_close(db);
		return 1;
	}
	// Clean up DB and close it.
	sqlite3_free(sql);
	sqlite3_finalize(pstmt);
	sqlite3_close(db);
	return 0;
}

/*
 * delete_creds
 * returns: 0 on success 1 on failure
 * takes: char ponter to hostname
 *
 * */
int delete_creds (char *hostname, const char* db_path){
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
	sql = sqlite3_mprintf("DELETE FROM credentials WHERE host = '%s';",
			hostname);

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

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
 * CredentialMgr - Manages Redfish Credentials
 **/

#ifndef CREDENTIALMGR_H
#define CREDENTIALMGR_H

int get_all_creds_callback(void* data_head, int argc, char **argv,
		char **azColName);
struct Credentials_list* get_creds_like(char *input_host,
		const char* db_path);
struct Credentials_list* get_all_creds(const char* db_path);
/**
 * get_creds
 * returns: credentials struct
 * takes: a *char for an IP address and path to database
 * Needs to be freed
 */
struct Credentials *get_creds(char *input_host, const char* db_path);

/**
 * get_event_registry
 * returns: json object representing the event registry
 * takes: a *char for an IP address
 * Needs to be freed
 */

/*
json_t *get_event_regitry(char *input_host);
*/
int get_json_registry(char *input_host, void** o_jsonreg, const char* db_path);

/**
 * get_session_url
 * returns: char *session_url like http://<ip>/v1/SessionService/Sessions/
 * input: char *ip
 */
int update_creds (struct Credentials *input_creds, const char* db_path);
int insert_creds (struct Credentials *input_creds, const char* db_path);
int delete_creds (char *hostname, const char* db_path);
char *get_session_url(char *host);

/**
 * get_session_token
 * This function post a new session
 * returns: char *x-auth-token that can be used
 * input: struct Credentials *mycreds
 * db_path: path to the db
 */

char *get_session_token(struct Credentials *mycreds, const char* db_path);


#endif

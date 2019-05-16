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


#include <stdio.h>
#include <glib.h>
#include <gio/gio.h>
#include <glib/gprintf.h>
#include <string.h>

static gsize build_message_to_send(gchar** buffer, const char* fmt, ...);
/*
struct user_data {
	char action[16];
	char host[16];
	char username[16];
	char password[16];
};
*/
struct user_data {
	gchar* action;
	gchar* host;
	gchar* username;
	gchar* password;
};
struct user_data user_action = {0};

static GOptionEntry entries[] = {
  { "action", 'a', 0, G_OPTION_ARG_STRING, &user_action.action,
	  "Add or remove credentials", NULL },
  { "host", 'h', 0, G_OPTION_ARG_STRING, &user_action.host,
	  "Host name and port of the target to contact to", "host<:port>" },
  { "username", 'u', 0, G_OPTION_ARG_STRING, &user_action.username,
	  "Username for the host", NULL },
  { "password", 'p', 0, G_OPTION_ARG_STRING, &user_action.password,
	  "Password for the host", NULL },
  { NULL }
};
gsize build_message_to_send(gchar** buffer, const gchar* format, ...){
	va_list argp;
	va_start(argp, format);
	gsize bytes = g_vasprintf(buffer, format, argp);
	va_end(argp);
    return bytes;

}
int
main (int argc, char *argv[])
{
	GError * error = NULL;
	GSocketConnection * connection = NULL;
	GOptionContext *context = NULL;
	gchar* buffer = NULL;
	gchar inmsg[256] = {'\0'};
	const gchar* fmt = NULL;
	gsize size = 0;
	context = g_option_context_new(
			"- Enter Credentials to Add/Remove.");
	g_option_context_add_main_entries (context, entries, NULL);

	if (!g_option_context_parse(context, &argc, &argv, &error))
	{
		g_print ("option parsing failed: %s\n", error->message);
		return 1 ;
	}
	if(user_action.action && user_action.host &&
			user_action.username && user_action.password){
		g_print("%s %s %s %s",user_action.action, user_action.host,
				user_action.username, user_action.password);
		fmt = "%s %s %s %s";
		size = build_message_to_send(&buffer, fmt ,user_action.action,
				user_action.host, user_action.username,
				user_action.password);
		g_print("%s", buffer);

	}else{
		g_print("Incorrect arguments, please try again. \n %s",
				g_option_context_get_help(context, TRUE, NULL));
		g_option_context_free(context);
		return 1;
	}
	/* create a new connection */
	GSocketClient * client = g_socket_client_new();

	/* connect to the host */
	connection = g_socket_client_connect_to_host (client,
			(gchar*)"localhost",
			1500, /* your port goes here */
			NULL,
			&error);

	/* don't forget to check for errors */
	if (error != NULL)
	{
		g_error ("%s",error->message);
	}

	GOutputStream * ostream = g_io_stream_get_output_stream (
			G_IO_STREAM (connection));
	GInputStream * istream = g_io_stream_get_input_stream (
			G_IO_STREAM (connection));

	g_output_stream_write  (ostream,
			buffer,
			size, /* length of your message */
			NULL,
			&error);
	/* don't forget to check for errors */
	if (error != NULL)
	{
		g_error ("%s",error->message);
	}
	// Read return value
	g_input_stream_read  (istream,
			inmsg,
			256,
			NULL,
			NULL);
	if (strncmp(inmsg, "OK", 2)) {
		g_print("I got an error back from the server. The error is:\n"
							"%s\n", inmsg);
		g_free(buffer);
		return 1;
	} else {
		g_print("\nSuccess\n");
		g_free(buffer);
		return 0;
	}
}

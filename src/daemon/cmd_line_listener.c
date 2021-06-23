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
 * Author(s)
 * Hemantha Beecherla <hemantha.beecherla@hpe.com>
 *
 **/

#include "rfeventrec.h"
#include "cmd_line_listener.h"
#include "subscriptionmgr.h"
#include "listener.h"

static void signal_handler(int signum);
gboolean call_back(gpointer loop);
struct userdata data = {0};
static gchar* cfgfile = NULL;
static gchar* optpidfile = NULL;
static gchar* event_host = NULL;
static gint event_port = 0;
static gboolean aggregatormode = FALSE;
static gboolean runasforeground = FALSE;
static gboolean daemonize   = FALSE;
static gboolean verbose_flag    = FALSE;
static const char * get_log_level_name(GLogLevelFlags log_level)
{
	if (log_level & G_LOG_LEVEL_ERROR) {
		return "ERR";
	} else if (log_level & G_LOG_LEVEL_CRITICAL) {
		return "CRIT";
	} else if (log_level & G_LOG_LEVEL_WARNING) {
		return "WARN";
	} else if (log_level & G_LOG_LEVEL_MESSAGE) {
		return "MSG";
	} else if (log_level & G_LOG_LEVEL_INFO) {
		return "INFO";
	} else if (log_level & G_LOG_LEVEL_DEBUG) {
		return "DBG";
	}
	return "???";
}
static int get_syslog_level(GLogLevelFlags log_level)
{
	if (log_level & G_LOG_LEVEL_ERROR) {
		return LOG_ERR;
	} else if (log_level & G_LOG_LEVEL_CRITICAL) {
		return LOG_CRIT;
	} else if (log_level & G_LOG_LEVEL_WARNING) {
		return LOG_WARNING;
	} else if (log_level & G_LOG_LEVEL_MESSAGE) {
		return LOG_NOTICE;
	} else if (log_level & G_LOG_LEVEL_INFO) {
		return LOG_INFO;
	} else if (log_level & G_LOG_LEVEL_DEBUG) {
		return LOG_DEBUG;
	}
	return LOG_INFO;
}	

void log_handler(const gchar* log_domain,
		GLogLevelFlags log_level,
		const gchar* message,
		gpointer data /*user data*/){
	if((!verbose_flag) && ((log_level & G_LOG_LEVEL_CRITICAL) == 0)){
		return;
	}
	if(!daemonize){
		printf("%s: %s: %s\n", log_domain,
				get_log_level_name(log_level),
				message);
	}else{
		syslog(LOG_DAEMON | get_syslog_level(log_level),
				"%s: %s\n", log_domain,
				message);
	}

}
gboolean check_pidfile(const char *pidfile)
{
	if (!pidfile) {
		return FALSE;
	}

	int fd = open(pidfile, O_RDONLY);
	if (fd >= 0) {
		char buf[32];
		memset(buf, 0, sizeof(buf));
		ssize_t len = read(fd, buf, sizeof(buf) - 1);
		if (len < 0) {
			CRIT("Cannot read from PID file.");
			return FALSE;
		}
		close(fd);
		int pid = atoi(buf);
		if ((pid > 0) && (pid == getpid() || (kill(pid, 0) < 0))) {
			unlink(pidfile);
		} else {
			CRIT("There is another active fishminder daemon.");
			return FALSE;
		}
	}

	return TRUE;
}
gboolean update_pidfile(const char *pidfile)
{
	// TODO add more checks here
	if (!pidfile) {
		return FALSE;
	}

	int fd = open(pidfile, O_WRONLY|O_CREAT, S_IRUSR|S_IWUSR|S_IRGRP);
	if (fd < 0) {
		CRIT("Cannot open PID file.");
		return FALSE;
	}
	char buf[32];
	snprintf(buf, sizeof(buf), "%d\n", (int)getpid());
	if (-1 == write(fd, buf, strlen(buf))) {
		close(fd);
		return FALSE;
	}
	close(fd);

	return TRUE;
}
static gboolean daemonized(const char *pidfile)
{
	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
		return FALSE;
	}

	pid_t pid;
	pid = fork();
	if (pid < 0) {
		return FALSE;
	} else if (pid > 0) {
		exit(0);
	}
	setsid();
	pid = fork();
	if (pid < 0) {
		return FALSE;
	} else if (pid > 0) {
		exit(0);
	}
	daemonize = TRUE;

	if (FALSE == update_pidfile(pidfile)) {
		return FALSE;
	}
#ifndef _WIN32
	mode_t prev_umask = umask(022); // Reset default file permissions

	if ( prev_umask != 022 ) {
		WARN("Using umask 0%o instead of 022(default)",prev_umask);
		umask(prev_umask);
	}
#endif
	// Close unneeded inherited file descriptors
	//     // Keep stdout and stderr open if they already are.
	//
#ifdef NR_OPEN
	for (int i = 3; i < NR_OPEN; i++) {
#else
		for (int i = 3; i < 1024; i++) {
#endif
			close(i);
		}

		return TRUE;

}

/* this function will get called everytime a client attempts to connect */
gboolean
incoming_callback  (GSocketService *service,
                    GSocketConnection *connection,
                    GObject *source_object,
                    gpointer user_data)
{
	//char action[16], host[256], username[256], password[256];
	char subs_type[256]={'\0'}, action[16]={'\0'}, host[256]={'\0'}, username[256]={'\0'},
	     password[256]={'\0'};
	char *action_ret = NULL;
	GError *error = NULL;

	DBG("Received Connection from client!\n");
	GInputStream * istream = g_io_stream_get_input_stream (
			G_IO_STREAM (connection));
	GOutputStream * ostream = g_io_stream_get_output_stream (
						G_IO_STREAM (connection));
	gchar message[1024] = {'\0'};
	gsize size = g_input_stream_read  (istream,
			message,
			1024,
			NULL,
			NULL);
	message[size] = '\0';
	sscanf(message, "%s %s %s %s %s ", subs_type, action, host, username, password);
	memset(message, '\0' ,size);
	DBG(" %s \n %s \n %s \n %s \n %s", subs_type, action, host, username, password);
	//	DBG("Message was: \"%s\"\n", message);
	g_mutex_lock(data.ulfius_lock);
	action_ret = fminder_action(subs_type, action, host, username, password, data.aggregationmode);
	g_mutex_unlock(data.ulfius_lock);
	if (action_ret != NULL) {
		// We have a problem need to send back the action_ret char
		// to the client
		g_output_stream_write  (ostream,
					action_ret,
					strlen(action_ret),
					NULL,
					&error);
	} else {
		g_output_stream_write  (ostream,
					"OK",
					2,
					NULL,
					&error);
	}
	free(action_ret);
	return FALSE;
}

void signal_handler(int signum)
{
	g_mutex_lock(data.mutex_lock);
	g_cond_signal(&data.data_flag);
	data.shutdown = TRUE;
	g_mutex_unlock(data.mutex_lock);
	return;
}

static GOptionEntry entries[] = {
	{ "cfg", 'c', 0, G_OPTION_ARG_FILENAME, &cfgfile,
		"Sets path/name of the configuraton file.\n"
	"                                 This option is required unless the environment\n"
	"                                 variable RFEVENTREC_CONF has been set to a valid\n"
	"                                 configuraton file.", "conf_file" },
	{ "hostname", 'h', 0, G_OPTION_ARG_STRING, &event_host,
		"Hostname to listen for events", "IP/Hostname" },
	{ "port", 'p', 0, G_OPTION_ARG_INT, &event_port,
		"Port number to listen for events", "Port number" },
	{ "aggregatormode", 'a', 0, G_OPTION_ARG_NONE, &aggregatormode,
		"If this flag provided, then fishminder can talk with\n"
	"                                 targets like iLO Aggregators.", NULL},
	{ "pidfile", 'f', 0, G_OPTION_ARG_FILENAME, &optpidfile,
	"Overrides the default path/name for the daemon pid file.\n"
	"                                 The option is optional.", "pidfile" },
	{ "verbose",   'v', 0, G_OPTION_ARG_NONE,     &verbose_flag,  
		"This option causes the daemon to display verbose\n"
		"                                 messages. This option is optional.",
		NULL },
	{ "nondaemon", 'n', 0, G_OPTION_ARG_NONE,   &runasforeground, 
	"Forces the code to run as a foreground process\n"
	"                                 and NOT as a daemon. The default is to run as\n"
	"                                 a daemon. The option is optional.",
		NULL },
	{ NULL }
};

int
main (int argc, char **argv)
{
	config_t cfg;
	const char* pidfile = NULL, *db_path = NULL, *key_path = NULL;
	const char* ilo_log_path = NULL, *write_to_file = NULL, *telemetry_log_path = NULL, *enable_telemetry = NULL;
	const char *cert_path = NULL;
        const char* user = NULL;
	GThread* subscription_thread_id = NULL;
	GThread* listener_thread_id = NULL;
	GMainContext* context = NULL;
	GError * error = NULL;
	GOptionContext *option_ctxt = NULL;
	config_init(&cfg);
	g_log_set_default_handler(log_handler, 0);
	option_ctxt = g_option_context_new(
			"- Enter the Hostname & Port number to listen for events.\n"
			"A typical invocation might be\n"
			"./fishminderd -c /ect/fishminderd/fishminderd.conf");
	g_option_context_add_main_entries (option_ctxt, entries, NULL);

	if (!g_option_context_parse(option_ctxt, &argc, &argv, &error))
	{
		CRIT ("option parsing failed: %s\n", error->message);
		return 1 ;
	}
	if(cfgfile){
		setenv("RFEVENTREC_CONF", cfgfile, 1);
	} else {
		cfgfile = getenv("RFEVENTREC_CONF");
	}
	if(event_host && event_port){
		DESTINATION =(char* ) g_strdup(event_host);
		LPORT=event_port;
		g_free(event_host);
	}else{
		CRIT("Incorrect arguments, please try again. \n%s",
				g_option_context_get_help (option_ctxt,
				TRUE, NULL));
		g_option_context_free(option_ctxt);
		return 1;
	}
	if((!cfgfile) || (!g_file_test(cfgfile, G_FILE_TEST_EXISTS))){
		CRIT("Cannot find configuration file %s. Existing.\n%s",
				cfgfile, g_option_context_get_help(option_ctxt,
					TRUE, NULL));
		g_option_context_free(option_ctxt);
		return 1;
	}
	if(!config_read_file(&cfg, cfgfile)){
		CRIT("\n%s:%d - %s", config_error_file(&cfg),
				config_error_line(&cfg),
				config_error_text(&cfg));
		config_destroy(&cfg);
		return 1;
	}
	if(optpidfile){
		pidfile = optpidfile;
	}else {
		if(!config_lookup_string(&cfg, "PID_FILE_PATH", &pidfile)){
			CRIT("PID_FILE_PATH not found in configuration file.");
			return 1;
		}
	}
	if(!config_lookup_string(&cfg, "DB_PATH", &db_path)){
		CRIT("DB_PATH not found in configuration file.");
		return 1;
	}
	strcpy(DB_PATH, db_path);

	if(!config_lookup_string(&cfg, "KEY_PATH", &key_path)){
		CRIT("KEY_PATH not found in configuration file.");
		return 1;
	}
	strcpy(data.key_path, key_path);

	if(!config_lookup_string(&cfg, "CERT_PATH", &cert_path)){
		CRIT("CERT_PATH not found in configuration file.");
		return 1;
	}
	strcpy(data.cert_path, cert_path);

	if(!config_lookup_string(&cfg, "ILO_LOG_FILE_PATH", &ilo_log_path)){
		CRIT("ILO_LOG_FILE_PATH not found in configuration file.");
		return 1;
	}
	strcpy(ILO_LOG_PATH, ilo_log_path);

	if(!config_lookup_string(&cfg, "DUMP_EVENTS_TO_FILE", &write_to_file)){
		CRIT("DUMP_EVENTS_TO_FILE not found in configuration file.");
		return 1;
	}
	if (strcmp(write_to_file, "TRUE") == 0) {
		IS_EVENT_WRITE_FILE = true;
	} else 
		IS_EVENT_WRITE_FILE = false;

	if(!config_lookup_string(&cfg, "METRICS_LOG_FILE_PATH", &telemetry_log_path)){
                CRIT("METRICS_LOG_FILE_PATH not found in configuration file.");
                return 1;
        }
        strcpy(METRICS_LOG_FILE_PATH, telemetry_log_path);

	if(!config_lookup_string(&cfg, "ENABLE_METRICS_SUBSCRIPTION", &enable_telemetry)){
		CRIT("ENABLE_METRICS_SUBSCRIPTION not found in configuration file.");
		return 1;
	}
	if (strcmp(enable_telemetry, "TRUE") == 0) {
		ENABLE_METRICS_SUBSCRIPTION = true;
	} else 
		ENABLE_METRICS_SUBSCRIPTION = false;

	if(!check_pidfile(pidfile)){
		CRIT("PID file check failed. Exiting.");
		CRIT(" Please try again. \n%s",
				g_option_context_get_help (option_ctxt,
				TRUE, NULL));
		exit(1);
	}
	if (!update_pidfile(pidfile)) {
		CRIT("Cannot update PID file. Exiting.");
		CRIT(" Please try again. \n%s",
				g_option_context_get_help (option_ctxt,
				TRUE, NULL));
		exit(1);
	}
	g_option_context_free(option_ctxt);

	if(signal(SIGTERM, signal_handler) == SIG_ERR){
		printf("Cannot set SIGTERM handler. Exiting");
		exit(1);
	}
	if(signal(SIGINT, signal_handler) == SIG_ERR){
		printf("Cannot set SIGINT handler. Exiting");
		exit(1);
	}
	data.aggregationmode = aggregatormode;
	if (!runasforeground) {
		if (!daemonized(pidfile)) {
			exit(8);
		}
	}
	/*Initialize the Mutex lock */
	data.mutex_lock = (GMutex*)g_malloc0(sizeof(GMutex));
	g_mutex_init(data.mutex_lock);
	data.ulfius_lock = (GMutex*)g_malloc0(sizeof(GMutex));
	g_mutex_init(data.ulfius_lock);
	data.shutdown = FALSE;
	context = g_main_context_default();

	/* create the new socketservice */
	GSocketService * service = g_socket_service_new ();

	/* connect to the port */
	g_socket_listener_add_inet_port ((GSocketListener*)service,
			1500, /* your port goes here */
			NULL,
			&error);

	/* don't forget to check for errors */
	if (error != NULL)
	{
		g_error ("%s",error->message);
	}

	subscription_thread_id = g_thread_new("subscription_mgr_thread",
			subscription_mgr_thread, (gpointer) &data);
	//Jonas Please pass data to listener thread, as per your requirements.
	listener_thread_id = g_thread_new("listener", listener,
			(gpointer) &data);
	/* listen to the 'incoming' signal */
	g_signal_connect (service,
			"incoming",
			G_CALLBACK (incoming_callback),
			NULL);

	/* start the socket service */
	g_socket_service_start (service);

	/* enter mainloop */
	INFO("Waiting for client!\n");
	while(!data.shutdown){
		g_main_context_iteration(context, FALSE);
		sleep(1);
	}
	g_main_context_wakeup(NULL);
	g_socket_service_stop(service);
	g_thread_join(subscription_thread_id);
	g_thread_join(listener_thread_id);
	g_mutex_clear(data.mutex_lock);
	g_socket_listener_close((GSocketListener*)service);
	config_destroy(&cfg);
	return 0;
}

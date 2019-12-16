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
 *      Jonas Arndt <jonas.arndt@hpe.com>
 *	Hemantha Beecherla <hemantha.beecherla@hpe.com>
 **/

#ifndef RFEVENTREC_H
#define RFEVENTREC_H

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <stdio.h>
#include <pthread.h>
#include <zlib.h>
#include <time.h>
#include <fcntl.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/types.h>


#include <string.h>
#include <stdlib.h>
#include <jansson.h>
#include <sqlite3.h>
#include <ulfius.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <libconfig.h>

#include <glib.h>
#include <gio/gio.h>

#define REDFISHROOT "/redfish/v1/"
#define URLSSL "https://"

#define REDFISH_DBG_MSGS
#ifdef REDFISH_DBG_MSGS

#define CRIT( fmt, ... ) \
            g_critical( "%s:%d: " fmt, __FILE__, __LINE__,## __VA_ARGS__ )

#define WARN( fmt, ... ) \
            g_warning( "%s:%d: " fmt, __FILE__, __LINE__,## __VA_ARGS__ )

#define MSG( fmt, ... ) \
            g_message( "%s:%d: " fmt, __FILE__, __LINE__,## __VA_ARGS__ )

#define INFO( fmt, ... ) \
            g_log (G_LOG_DOMAIN, G_LOG_LEVEL_INFO, \
                                       "%s:%d: " fmt, __FILE__, __LINE__,## __VA_ARGS__ )

#define DBG( fmt, ... ) \
            g_debug( "%s:%d: " fmt, __FILE__, __LINE__,## __VA_ARGS__ )


/******************************************************************
 *   Use CRIT, WARN, DBG macros intead of legacy err, warn, dbg
 *******************************************************************/
#define err( fmt, ... ) \
            g_critical( "%s:%d: " fmt, __FILE__, __LINE__,## __VA_ARGS__ )

#define warn( fmt, ... ) \
            g_warning( "%s:%d: " fmt, __FILE__, __LINE__,## __VA_ARGS__ )
#define dbg( fmt, ... ) \
            g_debug( "%s:%d: " fmt, __FILE__, __LINE__,## __VA_ARGS__ )

#else /* REDFISH_DBG_MSGS */

#define CRIT( fmt, ... )
#define WARN( fmt, ... )
#define MSG( fmt, ... )
#define INFO( fmt, ... )
#define DBG( fmt, ... )

#define err( fmt, ... )
#define warn( fmt, ... )
#define dbg( fmt, ... )

#endif /* REDFISH_DBG_MSGS */

struct Events {
        char host[256];
        char severity[64];
        char message[256];
        char resolution[256];
        int time;
        int isclearmessage;
        char originofcondition[256];
	char target_uuid[256];
        char messageid[256];
        char category[64];
};

char DB_PATH[256]; // Global variable for DB_PATH
char CERT_PATH[256]; // Global variable for CERT_PATH
char KEY_PATH[256]; // Global variable for KEY_PATH
char *DESTINATION; // Global variable for event destination
int LPORT; // Global variable for event port

struct userdata {
        GMutex *mutex_lock;
        GMutex *ulfius_lock;
        char action[16];
        char host[256];
        char username[256];
        char password[256];
	char db_path[256];
	char cert_path[256];
	char key_path[256];
	char user[16];
        char *destination;
        int port;
        GCond data_flag;
        gboolean shutdown;
	gboolean aggregationmode;

};

struct Credentials {
        char host[256];
        char username[256];
        char password[256];
        char x_auth_token[256];
        char subscription_url[256];
        char etag[32];
        char jsonetag[32];
        void *jsonreg;
        int jsonreg_len;
};

struct Credentials_list {
        struct Credentials cred;
        struct Credentials_list* next;
};


#define ASPRINTF(...)              \
    if (asprintf( __VA_ARGS__ ) == -1) {  \
        fprintf(stderr,"Faild to allocate memory, %s",strerror(errno));\
        abort();        \
    }


#endif

char *fminder_action(char * action, char *host, char *username, char
			*password);

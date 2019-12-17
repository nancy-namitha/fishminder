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

#ifndef _SUBSCRIPTIONMGR_H_
#define _SUBSCRIPTIONMGR_H_

char* get_event_service_subscription_uri(struct Credentials *cred);
gboolean is_this_my_subscription(struct Credentials* cred, char *sub_url, char* destination);
char *subscribe(struct Credentials* cred, char* destination, int port,
		const char* db_path, gboolean aggregatormode);
char *unsubscribe(char* host, const char* db_path);
gboolean check_subscription_status(struct Credentials* cred, char* destination,
		const char* db_path);
/* Pass global data to this thread as input arguments*/
void* subscription_mgr_thread(void* data);

#define REDFISH_ACCEPT \
        ("Accept: application/json")
#define REDFISH_ACCEPT_LANGUAGE \
        ("Accept-Language: en_US")
#define REDFISH_CONTENT_TYPE \
        "Content-Type: application/json"
#define REDFISH_AUTH \
        "Auth: %s"
#define REDFISH_ETAG \
        "If-None-Match: %s"
#define REDFISH_ROOT_URI \
	"https://%s/redfish/v1/"
#define REDFISH_LOGIN_URI \
        "https://%s/redfish/v1/SessionService/Sessions/"
#define _REDFISH_SUBSCRIPTION_URI \
        "https://%s/redfish/v1/EventService/EventSubscriptions/"
#define REDFISH_SUBSCRIPTION_ID_URI \
        "https://%s/redfish/v1/EventService/EventSubscriptions/%s/"
#define REDFISH_LOGIN_POST \
        "{\"UserName\":\"%s\", \"Password\":\"%s\"}"
#define REDFISH_LOGIN_POST_MASK \
        "{\"UserName\":\"%s\", \"Password\":\"%s\", \"loginMsgAck\":\"%s\"}"
#define REDFISH_SUBSCRIPTION_POST \
        "{\"Destination\": \"https://%s:%d/redfish/v1/EventService/Subscriptions\",\
    \"EventTypes\": [ \
        \"Alert\" ], \
    \"HttpHeaders\": {\"Content-Type\": \"application/json\"}, \
    \"Context\": \"Public\", \
    \"Oem\": { \
        \"Hpe\": { \
            \"DeliveryRetryIntervalInSeconds\": 30, \
            \"RequestedMaxEventsToQueue\": 20, \
            \"DeliveryRetryAttempts\": 5, \
            \"RetireOldEventInMinutes\": 10 \
        } \
    } \
}"

#define REDFISH_AGGREGATOR_SUBSCRIPTION_POST \
        "{\"Destination\": \"https://%s:%d/redfish/v1/EventService/Subscriptions\",\
    \"EventTypes\": [ \
        \"Alert\" ], \
    \"HttpHeaders\": {\"Content-Type\": \"application/json\"}, \
    \"Context\": \"Public\", \
    \"Protocol\": \"Redfish\", \
    \"SubordinateResources\": true, \
	  \"OriginResources\": [\"/redfish/v1/Systems\"], \
    \"Oem\": { \
        \"Hpe\": { \
            \"DeliveryRetryIntervalInSeconds\": 30, \
            \"RequestedMaxEventsToQueue\": 20, \
            \"DeliveryRetryAttempts\": 5, \
            \"RetireOldEventInMinutes\": 10 \
        } \
    } \
}"

#endif

# Fishminder Redfish Event Receiver
## Introduction
This project provides a daemon that can be used to retrieve events from a Redfish Event Service. The [DMTF Redfish](https://www.dmtf.org/standards/redfish) standard defines a service that a client can post subscription requests to. Such request would outline what type of events the client is interested in. In the Fishminder project we only subscribe to events of the type Alert. The client would also need to tell the Event Service where to send the events. The Event Service sends events to the clients through a RESTful POST operation. Therefore the Fishminder daemon is hosting a REST server that can accept such events and places them in a Sqlite database (the table name is "events").
## Architecture
The daemon service is called fishminderd and is using a configuration file that can be supplied by -c parameter. The config file can take a few parameters (see configuration file section below)
The daemon can manage subscriptions to the Event Service of different servers. One manage the subscriptions by using the client program fminder. For instance, to add a subscription to a server startgazer-ilo one could use the fminder client and issue
```
$ fminder -a add -h stargazer-ilo.telco.us.rdlabs.hpecorp.net:443 -u username -p password
```
For more information on the fminder utility see the fminder section below.
When a subscription has been set up the daemon will accept Redfish events from that server and put them in an Sqlite database. The database location is specified in the configuration file (see DB_PATH).

Other programs can then consume this database as seen fit. One such program is a Nagios plugin for Redfish that uses the database to look for alarms

**Arch overview**
![Alt text](fishminder_arch.jpg?raw=true "Architecture") ## Configuration File
You can tell the daemon where to look for the configuration file by add -c to the fishminderd binary when starting it, like:
```
$ sudo fishminder -c /etc/fishminder/fishminderd.conf -h myhostname.mydomain.ex -p 8080
```
The configuration file currently takes the following parameters
```
PID_FILE_PATH = "/var/run/fishminderd/fishminderd.pid"
CERT_PATH = "/etc/fishminder/certs/cert.pem"
KEY_PATH = "/etc/fishminder/certs/private/server.key"
DB_PATH = "/etc/fishminder/fishminder.db"
```

An example configuration file is included in the project (see fishminderd.conf)

## Certificates
The daemon supports certificates using the ulfius framework. You can generate SSL certificate and place them in the CERT_PATH directory. Set the parameters accordingly. It is highly adviced to place the private key file in a directory where only the user running the daemon has access

## Daemon options
```
  -c, --cfg=conf_file
				Sets path/name of the configuraton file.
				This option is required unless the environment
				variable RFEVENTREC_CONF has been set to a valid
				configuraton file.

  -h, --hostname=IP/Hostname
				Hostname to listen for events

  -p, --port=Port number
				Port number to listen for events

  -f, --pidfile=pidfile
				Overrides the default path/name for the daemon pid file.
				The option is optional.

  -v, --verbose
				This option causes the daemon to display verbose
				messages. This option is optional.

  -n, --nondaemon
				Forces the code to run as a foreground process
				and NOT as a daemon. The default is to run as
				a daemon. The option is optional.
```
## Installation
1. Run bootsrap.sh, configure, make
2. Create a user that will run the deamon (e.g. drumfish)
```
$ sudo useradd -m -d /home/fishminder fishminder
$ sudo passwd fishminder
```
3. Install
```
$ sudo make install
```
4. Generate and place your cert files in /etc/fishminder/certs and /etc/fishminder/certs/private (the key goes here). It is advisable to keep the private key with 700 permission
5. Edit your configuration file accordingly
6. Set permissions
```
$ sudo chown fishminder:fishminder /var/run/fishminderd
$ sudo chown -R fishminder:fishminder /etc/fishminder/
$ sudo chmod 700 -R /etc/fishminder/certs/private
```
7. Start fishminder with the IP and the port it should listen to (example below):
```
$ sudo -u fishminder fishminderd -c /etc/fishminder/fishminderd.conf -h 10.8.7.55 -p 8080
```
8. Add a subscription for a server using fminder (example below):
```
$ fminder -a add -h someserver-ilo.telco.us.rdlabs.hpecorp.net:443 -u username -p password
```

## Note
While most of the code is written in a way that should be applicable to any equipment that is Redfish compliant, some of it is looking at specific iLO OEM resources. Specifically we look at Oem:Hpe:ClearingLogic in order to decide what events need to be deleted for a clearing event. Our suggestion is that this code is moved into a specific plugin and allow for other plugins from different vendors.

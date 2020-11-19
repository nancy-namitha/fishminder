AUTOMAKE_OPTIONS = foreign subdir-objects

dist_doc_DATA = README.md

bin_PROGRAMS = fishminderd fminder
fishminderd_CFLAGS = $(GLIB_CFLAGS) $(GIO_CFLAGS) $(LIBCONFIG_CFLAGS)
fishminderd_LDADD = $(GLIB_LIBS) $(GIO_LIBS) $(LIBCONFIG_LIBS)
fishminderd_SOURCES = src/daemon/cmd_line_listener.c src/daemon/credentialmgr.c src/daemon/listener.c src/daemon/subscriptionmgr.c
nodist_fishminderd_SOURCES = fishminder.db
BUILT_SOURCES = fishminder.db
CLEANFILES = sqlite/fishminder.db
fishminder.db: Makefile
	if [ ! -f sqlite/fishminder.db ]; then sqlite3 sqlite/fishminder.db < sqlite/sqlite_schema.sql; fi

confdir = $(sysconfdir)/fishminder
certdir = $(sysconfdir)/fishminder/certs
privdir = $(sysconfdir)/fishminder/certs/private
elogdir =  $(localstatedir)/log/fishminderd
dist_conf_DATA = fishminderd.conf sqlite/fishminder.db

fminder_CFLAGS = $(GLIB_CFLAGS) $(GIO_CFLAGS)
fminder_LDADD = $(GLIB_LIBS) $(GIO_LIBS)
fminder_SOURCES = src/utils/client.c

man1_MANS = doc/man1/fminder.1
man8_MANS = doc/man8/fishminderd.8


install-data-hook: gen-config

.PHONY: gen-config
gen-config:
	echo "PID_FILE_PATH = \"$(runstatedir)/fishminderd/fishminderd.pid\"" >> $(confdir)/fishminderd.conf
	echo "CERT_PATH = \"$(certdir)/cert.pem\"" >> $(confdir)/fishminderd.conf
	echo "KEY_PATH = \"$(privdir)/server.key\"" >> $(confdir)/fishminderd.conf
	echo "DB_PATH = \"$(confdir)/fishminder.db\"" >> $(confdir)/fishminderd.conf
	echo "DUMP_EVENTS_TO_FILE = \"TRUE\"" >> $(confdir)/fishminderd.conf
	echo "ILO_LOG_FILE_PATH = \"$(elogdir)/ilo_redfish_event.log\"" >> $(confdir)/fishminderd.conf

install-exec-hook:
	-mkdir -p $(confdir)
	-mkdir -p $(certdir)
	-mkdir -p $(privdir)
	-mkdir -p $(runstatedir)/fishminderd
	-mkdir -p $(elogdir)

uninstall-hook:
	-rmdir $(privdir)
	-rmdir $(certdir)
	-rmdir $(confdir)
	-rmdir $(runstatedir)/fishminderd
	-rmdir -p $(elogdir)

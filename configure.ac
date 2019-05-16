#
# (C) Copyright 2019 Hewlett Packard Enterprise Development LP
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.


AC_PREREQ([2.69])
AC_INIT([rfeventsub], [0.1])
#AC_CONFIG_SRCDIR([src/listener/listener.c])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE

# Checks for programs.
AC_PROG_CC
AC_GNU_SOURCE
AC_PROG_INSTALL

# Checks for libraries.
AC_CHECK_LIB([glib-2.0], [g_mutex_init], [], [
	echo "The glib library was not located and is required for this program"
        exit -1])
AC_CHECK_LIB([jansson], [json_dumps], [], [
	echo "The jansson library was not located and is required for this program"
        exit -1])
AC_CHECK_LIB([m], [powf], [], [
	echo "The math library was not located and is required for this program"
        exit -1])
AC_CHECK_LIB([orcania], [o_strncmp], [], [
	echo "The orcania library was not located and is required for this program"
        exit -1])
AC_CHECK_LIB([pthread], [pthread_create], [], [
	echo "The orcania library was not located and is required for this program"
        exit -1])
AC_CHECK_LIB([sqlite3], [sqlite3_open], [], [
	echo "The sqlite3 library was not located and is required for this program"
        exit -1])
AC_CHECK_LIB([ulfius], [ulfius_init_instance], [], [
	echo "The ulfius library was not located and is required for this program"
        exit -1])
AC_CHECK_LIB([yder], [y_init_logs], [], [
	echo "The yder library was not located and is required for this program"
        exit -1])
AC_CHECK_LIB([z], [deflate], [], [
	echo "The zlib library was not located and is required for this program"
        exit -1])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h stdlib.h string.h sys/socket.h syslog.h glib.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_MODE_T
AC_TYPE_PID_T
AC_TYPE_SSIZE_T


PKG_CHECK_MODULES([GLIB], [glib-2.0])
PKG_CHECK_MODULES([GIO], [gio-2.0])
PKG_CHECK_MODULES([LIBCONFIG], [libconfig >= 1.4],,
        AC_MSG_ERROR([libconfig 1.4 or newer not found.]))

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_CHECK_FUNCS([gethostbyname inet_ntoa memset strcasecmp strchr strdup strstr])

AC_CONFIG_FILES([Makefile])

AC_OUTPUT

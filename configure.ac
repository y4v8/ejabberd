#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.53)
AC_INIT(ejabberd, 17.08, ejabberd@process-one.net, ejabberd)
REQUIRE_ERLANG_MIN="6.4 (Erlang/OTP 17.5)"
REQUIRE_ERLANG_MAX="100.0.0 (No Max)"

AC_CONFIG_MACRO_DIR([m4])

# Checks for programs.
AC_PROG_MAKE_SET
AC_PROG_INSTALL
AC_PROG_SED

if test "x$GCC" = "xyes"; then
    CFLAGS="$CFLAGS -Wall"
fi

# Checks Erlang runtime and compiler
AC_ARG_WITH(erlang,
	AC_HELP_STRING([--with-erlang=dir],
		[search for erlang in dir]),
[if test "$withval" = "yes" -o "$withval" = "no" -o "X$with_erlang" = "X"; then
    extra_erl_path=""
else
    extra_erl_path="$with_erlang:$with_erlang/bin:"
fi
])

AC_PATH_TOOL(ERL, erl, , [${extra_erl_path}$PATH])
AC_PATH_TOOL(ERLC, erlc, , [${extra_erl_path}$PATH])
AC_PATH_TOOL(EPMD, epmd, , [${extra_erl_path}$PATH])

AC_ERLANG_NEED_ERL
AC_ERLANG_NEED_ERLC

AC_ARG_ENABLE(erlang-version-check,
[AC_HELP_STRING([--enable-erlang-version-check],
	[Check Erlang/OTP version @<:@default=yes@:>@])])
case "$enable_erlang_version_check" in
	yes|'')
		ERLANG_VERSION_CHECK([$REQUIRE_ERLANG_MIN],[$REQUIRE_ERLANG_MAX])
		;;
	no)
		ERLANG_VERSION_CHECK([$REQUIRE_ERLANG_MIN],[$REQUIRE_ERLANG_MAX],[warn])
		;;
esac

# Checks and sets ERLANG_ROOT_DIR and ERLANG_LIB_DIR variable
AC_ERLANG_SUBST_ROOT_DIR
# AC_ERLANG_SUBST_LIB_DIR

#locating escript
AC_PATH_PROG([ESCRIPT], [escript], [], [$ERLANG_ROOT_DIR/bin])

#locating make
AC_CHECK_PROG([MAKE], [make], [make], [])

if test "x$ESCRIPT" = "x"; then
   AC_MSG_ERROR(['escript' was not found])
fi

if test "x$MAKE" = "x"; then
   AC_MSG_ERROR(['make' was not found])
fi

# Change default prefix
AC_PREFIX_DEFAULT(/usr/local)

AC_ARG_ENABLE(hipe,
[AC_HELP_STRING([--enable-hipe], [compile natively with HiPE, not recommended (default: no)])],
[case "${enableval}" in
  yes) hipe=true ;;
  no)  hipe=false ;;
  *) AC_MSG_ERROR(bad value ${enableval} for --enable-hipe) ;;
esac],[hipe=false])

AC_ARG_ENABLE(roster_gateway_workaround,
[AC_HELP_STRING([--enable-roster-gateway-workaround], [turn on workaround for processing gateway subscriptions (default: no)])],
[case "${enableval}" in
  yes) roster_gateway_workaround=true ;;
  no)  roster_gateway_workaround=false ;;
  *) AC_MSG_ERROR(bad value ${enableval} for --enable-roster-gateway-workaround) ;;
esac],[roster_gateway_workaround=false])

AC_ARG_ENABLE(full_xml,
[AC_HELP_STRING([--enable-full-xml], [use XML features in XMPP stream (ex: CDATA) (default: no, requires XML compliant clients)])],
[case "${enableval}" in
  yes) full_xml=true ;;
  no)  full_xml=false ;;
  *) AC_MSG_ERROR(bad value ${enableval} for --enable-full-xml) ;;
esac],[full_xml=false])

AC_ARG_ENABLE(mssql,
[AC_HELP_STRING([--enable-mssql], [use Microsoft SQL Server database (default: no, requires --enable-odbc)])],
[case "${enableval}" in
  yes) db_type=mssql ;;
  no)  db_type=generic ;;
  *) AC_MSG_ERROR(bad value ${enableval} for --enable-mssql) ;;
esac],[db_type=generic])

AC_ARG_ENABLE(all,
[AC_HELP_STRING([--enable-all], [same as --enable-odbc --enable-mysql --enable-pgsql --enable-sqlite --enable-pam --enable-zlib --enable-riak --enable-redis --enable-elixir --enable-esmb --enable-iconv --enable-stun --enable-sip --enable-debug --enable-tools (useful for Dialyzer checks, default: no)])],
[case "${enableval}" in
  yes) odbc=true mysql=true pgsql=true sqlite=true pam=true zlib=true riak=true redis=true elixir=true esmb=true iconv=true stun=true sip=true debug=true tools=true ;;
  no) odbc=false mysql=false pgsql=false sqlite=false pam=false zlib=false riak=false redis=false elixir=false esmb=true iconv=false stun=false sip=false debug=false tools=false ;;
  *) AC_MSG_ERROR(bad value ${enableval} for --enable-all) ;;
esac],[])

AC_ARG_ENABLE(tools,
[AC_HELP_STRING([--enable-tools], [build development tools (default: no)])],
[case "${enableval}" in
  yes) tools=true ;;
  no)  tools=false ;;
  *) AC_MSG_ERROR(bad value ${enableval} for --enable-tools) ;;
esac],[if test "x$tools" = "x"; then tools=false; fi])

AC_ARG_ENABLE(odbc,
[AC_HELP_STRING([--enable-odbc], [enable pure ODBC support (default: no)])],
[case "${enableval}" in
  yes) odbc=true ;;
  no)  odbc=false ;;
  *) AC_MSG_ERROR(bad value ${enableval} for --enable-odbc) ;;
esac],[if test "x$odbc" = "x"; then odbc=false; fi])

AC_ARG_ENABLE(mysql,
[AC_HELP_STRING([--enable-mysql], [enable MySQL support (default: no)])],
[case "${enableval}" in
  yes) mysql=true ;;
  no)  mysql=false ;;
  *) AC_MSG_ERROR(bad value ${enableval} for --enable-mysql) ;;
esac],[if test "x$mysql" = "x"; then mysql=false; fi])

AC_ARG_ENABLE(pgsql,
[AC_HELP_STRING([--enable-pgsql], [enable PostgreSQL support (default: no)])],
[case "${enableval}" in
  yes) pgsql=true ;;
  no)  pgsql=false ;;
  *) AC_MSG_ERROR(bad value ${enableval} for --enable-pgsql) ;;
esac],[if test "x$pgsql" = "x"; then pgsql=false; fi])

AC_ARG_ENABLE(sqlite,
[AC_HELP_STRING([--enable-sqlite], [enable SQLite support (default: no)])],
[case "${enableval}" in
  yes) sqlite=true ;;
  no)  sqlite=false ;;
  *) AC_MSG_ERROR(bad value ${enableval} for --enable-sqlite) ;;
esac],[if test "x$sqlite" = "x"; then sqlite=false; fi])

AC_ARG_ENABLE(pam,
[AC_HELP_STRING([--enable-pam], [enable PAM support (default: no)])],
[case "${enableval}" in
  yes) pam=true ;;
  no)  pam=false ;;
  *) AC_MSG_ERROR(bad value ${enableval} for --enable-pam) ;;
esac],[if test "x$pam" = "x"; then pam=false; fi])

AC_ARG_ENABLE(zlib,
[AC_HELP_STRING([--enable-zlib], [enable Stream Compression (XEP-0138) using zlib (default: yes)])],
[case "${enableval}" in
  yes) zlib=true ;;
  no)  zlib=false ;;
  *) AC_MSG_ERROR(bad value ${enableval} for --enable-zlib) ;;
esac],[if test "x$zlib" = "x"; then zlib=true; fi])

AC_ARG_ENABLE(riak,
[AC_HELP_STRING([--enable-riak], [enable Riak support (default: no)])],
[case "${enableval}" in
  yes) riak=true ;;
  no)  riak=false ;;
  *) AC_MSG_ERROR(bad value ${enableval} for --enable-riak) ;;
esac],[if test "x$riak" = "x"; then riak=false; fi])

AC_ARG_ENABLE(redis,
[AC_HELP_STRING([--enable-redis], [enable Redis support (default: no)])],
[case "${enableval}" in
  yes) redis=true ;;
  no)  redis=false ;;
  *) AC_MSG_ERROR(bad value ${enableval} for --enable-redis) ;;
esac],[if test "x$redis" = "x"; then redis=false; fi])

AC_ARG_ENABLE(elixir,
[AC_HELP_STRING([--enable-elixir], [enable Elixir support (default: no)])],
[case "${enableval}" in
  yes) elixir=true ;;
  no)  elixir=false ;;
  *) AC_MSG_ERROR(bad value ${enableval} for --enable-elixir) ;;
esac],[if test "x$elixir" = "x"; then elixir=false; fi])

AC_ARG_ENABLE(esmb,
[AC_HELP_STRING([--enable-esmb], [enable esmb support (default: yes)])],
[case "${enableval}" in
  yes) esmb=true ;;
  no)  esmb=false ;;
  *) AC_MSG_ERROR(bad value ${enableval} for --enable-esmb) ;;
esac],[if test "x$esmb" = "x"; then esmb=true; fi])

AC_ARG_ENABLE(iconv,
[AC_HELP_STRING([--enable-iconv], [enable iconv support (default: yes)])],
[case "${enableval}" in
  yes) iconv=true ;;
  no)  iconv=false ;;
  *) AC_MSG_ERROR(bad value ${enableval} for --enable-iconv) ;;
esac],[if test "x$iconv" = "x"; then iconv=true; fi])

AC_ARG_ENABLE(debug,
[AC_HELP_STRING([--enable-debug], [enable debug information (default: yes)])],
[case "${enableval}" in
  yes) debug=true ;;
  no)  debug=false ;;
  *) AC_MSG_ERROR(bad value ${enableval} for --enable-debug) ;;
esac],[if test "x$debug" = "x"; then debug=true; fi])

AC_ARG_ENABLE(latest_deps,
[AC_HELP_STRING([--enable-latest-deps], [makes rebar use latest commits for dependences instead of tagged versions (default: no)])],
[case "${enableval}" in
  yes) latest_deps=true ;;
  no)  latest_deps=false ;;
  *) AC_MSG_ERROR(bad value ${enableval} for --enable-latest-deps) ;;
esac],[if test "x$latest_deps" = "x"; then latest_deps=false; fi])

AC_ARG_ENABLE(system_deps,
[AC_HELP_STRING([--enable-system-deps], [makes rebar use localy installed dependences instead of downloading them (default: no)])],
[case "${enableval}" in
  yes) system_deps=true ;;
  no)  system_deps=false ;;
  *) AC_MSG_ERROR(bad value ${enableval} for --enable-system-deps) ;;
esac],[if test "x$system_deps" = "x"; then system_deps=false; fi])

AC_ARG_ENABLE(stun,
[AC_HELP_STRING([--enable-stun], [enable STUN/TURN support (default: no)])],
[case "${enableval}" in
  yes) stun=true ;;
  no)  stun=false ;;
  *) AC_MSG_ERROR(bad value ${enableval} for --enable-stun) ;;
esac],[if test "x$stun" = "x"; then stun=false; fi])

AC_ARG_ENABLE(sip,
[AC_HELP_STRING([--enable-sip], [enable SIP support (default: no)])],
[case "${enableval}" in
  yes) sip=true ;;
  no)  sip=false ;;
  *) AC_MSG_ERROR(bad value ${enableval} for --enable-sip) ;;
esac],[if test "x$sip" = "x"; then sip=false; fi])

AC_CONFIG_FILES([Makefile
		 vars.config
		 src/ejabberd.app.src])

ENABLEUSER=""
AC_ARG_ENABLE(user,
  [AS_HELP_STRING([--enable-user[[[[=USER]]]]], [allow this system user to start ejabberd (default: no)])],
  [case "${enableval}" in
     yes) ENABLEUSER=`whoami` ;;
     no) ENABLEUSER="" ;;
     *) ENABLEUSER=$enableval
   esac],
  [])
if test "$ENABLEUSER" != ""; then
  echo "allow this system user to start ejabberd: $ENABLEUSER"
  AC_SUBST([INSTALLUSER], [$ENABLEUSER])
fi

ERLANG_DEPRECATED_TYPES_CHECK

if test "$sqlite" = "true"; then
   AX_LIB_SQLITE3([3.6.19])
   if test "x$SQLITE3_VERSION" = "x"; then
      AC_MSG_ERROR(SQLite3 library >= 3.6.19 was not found)
   fi
fi

AC_SUBST(hipe)
AC_SUBST(roster_gateway_workaround)
AC_SUBST(full_xml)
AC_SUBST(db_type)
AC_SUBST(odbc)
AC_SUBST(mysql)
AC_SUBST(pgsql)
AC_SUBST(sqlite)
AC_SUBST(pam)
AC_SUBST(zlib)
AC_SUBST(riak)
AC_SUBST(redis)
AC_SUBST(elixir)
AC_SUBST(esmb)
AC_SUBST(iconv)
AC_SUBST(stun)
AC_SUBST(sip)
AC_SUBST(debug)
AC_SUBST(tools)
AC_SUBST(latest_deps)
AC_SUBST(system_deps)
AC_SUBST(CFLAGS)
AC_SUBST(CPPFLAGS)
AC_SUBST(LDFLAGS)

AC_OUTPUT

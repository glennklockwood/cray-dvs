#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT([cray-dvs], [0.9.0], [http://bugzilla.us.cray.com])
AM_CONFIG_HEADER([dvs_autoconfig.h])
AM_INIT_AUTOMAKE([foreign -Wall -Werror])
AC_USE_SYSTEM_EXTENSIONS

# Checks for programs.
AC_PROG_AWK
AC_PROG_CC
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
AC_PROG_INSTALL
AM_PROG_LIBTOOL
AC_PROG_LN_S

# Checks for libraries.
# FIXME: Replace `main' with a function in `-lail':
AC_CHECK_LIB([ail], [main])
# FIXME: Replace `main' with a function in `-laio':
AC_CHECK_LIB([aio], [main])
# FIXME: Replace `main' with a function in `-lcnx_syscall':
AC_CHECK_LIB([cnx_syscall], [main])
# FIXME: Replace `main' with a function in `-lnsl':
AC_CHECK_LIB([nsl], [main])
# FIXME: Replace `main' with a function in `-lposix4':
AC_CHECK_LIB([posix4], [main])
# FIXME: Replace `main' with a function in `-lpthread':
AC_CHECK_LIB([pthread], [main])
# FIXME: Replace `main' with a function in `-lpthreads':
AC_CHECK_LIB([pthreads], [main])
# FIXME: Replace `main' with a function in `-lrt':
AC_CHECK_LIB([rt], [main])
# FIXME: Replace `main' with a function in `-lsocket':
AC_CHECK_LIB([socket], [main])
# FIXME: Replace `main' with a function in `-lthread':
AC_CHECK_LIB([thread], [main])

# Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h malloc.h mntent.h netdb.h netinet/in.h stdint.h stdlib.h string.h strings.h sys/file.h sys/ioctl.h sys/param.h sys/socket.h sys/time.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_UID_T
AC_C_INLINE
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_C_VOLATILE

# Checks for library functions.
AC_FUNC_CLOSEDIR_VOID
AC_FUNC_FORK
AC_FUNC_GETMNTENT
AC_PROG_GCC_TRADITIONAL
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_MMAP
AC_FUNC_REALLOC
AC_FUNC_SELECT_ARGTYPES
AC_FUNC_SETVBUF_REVERSED
AC_TYPE_SIGNAL
AC_FUNC_STAT
AC_FUNC_STRNLEN
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([alarm bzero ftruncate gethostbyname gethostname getmntent getpagesize gettimeofday inet_ntoa memmove memset mkdir munmap rmdir select socket strchr strdup strerror strrchr strtol])

AC_SUBST([initdir], [${sysconfdir}/init.d])
AC_SUBST([ldsoconfdir], [/etc/ld.so.conf.d])
AC_SUBST([pkgconfigdir], [${libdir}/pkgconfig])
AC_SUBST([whatisdir], [${mandir}])
AC_SUBST([modprobeddir], [/etc/modprobe.d])

PKG_PROG_PKG_CONFIG
PKG_CHECK_MODULES([CRAY_PORTALS], [cray-portals], have_portals="yes", have_portals="no")

# MPI
AC_ARG_WITH([mpi],
  [AS_HELP_STRING([--with-mpi],
  [with mpi support @<:@default=no@:>@])])

AS_IF([test "x${with_mpi}" == "xyes" ],
      [AC_DEFINE([USE_MPI], 1, [Use MPI])],
      [AC_DEFINE([USE_MPI], 0, [Do not use MPI])])

# HSS
AC_ARG_WITH([hss],
  [AS_HELP_STRING([--with-hss],
  [with hss support @<:@default=yes@:>@])])

AS_IF([test "x${with_hss}" = "xyes" -o "x${with_hss}" = "x"],
       [AC_DEFINE([USE_HSS], 1, [Use HSS])
       PKG_CHECK_MODULES([LSB_CRAY_HSS], [lsb-cray-hss],
           [AC_SUBST([LSB_CRAY_HSS_INCLUDEDIR],
		     [[`${PKG_CONFIG} --variable=includedir lsb-cray-hss`]])])
       with_hss=yes],
      [test "x${with_hss}" != "xno"],
       [AC_MSG_FAILURE([invalid HSS value: $with_hss])],
      [with_hss=no])

# KATLAS
AC_ARG_WITH([katlas],
  [AS_HELP_STRING([--with-katlas],
  [with KATLAS support @<:@default=yes@:>@])])

AS_IF([test "x${with_katlas}" = "xyes" -o "x${with_katlas}" = "x"],
       [AC_DEFINE([USE_KATLAS], 1, [Use KATLAS])
       PKG_CHECK_MODULES([CRAY_KATLAS], [cray-katlas],
           [AC_SUBST([CRAY_KATLAS_INCLUDEDIR],
                     [[`${PKG_CONFIG} --variable=includedir cray-katlas`]])])
       AC_SUBST([USE_KATLAS], 1)
       with_katlas=yes],
      [test "x${with_katlas}" != "xno"],
       [AC_MSG_FAILURE([invalid KATLAS value: $with_katlas])],
      [with_katlas=no
       AC_SUBST([USE_KATLAS], 0)])

# RCA
AC_ARG_WITH([rca],
  [AS_HELP_STRING([--with-rca],
  [with RCA support @<:@default=yes@:>@])])

AS_IF([test "x${with_rca}" = "xyes" -o "x${with_rca}" = "x"],
       [AC_DEFINE([USE_RCA], 1, [Use RCA])
       PKG_CHECK_MODULES([CRAY_KRCA], [cray-krca],
           [AC_SUBST([CRAY_KRCA_INCLUDEDIR],
                     [[`${PKG_CONFIG} --variable=includedir cray-krca`]])])
       PKG_CHECK_MODULES([CRAY_RCA], [cray-rca],
           [AC_SUBST([CRAY_RCA_DEFAULT_BINDIR],
		     [[`${PKG_CONFIG} --variable=default_bindir cray-rca`]])])
       AC_SUBST([USE_RCA], 1)
       with_rca=yes],
      [test "x${with_rca}" != "xno"],
       [AC_MSG_FAILURE([invalid RCA value: $with_rca])],
      [with_rca=no
       AC_SUBST([USE_RCA], 0)])

# ANSIBLE
AC_ARG_ENABLE([ansible],
  [AS_HELP_STRING([--enable-ansible=[yes|no]],
     [Enable Ansible support (default is yes)])],
  [case "${enableval}" in
     no)
       enable_ansible=no
       AC_SUBST([ansible_enabled], "no")
       ;;
     yes)
       enable_ansible=yes
       AC_SUBST([ansible_enabled], "yes")
       ;;
     *)
       AC_MSG_ERROR([--enable-ansible arguments restricted to yes or no. Got ${enableval}])
       ;;
   esac],
  [enable_ansible=yes])

#AS_IF([test "$enable_ansible" = "yes"],
#   [AC_SUBST([RCAD_DEPENDENCIES], [''])],
#   [AC_SUBST([RCAD_DEPENDENCIES], ['$sdb $alpscompute'])]
#)


AC_ARG_WITH([docs],
  [AS_HELP_STRING([--with-docs],
  [with documentation @<:@default=yes@:>@])])

AS_IF([test "x${with_docs}" = "xyes" -o "x${with_docs}" = "x"],
       [with_docs=yes],
      [test "x${with_docs}" != "xno"],
       [AC_MSG_FAILURE([invalid DOCS value: $with_docs])],
      [with_docs=no])

AM_CONDITIONAL([DOCS], [test "$with_docs" = "yes"])

AC_ARG_WITH([default-prefix],
  [AS_HELP_STRING([--with-default-prefix=PATH],
     [PATH to use in place of ${prefix} for default paths.])],
  [AC_SUBST([default_prefix], $withval)],
  [AC_SUBST([default_prefix], "")])

AC_ARG_WITH([default-libdir],
  [AS_HELP_STRING([--with-default-libdir=PATH],
     [Default PATH for libraries.])],
  [AC_SUBST([default_libdir], $withval)],
  [if test -z "${default_prefix}"
   then
       AC_MSG_ERROR([Default library path or default prefix must be specified])
   else
       default_libdir=${libdir//${prefix}/${default_prefix}}
       AC_SUBST([default_libdir])
   fi])

AC_ARG_WITH([module],
  [AS_HELP_STRING([--with-module=PATH],
     [use $PATH as name of module file to write.])],
  [AC_SUBST([MODULE_PATH], $withval)
   AC_SUBST([MODULE_VERSION], [`basename $withval`])],
  [AC_MSG_ERROR([Module path must be specified])])

AC_ARG_WITH([subversion-revision],
  [AS_HELP_STRING([--with-subversion-revision=REVISION],
     [use $REVISION as subversion revisions of source.])],
  [AC_SUBST([SUBVERSION_REVISION], $withval)],
  [AC_MSG_ERROR([Subversion revision path must be specified.])])

AC_ARG_WITH([lnet-version],
  [AS_HELP_STRING([--with-lnet-version=LNET-VERSION],
     [use $LNET-VERSION as lnet revision of source.])],
  [AC_SUBST([LNET_BUILD], $withval)],
  [AC_MSG_ERROR([lnet version path must be specified.])])

AC_CONFIG_FILES([cray-dvs.pc
                 include/Makefile
                 Makefile
                 man/Makefile
                 man/man5/Makefile
                 module
                 scripts/dvs
                 scripts/dvs.cnl
                 scripts/functions
                 scripts/Makefile
                 test/ioperf/Makefile
                 test/unittest/Makefile
                 test/xattr/xattr_stress/Makefile
                 userspace/Makefile])
AC_OUTPUT

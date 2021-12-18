AC_INIT([chipvpn], [0.1], [maintainer@example.com])
AC_CONFIG_AUX_DIR([build-aux])
AC_CHECK_HEADERS(pthread.h)
AC_SEARCH_LIBS(pthread, pthread)
AC_CHECK_HEADERS(openssl/evp.h)
AC_CHECK_HEADERS(openssl/aes.h)
AC_SEARCH_LIBS(crypto, crypto)
AC_SEARCH_LIBS(ssl, ssl)
AM_INIT_AUTOMAKE
AC_PROG_CC
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
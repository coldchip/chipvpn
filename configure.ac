AC_INIT([chipvpn], [10000061], [ryan@chip.sg])

AC_CONFIG_AUX_DIR(auxdir)
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([foreign -Wall -Werror])

AC_PROG_CC

AC_CHECK_HEADERS(pthread.h)
AC_SEARCH_LIBS(pthread, pthread)
AC_CHECK_HEADERS(openssl/evp.h)
AC_CHECK_HEADERS(openssl/aes.h)
AC_SEARCH_LIBS(crypto, crypto)
AC_SEARCH_LIBS(ssl, ssl)

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
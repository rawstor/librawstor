libdir=${LIBDIR}
includedir=${INCLUDEDIR}

Name: rawstor
Description: Rawstor client library
Requires: ${REQUIRES}
Version: 0.0.0
Libs: -L${LIBDIR} -lrawstor
Cflags: -I${INCLUDEDIR}

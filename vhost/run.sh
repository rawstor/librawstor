#!/bin/bash

set -e

make -C ..

rm -f ../../rawstor.sock

./rawstor-vhost \
    -s ../../rawstor.sock \
    -o ost://127.0.0.1:8080/019925fe-29f3-7ff3-9136-57b598800819

#!/bin/bash

set -ex

make -j8

cd cli

./rawstor-cli \
    --sessions=1 \
    testio \
    --block-size=1024 \
    --count=10 \
    --io-depth=1 \
    --object-uri=ost://127.0.0.1:8080/019925fe-29f3-7ff3-9136-57b598800819,file:///tmp/objects/019925fe-29f3-7ff3-9136-57b598800819

#    --object-uri=ost://127.0.0.1:8080/019925fe-29f3-7ff3-9136-57b598800819,file:///tmp/objects/019925fe-29f3-7ff3-9136-57b598800819

# ./rawstor-cli \
#     --sessions=1 \
#     testio \
#     --block-size=4096 \
#     --count=10 \
#     --io-depth=16 \
#     --object-uri=file:///tmp/objects/0199e32f-2461-745f-8ca1-c27b28bf5398

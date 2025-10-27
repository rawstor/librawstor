#!/bin/bash

make -C .. -j8

./rawstor-vhost \
    --object-uri=file:///tmp/objects/019925fe-29f3-7ff3-9136-57b598800819 \
    --socket-path=../../rawstor1-user-blk.sock

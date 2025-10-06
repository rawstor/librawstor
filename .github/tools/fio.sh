#!/bin/bash

set -e

URI=$1
FILENAME=$2
BS=$3
IODEPTH=$4
NUMJOBS=$5
FIO_TXT=$6
FIO_JSON=$7

_FIO_OUTPUT=fio.output

fio \
  --ioengine=librawstor \
  --uri=${URI} \
  --filename=${FILENAME} \
  --name=rawstor \
  --iodepth=${IODEPTH} \
  --rw=randrw \
  --bs=${BS} \
  --size=1G \
  --numjobs=${NUMJOBS} \
  --runtime=10 \
  --time_based \
  --group_reporting \
  --output-format=normal,json \
  --output=${_FIO_OUTPUT}

_FIO_TXT=_fio.txt
_FIO_JSON=_fio.json

rm -f ${_FIO_TXT} ${_FIO_JSON}
output=fio.txt
while IFS='' read line; do
    if [ "${line}" == "{"  ] ; then
        output=${_FIO_JSON}
    fi

    echo "${line}" >> ${output}

    if [ "${line}" == "}"  ] ; then
        output=${_FIO_TXT}
    fi
done < ${_FIO_OUTPUT}

cp ${_FIO_TXT} ${FIO_TXT}
cp ${_FIO_JSON} ${FIO_JSON}

rm ${_FIO_OUTPUT} ${_FIO_TXT} ${_FIO_JSON}

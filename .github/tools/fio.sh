#!/bin/bash

set -e

OBJECT_URI=$1
BS=$2
IODEPTH=$3
NUMJOBS=$4
FIO_TXT=$5
FIO_JSON=$6

_FIO_OUTPUT=fio.output

fio \
  --output-format=normal,json \
  --output=${_FIO_OUTPUT} \
  --ioengine=librawstor \
  --filename="${OBJECT_URI//:/\\:}" \
  \
  --name=randread \
  --iodepth=${IODEPTH} \
  --rw=randread \
  --bs=${BS} \
  --size=1G \
  --numjobs=${NUMJOBS} \
  --runtime=10 \
  --time_based \
  --group_reporting \
  \
  \
  --name=randwrite \
  --stonewall \
  --iodepth=${IODEPTH} \
  --rw=randwrite \
  --bs=${BS} \
  --size=1G \
  --numjobs=${NUMJOBS} \
  --runtime=10 \
  --time_based \
  --group_reporting

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
cat ${_FIO_JSON} | sed s/\\\\:/:/g > ${FIO_JSON}

rm ${_FIO_OUTPUT} ${_FIO_TXT} ${_FIO_JSON}

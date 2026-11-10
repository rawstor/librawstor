# Building from source

Build Rawstor from a checkout and run every service by hand on one
machine. For packages and systemd units see the [Quick start](quickstart.md).

```
PREFIX=${HOME}/local

./autogen.sh
./configure --prefix=${PREFIX}
make -j$(nproc)
make install

OST_HOST=192.168.0.1
MDS_HOST=192.168.0.1

##
# OST Server
#
OST_DATADIR=/var/rawstor

mkdir -p ${OST_DATADIR}

rawstor-ost \
    --bind ${OST_HOST} \
    file://${OST_DATADIR}

##
# MDS Server (optional: only for chunked mds:// objects)
#
MDS_DATADIR=/var/lib/rawstor/mds

mkdir -p ${MDS_DATADIR}

# One line per OST: <uuid> <location> <weight> <role> [[[<dc>/]<row>/]<rack>/]<server>
cat > ${MDS_DATADIR}/topology.conf <<EOF
$(cat /proc/sys/kernel/random/uuid) ost://${OST_HOST} 100 data,witness dc1/row1/rack1/host1
EOF

rawstor-mds \
    --bind ${MDS_HOST} \
    --db ${MDS_DATADIR}/mds.db \
    --topology ${MDS_DATADIR}/topology.conf

##
# Client
#
# The port may be omitted: it defaults to 7777 for ost:// and 7776 for mds://.
#
# An object split into 256M chunks, placed across the OSTs by the MDS...
OBJECT_TARGET=$(rawstor create mds://${MDS_HOST} --size=1G --chunk-size=256M --mirrors=1 --format value --column target)
# ...or a plain object stored whole on one OST, no MDS needed:
# OBJECT_TARGET=$(rawstor create ost://${OST_HOST} --size=1G --mirrors=1 --format value --column target)

VHOST_RUNDIR=${PREFIX}/var/run/rawstor

mkdir -p ${VHOST_RUNDIR}

rawstor-vhost \
    --socket-path=${VHOST_RUNDIR}/rawstor1.sock \
    ${OBJECT_TARGET}

qemu-system-x86_64 \
    -enable-kvm \
    -m 4G \
    -machine accel=kvm,memory-backend=mem \
    -drive file=image.qcow2,if=none,id=drive1 \
    -device virtio-blk-pci,drive=drive1 \
    -object memory-backend-memfd,id=mem,size=4G,share=on \
    -chardev socket,id=rawstor1,reconnect=1,path=${VHOST_RUNDIR}/rawstor1.sock \
    -device vhost-user-blk-pci,chardev=rawstor1,num-queues=1,disable-legacy=on
```

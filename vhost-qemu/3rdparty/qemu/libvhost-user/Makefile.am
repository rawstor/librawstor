noinst_LTLIBRARIES = libvhost-user.la


AM_CFLAGS = -std=gnu99 -Wall -Wextra \
            $(ASAN_CFLAGS)

AM_LDFLAGS = $(ASAN_LDFLAGS)


libvhost_user_la_SOURCES = include/atomic.h \
                           include/compiler.h \
                           standard-headers/linux/const.h \
                           standard-headers/linux/ethtool.h \
                           standard-headers/linux/fuse.h \
                           standard-headers/linux/if_ether.h \
                           standard-headers/linux/input-event-codes.h \
                           standard-headers/linux/input.h \
                           standard-headers/linux/kernel.h \
                           standard-headers/linux/kvm_para.h \
                           standard-headers/linux/pci_regs.h \
                           standard-headers/linux/qemu_fw_cfg.h \
                           standard-headers/linux/sysinfo.h \
                           standard-headers/linux/types.h \
                           standard-headers/linux/udmabuf.h \
                           standard-headers/linux/vhost_types.h \
                           standard-headers/linux/virtio_9p.h \
                           standard-headers/linux/virtio_balloon.h \
                           standard-headers/linux/virtio_blk.h \
                           standard-headers/linux/virtio_bt.h \
                           standard-headers/linux/virtio_config.h \
                           standard-headers/linux/virtio_console.h \
                           standard-headers/linux/virtio_crypto.h \
                           standard-headers/linux/virtio_fs.h \
                           standard-headers/linux/virtio_gpio.h \
                           standard-headers/linux/virtio_gpu.h \
                           standard-headers/linux/virtio_i2c.h \
                           standard-headers/linux/virtio_ids.h \
                           standard-headers/linux/virtio_input.h \
                           standard-headers/linux/virtio_iommu.h \
                           standard-headers/linux/virtio_mem.h \
                           standard-headers/linux/virtio_mmio.h \
                           standard-headers/linux/virtio_net.h \
                           standard-headers/linux/virtio_pci.h \
                           standard-headers/linux/virtio_pcidev.h \
                           standard-headers/linux/virtio_pmem.h \
                           standard-headers/linux/virtio_ring.h \
                           standard-headers/linux/virtio_rng.h \
                           standard-headers/linux/virtio_scmi.h \
                           standard-headers/linux/virtio_scsi.h \
                           standard-headers/linux/virtio_snd.h \
                           standard-headers/linux/virtio_types.h \
                           standard-headers/linux/virtio_vsock.h \
                           standard-headers/linux/vmclock-abi.h \
                           libvhost-user.c \
                           libvhost-user.h

libvhost_user_la_LIBADD =

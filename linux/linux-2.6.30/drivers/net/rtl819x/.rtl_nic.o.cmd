cmd_drivers/net/rtl819x/rtl_nic.o := rsdk-linux-gcc -Wp,-MD,drivers/net/rtl819x/.rtl_nic.o.d  -nostdinc -isystem /home/rtlac/RTL3.4/rtl819x_3.4.6.5/toolchain/rsdk-1.5.10-5281-EB-2.6.30-0.9.30-m32ub-130429/bin/../lib/gcc/mips-linux-uclibc/4.4.7/include -Iinclude  -I/home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include -include include/linux/autoconf.h -D__KERNEL__ -Wall -Wundef -Wstrict-prototypes -Wno-trigraphs -fno-strict-aliasing -fno-common -Werror-implicit-function-declaration -fno-delete-null-pointer-checks -Os -ffunction-sections -mno-check-zero-division -mabi=32 -G 0 -mno-abicalls -fno-pic -pipe -msoft-float -ffreestanding -EB -UMIPSEB -U_MIPSEB -U__MIPSEB -U__MIPSEB__ -UMIPSEL -U_MIPSEL -U__MIPSEL -U__MIPSEL__ -DMIPSEB -D_MIPSEB -D__MIPSEB -D__MIPSEB__ -Iinclude/asm-rlx -Iarch/rlx/bsp/ -I/home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/mach-generic -D"VMLINUX_LOAD_ADDRESS=0x80000000" -Wframe-larger-than=1024 -fno-stack-protector -fomit-frame-pointer -Wdeclaration-after-statement -Wno-pointer-sign -fno-strict-overflow -fno-dwarf2-cfi-asm -DCONFIG_RTL865X_MODULE_INTERNAL -DRTL865X_OVER_KERNEL -DRTL865X_OVER_LINUX -D__KERNEL__ -Wno-implicit -Werror -I/home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/include -I/home/rtlac/RTL3.4/rtl819x_3.4.6.5/target/bsp -I/home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/drivers/net/rtl819x/ -I/home/rtlac/RTL3.4/rtl819x_3.4.6.5/target -D__KERNEL__ -DEXPORT_SYMTAB   -D"KBUILD_STR(s)=\#s" -D"KBUILD_BASENAME=KBUILD_STR(rtl_nic)"  -D"KBUILD_MODNAME=KBUILD_STR(rtl_nic)"  -c -o drivers/net/rtl819x/rtl_nic.o drivers/net/rtl819x/rtl_nic.c

deps_drivers/net/rtl819x/rtl_nic.o := \
  drivers/net/rtl819x/rtl_nic.c \
    $(wildcard include/config/rtk/vlan/support.h) \
    $(wildcard include/config/rtl/vlan/8021q.h) \
    $(wildcard include/config/rtl8196/rtl8366.h) \
    $(wildcard include/config/rtl/igmp/snooping.h) \
    $(wildcard include/config/rtl/eth/priv/sk.h) \
    $(wildcard include/config/rtk/fake/eth.h) \
    $(wildcard include/config/rtl/layered/asic/driver/l3.h) \
    $(wildcard include/config/rtl/layered/driver/l2.h) \
    $(wildcard include/config/rtl/layered/driver/l3.h) \
    $(wildcard include/config/rtl865x/romeperf.h) \
    $(wildcard include/config/rtl/fastbridge.h) \
    $(wildcard include/config/rtl/hw/qos/support.h) \
    $(wildcard include/config/net/sched.h) \
    $(wildcard include/config/rtl/layered/driver.h) \
    $(wildcard include/config/rtl/stp.h) \
    $(wildcard include/config/rtl8367r/vb/api.h) \
    $(wildcard include/config/rtl/hw/stp.h) \
    $(wildcard include/config/rtl/8196c/esd.h) \
    $(wildcard include/config/rtl/8198/esd.h) \
    $(wildcard include/config/rtl/mld/snooping.h) \
    $(wildcard include/config/rtl/hardware/multicast.h) \
    $(wildcard include/config/tr181/eth.h) \
    $(wildcard include/config/rtl/jate/test.h) \
    $(wildcard include/config/rtk/vlan/wan/tag/support.h) \
    $(wildcard include/config/size.h) \
    $(wildcard include/config/pppoe/index.h) \
    $(wildcard include/config/rtl/8198/inband/ap.h) \
    $(wildcard include/config/rtl/8198/nfbi/board.h) \
    $(wildcard include/config/819x/phy/rw.h) \
    $(wildcard include/config/rtl/8197d/dyn/thr.h) \
    $(wildcard include/config/rtk/voip/port/link.h) \
    $(wildcard include/config/rtk/voip/ethernet/dsp.h) \
    $(wildcard include/config/rtl/custom/passthru.h) \
    $(wildcard include/config/rtl/8198.h) \
    $(wildcard include/config/rtl/819xd.h) \
    $(wildcard include/config/rtl/8196e.h) \
    $(wildcard include/config/rtl/eth/priv/skb.h) \
    $(wildcard include/config/net/wireless/agn.h) \
    $(wildcard include/config/net/wireless/ag.h) \
    $(wildcard include/config/wireless.h) \
    $(wildcard include/config/rtl/local/public.h) \
    $(wildcard include/config/wireless/lan.h) \
    $(wildcard include/config/rtl/reinit/switch/core.h) \
    $(wildcard include/config/rtl/unkown/unicast/control.h) \
    $(wildcard include/config/rtl8186/tr.h) \
    $(wildcard include/config/rtl8196c/green/ethernet.h) \
    $(wildcard include/config/rtl/linkstate.h) \
    $(wildcard include/config/rtl/hw/vlan/support.h) \
    $(wildcard include/config/rtk/qos/for/cable/modem.h) \
    $(wildcard include/config/rtl/multiple/wan.h) \
    $(wildcard include/config/defaults/kernel/2/6.h) \
    $(wildcard include/config/rtl/report/link/status.h) \
    $(wildcard include/config/rtl/phy/power/ctrl.h) \
    $(wildcard include/config/rtl/linkchg/process.h) \
    $(wildcard include/config/rtl/phy/patch.h) \
    $(wildcard include/config/rtl/proc/debug.h) \
    $(wildcard include/config/rtl/debug/tool.h) \
    $(wildcard include/config/rtl/8370/support.h) \
    $(wildcard include/config/efm/patch.h) \
    $(wildcard include/config/rtl/multi/lan/dev.h) \
    $(wildcard include/config/bridge.h) \
    $(wildcard include/config/rtl/public/ssid.h) \
    $(wildcard include/config/8198/port5/gmii.h) \
    $(wildcard include/config/rtk/vlan/new/feature.h) \
    $(wildcard include/config/end.h) \
    $(wildcard include/config/proc/fs.h) \
    $(wildcard include/config/pocket/ap/support.h) \
    $(wildcard include/config/rtl/ap/package.h) \
    $(wildcard include/config/rtk/mesh.h) \
    $(wildcard include/config/rtl/8367r/support.h) \
    $(wildcard include/config/rtk/refine/port/duplex/mode.h) \
    $(wildcard include/config/rtk/vlan/for/cable/modem.h) \
    $(wildcard include/config/rtl8196c/revision/b.h) \
    $(wildcard include/config/rtl8196c/eth/iot.h) \
    $(wildcard include/config/rtl/8211ds/support.h) \
    $(wildcard include/config/rtl/8197d.h) \
    $(wildcard include/config/rtl/nic/hwstats.h) \
    $(wildcard include/config/rtl/8196c.h) \
    $(wildcard include/config/rtl/eth/priv/skb/debug.h) \
    $(wildcard include/config/rtl/ulinker/brsc.h) \
    $(wildcard include/config/rtl/fast/bridge.h) \
    $(wildcard include/config/rtk/voip/vlan/id.h) \
    $(wildcard include/config/rtl/qos/8021p/support.h) \
    $(wildcard include/config/netfilter/xt/match/phyport.h) \
    $(wildcard include/config/rtl/fast/filter.h) \
    $(wildcard include/config/rtl/qos/patch.h) \
    $(wildcard include/config/rtk/voip/qos.h) \
    $(wildcard include/config/rtl/mac/filter/care/inport.h) \
    $(wildcard include/config/rtl8196bu/8186sdk/mp/spi.h) \
    $(wildcard include/config/netfilter.h) \
    $(wildcard include/config/rtl865x/igmp/snooping.h) \
    $(wildcard include/config/rtl/custom/passthru/pppoe.h) \
    $(wildcard include/config/vlan/8021q.h) \
    $(wildcard include/config/rtl/cpu/tag.h) \
    $(wildcard include/config/domain/name/query/support.h) \
    $(wildcard include/config/rtl/ulinker.h) \
    $(wildcard include/config/rtl/hardware/nat.h) \
    $(wildcard include/config/compat/net/dev/ops.h) \
    $(wildcard include/config/rtl8192se.h) \
    $(wildcard include/config/rtl8192cd.h) \
    $(wildcard include/config/rtl/ipv6readylogo.h) \
    $(wildcard include/config/rtk/voip/ethernet/dsp/is/host.h) \
    $(wildcard include/config/rtl/819x/swcore.h) \
    $(wildcard include/config/rtl/ivl/support.h) \
    $(wildcard include/config/printk.h) \
    $(wildcard include/config/rtl/8196d.h) \
    $(wildcard include/config/rtl/8881a.h) \
    $(wildcard include/config/rtl/8370/support/xxxx.h) \
    $(wildcard include/config/pocket/router/support.h) \
    $(wildcard include/config/rtl/pppoe/direct/reply.h) \
    $(wildcard include/config/8198/port5/rgmii.h) \
    $(wildcard include/config/rtl8186/kb.h) \
    $(wildcard include/config/rtl8186/gr.h) \
    $(wildcard include/config/rtl8186/link/change.h) \
    $(wildcard include/config/hardware/nat/debug.h) \
    $(wildcard include/config/rtl/iptables/rule/2/acl.h) \
    $(wildcard include/config/efm/patch/xxxx.h) \
    $(wildcard include/config/efm/patch/for/multi.h) \
    $(wildcard include/config/efm/patch/mobile/ap.h) \
    $(wildcard include/config/rtl/layered/asic/driver/l4.h) \
    $(wildcard include/config/rtl865x/bicolor/led.h) \
    $(wildcard include/config/rtk/voip/board.h) \
    $(wildcard include/config/efm/patch/xxx.h) \
    $(wildcard include/config/efm/kt/3wan/ports.h) \
    $(wildcard include/config/rtl/sock/debug.h) \
    $(wildcard include/config/efm/extender/u1.h) \
    $(wildcard include/config/efm/extender/n2.h) \
    $(wildcard include/config/rtl/layered/driver/acl.h) \
    $(wildcard include/config/rtl/layered/driver/l4.h) \
    $(wildcard include/config/check.h) \
    $(wildcard include/config/support/russia/features.h) \
    $(wildcard include/config/rtl865x/lanport/restriction.h) \
    $(wildcard include/config/rtl/wtdog.h) \
  include/linux/config.h \
    $(wildcard include/config/h.h) \
  include/linux/module.h \
    $(wildcard include/config/modules.h) \
    $(wildcard include/config/modversions.h) \
    $(wildcard include/config/unused/symbols.h) \
    $(wildcard include/config/generic/bug.h) \
    $(wildcard include/config/kallsyms.h) \
    $(wildcard include/config/markers.h) \
    $(wildcard include/config/tracepoints.h) \
    $(wildcard include/config/tracing.h) \
    $(wildcard include/config/module/unload.h) \
    $(wildcard include/config/smp.h) \
    $(wildcard include/config/sysfs.h) \
  include/linux/list.h \
    $(wildcard include/config/debug/list.h) \
  include/linux/stddef.h \
  include/linux/compiler.h \
    $(wildcard include/config/trace/branch/profiling.h) \
    $(wildcard include/config/profile/all/branches.h) \
    $(wildcard include/config/enable/must/check.h) \
    $(wildcard include/config/enable/warn/deprecated.h) \
  include/linux/compiler-gcc.h \
    $(wildcard include/config/arch/supports/optimized/inlining.h) \
    $(wildcard include/config/optimize/inlining.h) \
  include/linux/compiler-gcc4.h \
  include/linux/poison.h \
  include/linux/prefetch.h \
  include/linux/types.h \
    $(wildcard include/config/uid16.h) \
    $(wildcard include/config/lbd.h) \
    $(wildcard include/config/4kb/harddisk/support.h) \
    $(wildcard include/config/phys/addr/t/64bit.h) \
    $(wildcard include/config/64bit.h) \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/types.h \
  include/asm-generic/int-ll64.h \
  include/asm-generic/bitsperlong.h \
  include/linux/posix_types.h \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/posix_types.h \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/sgidefs.h \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/processor.h \
    $(wildcard include/config/cpu/has/sleep.h) \
    $(wildcard include/config/arch/suspend/possible.h) \
    $(wildcard include/config/rtl8197b/pana.h) \
    $(wildcard include/config/cpu/has/watch.h) \
  include/linux/cpumask.h \
    $(wildcard include/config/disable/obsolete/cpumask/functions.h) \
    $(wildcard include/config/hotplug/cpu.h) \
    $(wildcard include/config/cpumask/offstack.h) \
    $(wildcard include/config/debug/per/cpu/maps.h) \
  include/linux/kernel.h \
    $(wildcard include/config/preempt/voluntary.h) \
    $(wildcard include/config/debug/spinlock/sleep.h) \
    $(wildcard include/config/prove/locking.h) \
    $(wildcard include/config/panic/printk.h) \
    $(wildcard include/config/dynamic/debug.h) \
    $(wildcard include/config/ring/buffer.h) \
    $(wildcard include/config/numa.h) \
    $(wildcard include/config/ftrace/mcount/record.h) \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/toolchain/rsdk-1.5.10-5281-EB-2.6.30-0.9.30-m32ub-130429/bin/../lib/gcc/mips-linux-uclibc/4.4.7/include/stdarg.h \
  include/linux/linkage.h \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/linkage.h \
  include/linux/bitops.h \
    $(wildcard include/config/generic/find/first/bit.h) \
    $(wildcard include/config/generic/find/last/bit.h) \
    $(wildcard include/config/generic/find/next/bit.h) \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/bitops.h \
    $(wildcard include/config/cpu/has/llsc.h) \
    $(wildcard include/config/cpu/rlx4181.h) \
    $(wildcard include/config/cpu/rlx5181.h) \
    $(wildcard include/config/cpu/rlx5281.h) \
    $(wildcard include/config/cpu/has/radiax.h) \
  include/linux/irqflags.h \
    $(wildcard include/config/trace/irqflags.h) \
    $(wildcard include/config/irqsoff/tracer.h) \
    $(wildcard include/config/preempt/tracer.h) \
    $(wildcard include/config/trace/irqflags/support.h) \
    $(wildcard include/config/rtl/819x.h) \
  include/linux/typecheck.h \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/irqflags.h \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/hazards.h \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/cpu-features.h \
    $(wildcard include/config/cpu/has/ejtag.h) \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/cpu.h \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/cpu-info.h \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/cache.h \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/mach-generic/kmalloc.h \
    $(wildcard include/config/dma/coherent.h) \
  arch/rlx/bsp/bspcpu.h \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/barrier.h \
    $(wildcard include/config/cpu/has/sync.h) \
    $(wildcard include/config/cpu/has/wb.h) \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/bug.h \
    $(wildcard include/config/bug.h) \
  include/asm-generic/bug.h \
    $(wildcard include/config/generic/bug/relative/pointers.h) \
    $(wildcard include/config/debug/bugverbose.h) \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/byteorder.h \
    $(wildcard include/config/cpu/big/endian.h) \
  include/linux/byteorder/big_endian.h \
  include/linux/swab.h \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/swab.h \
  include/linux/byteorder/generic.h \
  include/asm-generic/bitops/non-atomic.h \
  include/asm-generic/bitops/fls64.h \
  include/asm-generic/bitops/ffz.h \
  include/asm-generic/bitops/find.h \
  include/asm-generic/bitops/sched.h \
  include/asm-generic/bitops/hweight.h \
  include/asm-generic/bitops/ext2-non-atomic.h \
  include/asm-generic/bitops/le.h \
  include/asm-generic/bitops/ext2-atomic.h \
  include/asm-generic/bitops/minix.h \
  include/linux/log2.h \
    $(wildcard include/config/arch/has/ilog2/u32.h) \
    $(wildcard include/config/arch/has/ilog2/u64.h) \
  include/linux/ratelimit.h \
  include/linux/param.h \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/param.h \
    $(wildcard include/config/hz.h) \
  include/linux/dynamic_debug.h \
  include/linux/threads.h \
    $(wildcard include/config/nr/cpus.h) \
    $(wildcard include/config/base/small.h) \
  include/linux/bitmap.h \
  include/linux/string.h \
    $(wildcard include/config/binary/printf.h) \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/string.h \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/cachectl.h \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/rlxregs.h \
    $(wildcard include/config/cpu/rlx4281.h) \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/system.h \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/addrspace.h \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/mach-generic/spaces.h \
    $(wildcard include/config/32bit.h) \
    $(wildcard include/config/dma/noncoherent.h) \
  include/linux/const.h \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/cmpxchg.h \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/watch.h \
  include/linux/stat.h \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/stat.h \
  include/linux/time.h \
  include/linux/cache.h \
    $(wildcard include/config/arch/has/cache/line/size.h) \
  include/linux/seqlock.h \
  include/linux/spinlock.h \
    $(wildcard include/config/debug/spinlock.h) \
    $(wildcard include/config/generic/lockbreak.h) \
    $(wildcard include/config/preempt.h) \
    $(wildcard include/config/debug/lock/alloc.h) \
  include/linux/preempt.h \
    $(wildcard include/config/debug/preempt.h) \
    $(wildcard include/config/preempt/notifiers.h) \
  include/linux/thread_info.h \
    $(wildcard include/config/compat.h) \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/thread_info.h \
    $(wildcard include/config/kernel/stack/size/order.h) \
    $(wildcard include/config/debug/stack/usage.h) \
  include/linux/stringify.h \
  include/linux/bottom_half.h \
  include/linux/spinlock_types.h \
  include/linux/spinlock_types_up.h \
  include/linux/lockdep.h \
    $(wildcard include/config/lockdep.h) \
    $(wildcard include/config/lock/stat.h) \
    $(wildcard include/config/generic/hardirqs.h) \
  include/linux/spinlock_up.h \
  include/linux/spinlock_api_up.h \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/atomic.h \
  include/asm-generic/atomic-long.h \
  include/linux/math64.h \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/div64.h \
  include/asm-generic/div64.h \
  include/linux/kmod.h \
  include/linux/gfp.h \
    $(wildcard include/config/zone/dma.h) \
    $(wildcard include/config/zone/dma32.h) \
    $(wildcard include/config/highmem.h) \
  include/linux/mmzone.h \
    $(wildcard include/config/force/max/zoneorder.h) \
    $(wildcard include/config/memory/hotplug.h) \
    $(wildcard include/config/sparsemem.h) \
    $(wildcard include/config/arch/populates/node/map.h) \
    $(wildcard include/config/discontigmem.h) \
    $(wildcard include/config/flat/node/mem/map.h) \
    $(wildcard include/config/cgroup/mem/res/ctlr.h) \
    $(wildcard include/config/have/memory/present.h) \
    $(wildcard include/config/need/node/memmap/size.h) \
    $(wildcard include/config/need/multiple/nodes.h) \
    $(wildcard include/config/have/arch/early/pfn/to/nid.h) \
    $(wildcard include/config/flatmem.h) \
    $(wildcard include/config/sparsemem/extreme.h) \
    $(wildcard include/config/nodes/span/other/nodes.h) \
    $(wildcard include/config/holes/in/zone.h) \
    $(wildcard include/config/arch/has/holes/memorymodel.h) \
  include/linux/wait.h \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/current.h \
  include/linux/numa.h \
    $(wildcard include/config/nodes/shift.h) \
  include/linux/init.h \
    $(wildcard include/config/hotplug.h) \
  include/linux/section-names.h \
  include/linux/nodemask.h \
  include/linux/pageblock-flags.h \
    $(wildcard include/config/hugetlb/page.h) \
    $(wildcard include/config/hugetlb/page/size/variable.h) \
  include/linux/bounds.h \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/page.h \
  include/linux/pfn.h \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/io.h \
  include/asm-generic/iomap.h \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/pgtable-bits.h \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/mach-generic/ioremap.h \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/mach-generic/mangle-port.h \
    $(wildcard include/config/swap/io/space.h) \
  include/asm-generic/memory_model.h \
    $(wildcard include/config/sparsemem/vmemmap.h) \
  include/asm-generic/getorder.h \
  include/linux/memory_hotplug.h \
    $(wildcard include/config/have/arch/nodedata/extension.h) \
    $(wildcard include/config/memory/hotremove.h) \
  include/linux/notifier.h \
  include/linux/errno.h \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/errno.h \
  include/asm-generic/errno-base.h \
  include/linux/mutex.h \
    $(wildcard include/config/debug/mutexes.h) \
  include/linux/rwsem.h \
    $(wildcard include/config/rwsem/generic/spinlock.h) \
  include/linux/rwsem-spinlock.h \
  include/linux/srcu.h \
  include/linux/topology.h \
    $(wildcard include/config/sched/smt.h) \
    $(wildcard include/config/sched/mc.h) \
  include/linux/smp.h \
    $(wildcard include/config/use/generic/smp/helpers.h) \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/topology.h \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/mach-generic/topology.h \
  include/asm-generic/topology.h \
  include/linux/mmdebug.h \
    $(wildcard include/config/debug/vm.h) \
    $(wildcard include/config/debug/virtual.h) \
  include/linux/elf.h \
  include/linux/elf-em.h \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/elf.h \
  include/linux/kobject.h \
  include/linux/sysfs.h \
  include/linux/kref.h \
  include/linux/moduleparam.h \
    $(wildcard include/config/alpha.h) \
    $(wildcard include/config/ia64.h) \
    $(wildcard include/config/ppc64.h) \
  include/linux/marker.h \
  include/linux/tracepoint.h \
  include/linux/rcupdate.h \
    $(wildcard include/config/classic/rcu.h) \
    $(wildcard include/config/tree/rcu.h) \
    $(wildcard include/config/preempt/rcu.h) \
  include/linux/completion.h \
  include/linux/rcuclassic.h \
    $(wildcard include/config/rcu/cpu/stall/detector.h) \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/local.h \
  include/linux/percpu.h \
    $(wildcard include/config/have/dynamic/per/cpu/area.h) \
  include/linux/slab.h \
    $(wildcard include/config/slab/debug.h) \
    $(wildcard include/config/debug/objects.h) \
    $(wildcard include/config/slub.h) \
    $(wildcard include/config/slob.h) \
    $(wildcard include/config/debug/slab.h) \
  include/linux/slab_def.h \
    $(wildcard include/config/kmemtrace.h) \
  include/trace/kmemtrace.h \
  include/linux/kmalloc_sizes.h \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/percpu.h \
  include/asm-generic/percpu.h \
    $(wildcard include/config/have/setup/per/cpu/area.h) \
  include/linux/percpu-defs.h \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/module.h \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/uaccess.h \
  include/linux/netdevice.h \
    $(wildcard include/config/dcb.h) \
    $(wildcard include/config/wlan/80211.h) \
    $(wildcard include/config/ax25.h) \
    $(wildcard include/config/mac80211/mesh.h) \
    $(wildcard include/config/tr.h) \
    $(wildcard include/config/net/ipip.h) \
    $(wildcard include/config/net/ipgre.h) \
    $(wildcard include/config/ipv6/sit.h) \
    $(wildcard include/config/ipv6/tunnel.h) \
    $(wildcard include/config/netpoll.h) \
    $(wildcard include/config/net/poll/controller.h) \
    $(wildcard include/config/fcoe.h) \
    $(wildcard include/config/wireless/ext.h) \
    $(wildcard include/config/net/dsa.h) \
    $(wildcard include/config/net/ns.h) \
    $(wildcard include/config/rtl/hw/napt.h) \
    $(wildcard include/config/net/dsa/tag/dsa.h) \
    $(wildcard include/config/net/dsa/tag/trailer.h) \
    $(wildcard include/config/rtl/usb/otg.h) \
    $(wildcard include/config/netpoll/trap.h) \
  include/linux/if.h \
  include/linux/socket.h \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/socket.h \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/sockios.h \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/ioctl.h \
  include/asm-generic/ioctl.h \
  include/linux/sockios.h \
  include/linux/uio.h \
  include/linux/hdlc/ioctl.h \
  include/linux/if_ether.h \
    $(wildcard include/config/sysctl.h) \
  include/linux/skbuff.h \
    $(wildcard include/config/rtl8190.h) \
    $(wildcard include/config/nf/conntrack.h) \
    $(wildcard include/config/bridge/netfilter.h) \
    $(wildcard include/config/has/dma.h) \
    $(wildcard include/config/rtl8686/gmac.h) \
    $(wildcard include/config/xfrm.h) \
    $(wildcard include/config/net/cls/act.h) \
    $(wildcard include/config/ipv6/ndisc/nodetype.h) \
    $(wildcard include/config/mac80211.h) \
    $(wildcard include/config/net/dma.h) \
    $(wildcard include/config/network/secmark.h) \
    $(wildcard include/config/rtl/dscp/iptable/check.h) \
    $(wildcard include/config/rtl/iptables/fast/path.h) \
    $(wildcard include/config/rtl/fast/pppoe.h) \
  include/linux/net.h \
  include/linux/random.h \
  include/linux/ioctl.h \
  include/linux/irqnr.h \
    $(wildcard include/config/sparse/irq.h) \
  include/linux/fcntl.h \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/fcntl.h \
  include/asm-generic/fcntl.h \
  include/linux/sysctl.h \
    $(wildcard include/config/rtl/nf/conntrack/garbage/new.h) \
    $(wildcard include/config/forward/speed/up/patch.h) \
    $(wildcard include/config/passthrough/all/chain.h) \
    $(wildcard include/config/nf/nat/ispfake.h) \
    $(wildcard include/config/efm/patch/skip/nf/input/output.h) \
    $(wildcard include/config/ip/conntrack/limit/control.h) \
    $(wildcard include/config/ip/conntrack/limit/per/ip.h) \
  include/linux/textsearch.h \
  include/linux/err.h \
  include/net/checksum.h \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/checksum.h \
  include/linux/in6.h \
  include/linux/dmaengine.h \
    $(wildcard include/config/dma/engine.h) \
    $(wildcard include/config/async/tx/dma.h) \
  include/linux/device.h \
    $(wildcard include/config/debug/devres.h) \
  include/linux/ioport.h \
  include/linux/klist.h \
  include/linux/pm.h \
    $(wildcard include/config/pm/sleep.h) \
  include/linux/semaphore.h \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/device.h \
  include/asm-generic/device.h \
  include/linux/pm_wakeup.h \
    $(wildcard include/config/pm.h) \
  include/linux/dma-mapping.h \
    $(wildcard include/config/have/dma/attrs.h) \
  include/linux/dma-attrs.h \
  include/linux/bug.h \
  include/linux/scatterlist.h \
    $(wildcard include/config/debug/sg.h) \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/scatterlist.h \
  include/linux/mm.h \
    $(wildcard include/config/mmu.h) \
    $(wildcard include/config/stack/growsup.h) \
    $(wildcard include/config/swap.h) \
    $(wildcard include/config/shmem.h) \
    $(wildcard include/config/debug/pagealloc.h) \
    $(wildcard include/config/hibernation.h) \
  include/linux/rbtree.h \
  include/linux/prio_tree.h \
  include/linux/debug_locks.h \
    $(wildcard include/config/debug/locking/api/selftests.h) \
  include/linux/mm_types.h \
    $(wildcard include/config/split/ptlock/cpus.h) \
    $(wildcard include/config/want/page/debug/flags.h) \
    $(wildcard include/config/mm/owner.h) \
    $(wildcard include/config/mmu/notifier.h) \
  include/linux/auxvec.h \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/auxvec.h \
  include/linux/page-debug-flags.h \
    $(wildcard include/config/page/poisoning.h) \
    $(wildcard include/config/page/debug/something/else.h) \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/mmu.h \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/pgtable.h \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/pgtable-32.h \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/fixmap.h \
  include/asm-generic/pgtable-nopmd.h \
  include/asm-generic/pgtable-nopud.h \
  include/asm-generic/pgtable.h \
  include/linux/page-flags.h \
    $(wildcard include/config/pageflags/extended.h) \
    $(wildcard include/config/have/mlocked/page/bit.h) \
    $(wildcard include/config/ia64/uncached/allocator.h) \
    $(wildcard include/config/s390.h) \
  include/linux/vmstat.h \
    $(wildcard include/config/vm/event/counters.h) \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/dma-mapping.h \
  include/linux/hrtimer.h \
    $(wildcard include/config/timer/stats.h) \
    $(wildcard include/config/high/res/timers.h) \
    $(wildcard include/config/debug/objects/timers.h) \
  include/linux/ktime.h \
    $(wildcard include/config/ktime/scalar.h) \
  include/linux/jiffies.h \
  include/linux/timex.h \
    $(wildcard include/config/no/hz.h) \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/timex.h \
  include/linux/if_packet.h \
  include/linux/timer.h \
  include/linux/debugobjects.h \
    $(wildcard include/config/debug/objects/free.h) \
  include/linux/delay.h \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/delay.h \
  include/linux/workqueue.h \
  include/net/net_namespace.h \
    $(wildcard include/config/ipv6.h) \
    $(wildcard include/config/ip/dccp.h) \
    $(wildcard include/config/net.h) \
  include/net/netns/core.h \
  include/net/netns/mib.h \
    $(wildcard include/config/xfrm/statistics.h) \
  include/net/snmp.h \
  include/linux/snmp.h \
  include/net/netns/unix.h \
  include/net/netns/packet.h \
  include/net/netns/ipv4.h \
    $(wildcard include/config/ip/multiple/tables.h) \
    $(wildcard include/config/ip/mroute.h) \
    $(wildcard include/config/ip/pimsm/v1.h) \
    $(wildcard include/config/ip/pimsm/v2.h) \
  include/net/inet_frag.h \
  include/net/netns/ipv6.h \
    $(wildcard include/config/ipv6/multiple/tables.h) \
    $(wildcard include/config/ipv6/mroute.h) \
    $(wildcard include/config/ipv6/pimsm/v2.h) \
  include/net/netns/dccp.h \
  include/net/netns/x_tables.h \
  include/linux/netfilter.h \
    $(wildcard include/config/netfilter/debug.h) \
    $(wildcard include/config/nf/nat/needed.h) \
  include/linux/in.h \
  include/net/flow.h \
  include/linux/proc_fs.h \
    $(wildcard include/config/proc/devicetree.h) \
    $(wildcard include/config/proc/kcore.h) \
  include/linux/fs.h \
    $(wildcard include/config/dnotify.h) \
    $(wildcard include/config/quota.h) \
    $(wildcard include/config/inotify.h) \
    $(wildcard include/config/security.h) \
    $(wildcard include/config/epoll.h) \
    $(wildcard include/config/debug/writecount.h) \
    $(wildcard include/config/file/locking.h) \
    $(wildcard include/config/auditsyscall.h) \
    $(wildcard include/config/block.h) \
    $(wildcard include/config/fs/xip.h) \
    $(wildcard include/config/migration.h) \
  include/linux/limits.h \
  include/linux/kdev_t.h \
  include/linux/dcache.h \
  include/linux/rculist.h \
  include/linux/path.h \
  include/linux/radix-tree.h \
  include/linux/pid.h \
  include/linux/capability.h \
    $(wildcard include/config/security/file/capabilities.h) \
  include/linux/fiemap.h \
  include/linux/quota.h \
  include/linux/dqblk_xfs.h \
  include/linux/dqblk_v1.h \
  include/linux/dqblk_v2.h \
  include/linux/dqblk_qtree.h \
  include/linux/nfs_fs_i.h \
  include/linux/nfs.h \
  include/linux/sunrpc/msg_prot.h \
  include/linux/magic.h \
  include/net/netns/conntrack.h \
    $(wildcard include/config/nf/conntrack/events.h) \
  include/linux/list_nulls.h \
  include/net/netns/xfrm.h \
  include/linux/xfrm.h \
  include/linux/seq_file_net.h \
  include/linux/seq_file.h \
  include/net/dsa.h \
  include/linux/interrupt.h \
    $(wildcard include/config/generic/irq/probe.h) \
    $(wildcard include/config/debug/shirq.h) \
  include/linux/irqreturn.h \
  include/linux/hardirq.h \
    $(wildcard include/config/virt/cpu/accounting.h) \
  include/linux/ftrace_irq.h \
    $(wildcard include/config/ftrace/nmi/enter.h) \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/hardirq.h \
  include/linux/irq.h \
    $(wildcard include/config/irq/per/cpu.h) \
    $(wildcard include/config/irq/release/method.h) \
    $(wildcard include/config/intr/remap.h) \
    $(wildcard include/config/generic/pending/irq.h) \
    $(wildcard include/config/numa/migrate/irq/desc.h) \
    $(wildcard include/config/generic/hardirqs/no//do/irq.h) \
    $(wildcard include/config/cpumasks/offstack.h) \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/irq.h \
    $(wildcard include/config/rtk/voip.h) \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/mach-generic/irq.h \
    $(wildcard include/config/i8259.h) \
    $(wildcard include/config/irq/cpu.h) \
    $(wildcard include/config/irq/cpu/rm7k.h) \
    $(wildcard include/config/irq/cpu/rm9k.h) \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/ptrace.h \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/isadep.h \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/irq_regs.h \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/hw_irq.h \
  include/linux/irq_cpustat.h \
  include/linux/sched.h \
    $(wildcard include/config/sched/debug.h) \
    $(wildcard include/config/detect/softlockup.h) \
    $(wildcard include/config/detect/hung/task.h) \
    $(wildcard include/config/core/dump/default/elf/headers.h) \
    $(wildcard include/config/bsd/process/acct.h) \
    $(wildcard include/config/taskstats.h) \
    $(wildcard include/config/audit.h) \
    $(wildcard include/config/inotify/user.h) \
    $(wildcard include/config/posix/mqueue.h) \
    $(wildcard include/config/keys.h) \
    $(wildcard include/config/user/sched.h) \
    $(wildcard include/config/schedstats.h) \
    $(wildcard include/config/task/delay/acct.h) \
    $(wildcard include/config/fair/group/sched.h) \
    $(wildcard include/config/rt/group/sched.h) \
    $(wildcard include/config/blk/dev/io/trace.h) \
    $(wildcard include/config/x86/ptrace/bts.h) \
    $(wildcard include/config/sysvipc.h) \
    $(wildcard include/config/rt/mutexes.h) \
    $(wildcard include/config/task/xacct.h) \
    $(wildcard include/config/cpusets.h) \
    $(wildcard include/config/cgroups.h) \
    $(wildcard include/config/futex.h) \
    $(wildcard include/config/fault/injection.h) \
    $(wildcard include/config/latencytop.h) \
    $(wildcard include/config/function/graph/tracer.h) \
    $(wildcard include/config/have/unstable/sched/clock.h) \
    $(wildcard include/config/preempt/bkl.h) \
    $(wildcard include/config/group/sched.h) \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/cputime.h \
  include/asm-generic/cputime.h \
  include/linux/sem.h \
  include/linux/ipc.h \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/ipcbuf.h \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/sembuf.h \
  include/linux/signal.h \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/signal.h \
    $(wildcard include/config/trad/signals.h) \
  include/asm-generic/signal-defs.h \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/sigcontext.h \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/siginfo.h \
  include/asm-generic/siginfo.h \
  include/linux/proportions.h \
  include/linux/percpu_counter.h \
  include/linux/seccomp.h \
    $(wildcard include/config/seccomp.h) \
  include/linux/rtmutex.h \
    $(wildcard include/config/debug/rt/mutexes.h) \
  include/linux/plist.h \
    $(wildcard include/config/debug/pi/list.h) \
  include/linux/resource.h \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/resource.h \
  include/asm-generic/resource.h \
  include/linux/task_io_accounting.h \
    $(wildcard include/config/task/io/accounting.h) \
  include/linux/latencytop.h \
  include/linux/cred.h \
  include/linux/key.h \
  include/linux/aio.h \
    $(wildcard include/config/aio.h) \
  include/linux/aio_abi.h \
  include/linux/inetdevice.h \
  include/linux/etherdevice.h \
    $(wildcard include/config/have/efficient/unaligned/access.h) \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/unaligned.h \
  include/linux/unaligned/be_struct.h \
  include/linux/unaligned/packed_struct.h \
  include/linux/unaligned/le_byteshift.h \
  include/linux/unaligned/generic.h \
  include/linux/pci.h \
    $(wildcard include/config/pci/iov.h) \
    $(wildcard include/config/pcieaspm.h) \
    $(wildcard include/config/pci/msi.h) \
    $(wildcard include/config/pci.h) \
    $(wildcard include/config/pci/legacy.h) \
    $(wildcard include/config/ht/irq.h) \
    $(wildcard include/config/pci/domains.h) \
    $(wildcard include/config/pci/mmconfig.h) \
  include/linux/pci_regs.h \
  include/linux/mod_devicetable.h \
  include/linux/io.h \
    $(wildcard include/config/has/ioport.h) \
  include/linux/pci_ids.h \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/pci.h \
    $(wildcard include/config/dma/need/pci/map/state.h) \
  include/asm-generic/pci-dma-compat.h \
  include/linux/ethtool.h \
  include/linux/mii.h \
  include/linux/if_vlan.h \
  include/linux/crc32.h \
  include/linux/bitrev.h \
  include/linux/rtc.h \
    $(wildcard include/config/rtc/intf/dev/uie/emul.h) \
  include/linux/cdev.h \
  include/linux/poll.h \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/poll.h \
  include/asm-generic/poll.h \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/target/bsp/bspchip.h \
    $(wildcard include/config/fpga/platform.h) \
    $(wildcard include/config/rtl/92d/support.h) \
    $(wildcard include/config/rtl/usb/ip/host/speedup.h) \
  drivers/net/rtl819x/version.h \
  include/net/rtl/rtl_types.h \
    $(wildcard include/config/rtl865x/nicdrv2.h) \
    $(wildcard include/config/rtl/dynamic/iram/mapping/for/wapi.h) \
    $(wildcard include/config/rtl/8196c/gw.h) \
    $(wildcard include/config/mp/psd/support.h) \
    $(wildcard include/config/rtl/819xdt.h) \
    $(wildcard include/config/rtl/log/debug.h) \
  include/linux/version.h \
  include/net/rtl/rtl_glue.h \
  drivers/net/rtl819x/AsicDriver/asicRegs.h \
  drivers/net/rtl819x/AsicDriver/rtl865xc_asicregs.h \
    $(wildcard include/config/rtl8196b.h) \
    $(wildcard include/config/rtl/8198c.h) \
    $(wildcard include/config/rtl865xc/bcut.h) \
    $(wildcard include/config/rtl865xb.h) \
    $(wildcard include/config/rtl/8196b.h) \
  drivers/net/rtl819x/AsicDriver/rtl865x_asicCom.h \
  drivers/net/rtl819x/AsicDriver/rtl865x_asicL2.h \
    $(wildcard include/config/rtl/enable/ratelimit/table.h) \
  drivers/net/rtl819x/AsicDriver/rtl865x_asicL3.h \
    $(wildcard include/config/rtl/hardware/multicast/cam.h) \
    $(wildcard include/config/rtl8198/revision/b.h) \
  drivers/net/rtl819x/common/mbuf.h \
  include/net/rtl/rtl_queue.h \
  drivers/net/rtl819x/common/rtl_errno.h \
  drivers/net/rtl819x/rtl865xc_swNic.h \
    $(wildcard include/config/rtl/nfjrom/mp.h) \
    $(wildcard include/config/rtl/8198/ap/root.h) \
    $(wildcard include/config/use/pcie/slot/0.h) \
    $(wildcard include/config/rtl/sdram/ge/32m.h) \
  drivers/net/rtl819x/common/rtl865x_vlan.h \
  include/net/rtl/rtl865x_netif.h \
    $(wildcard include/config/rtl/8196c/inic.h) \
    $(wildcard include/config/rtk/inband/host/hack.h) \
    $(wildcard include/config/rtl/89xxd.h) \
    $(wildcard include/config/rtl8186/kb/n.h) \
    $(wildcard include/config/efm/extender.h) \
    $(wildcard include/config/rtl/iptables2acl/patch.h) \
  include/net/rtl/rtl_types.h \
  drivers/net/rtl819x/common/rtl865x_netif_local.h \
  drivers/net/rtl819x/l2Driver/rtl865x_fdb.h \
    $(wildcard include/config/rtl865x/sync/l2.h) \
  include/net/rtl/rtl865x_fdb_api.h \
  drivers/net/rtl819x/l3Driver/rtl865x_ip.h \
  include/net/rtl/rtl865x_ip_api.h \
  drivers/net/rtl819x/l3Driver/rtl865x_nexthop.h \
  include/net/rtl/rtl865x_ppp.h \
  drivers/net/rtl819x/l3Driver/rtl865x_ppp_local.h \
  drivers/net/rtl819x/l3Driver/rtl865x_route.h \
  include/net/rtl/rtl865x_route_api.h \
  drivers/net/rtl819x/l3Driver/rtl865x_arp.h \
  include/net/rtl/rtl865x_arp_api.h \
    $(wildcard include/config/rtl/avoid/adding/wlan/pkt/to/hw/nat.h) \
  include/net/rtl/rtl865x_nat.h \
    $(wildcard include/config/rtl/inbound/collision/avoidance.h) \
    $(wildcard include/config/rtl/half/napt/acceleration.h) \
  include/net/rtl/rtl_nic.h \
  include/net/rtl/rtl865x_netif.h \
  include/linux/reboot.h \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/emergency-restart.h \
  include/asm-generic/emergency-restart.h \
  include/net/rtl/rtl865x_igmpsnooping.h \
  include/linux/ip.h \
  include/linux/ipv6.h \
    $(wildcard include/config/ipv6/privacy.h) \
    $(wildcard include/config/ipv6/router/pref.h) \
    $(wildcard include/config/ipv6/route/info.h) \
    $(wildcard include/config/ipv6/optimistic/dad.h) \
    $(wildcard include/config/ipv6/mip6.h) \
    $(wildcard include/config/ipv6/subtrees.h) \
  include/linux/icmpv6.h \
  include/linux/tcp.h \
    $(wildcard include/config/tcp/md5sig.h) \
  include/net/sock.h \
  include/linux/security.h \
    $(wildcard include/config/security/path.h) \
    $(wildcard include/config/security/network.h) \
    $(wildcard include/config/security/network/xfrm.h) \
    $(wildcard include/config/securityfs.h) \
  include/linux/binfmts.h \
  include/linux/shm.h \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/shmparam.h \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/shmbuf.h \
  include/linux/msg.h \
  /home/rtlac/RTL3.4/rtl819x_3.4.6.5/linux-2.6.30/arch/rlx/include/asm/msgbuf.h \
    $(wildcard include/config/cpu/little/endian.h) \
  include/linux/filter.h \
  include/linux/rculist_nulls.h \
  include/net/dst.h \
    $(wildcard include/config/net/cls/route.h) \
  include/linux/rtnetlink.h \
  include/linux/netlink.h \
  include/linux/if_link.h \
  include/linux/if_addr.h \
  include/linux/neighbour.h \
  include/net/neighbour.h \
  include/net/rtnetlink.h \
  include/net/netlink.h \
  include/net/inet_connection_sock.h \
  include/net/inet_sock.h \
  include/linux/jhash.h \
  include/net/request_sock.h \
  include/net/netns/hash.h \
  include/net/inet_timewait_sock.h \
  include/net/tcp_states.h \
  include/net/timewait_sock.h \
  include/linux/udp.h \
  include/net/rtl/rtl865x_multicast.h \
    $(wildcard include/config/rtl/hw/mcast/patch/for/mac.h) \

drivers/net/rtl819x/rtl_nic.o: $(deps_drivers/net/rtl819x/rtl_nic.o)

$(deps_drivers/net/rtl819x/rtl_nic.o):

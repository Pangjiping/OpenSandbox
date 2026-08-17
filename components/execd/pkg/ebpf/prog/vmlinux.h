#if defined(__TARGET_ARCH_arm64)
#include "vmlinux_6_14_0_arm.h"
#elif defined(__TARGET_ARCH_x86)
#include "vmlinux_6_14_0.h"
#else
#error "opensandbox ebpf audit: unsupported architecture"
#endif

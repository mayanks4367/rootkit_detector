#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

SEC("kprobe/sys_execve")
int detect_syscall_hook(struct pt_regs *ctx) {
    u64 addr = PT_REGS_PARM1(ctx);
    
    // Known-good execve address (you'll calculate this)
    u64 expected = 0xffffffff81234567;
    
    if (addr != expected) {
        bpf_printk("SYSCALL HOOK: execve -> 0x%lx", addr);
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, 
                             &addr, sizeof(addr));
    }
    return 0;
}

char _license[] SEC("license") = "GPL";


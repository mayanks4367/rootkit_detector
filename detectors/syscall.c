#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/ptrace.h>
#include <linux/sched.h>

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 256

// Event types
enum event_type {
    EVENT_SYSCALL_HOOK = 1,
    EVENT_PROCESS_HIDE = 2,
    EVENT_FILE_HIDE = 3,
    EVENT_MODULE_TAMPER = 4,
};

// Event structure sent to userspace
struct event {
    __u32 type;
    __u32 pid;
    __u64 timestamp;
    char comm[TASK_COMM_LEN];
    char details[128];
};

// Ring buffer for events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Process tracking
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u64);
} process_cache SEC(".maps");

// Timing for file operations
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u64);
} file_timing SEC(".maps");

// Helper function to send event
static __always_inline void send_event(__u32 type, __u32 pid, const char *comm, const char *details) {
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return;
    
    e->type = type;
    e->pid = pid;
    e->timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    if (details) {
        __builtin_memcpy(&e->details, details, sizeof(e->details) - 1);
        e->details[sizeof(e->details) - 1] = '\0';
    } else {
        __builtin_memset(&e->details, 0, sizeof(e->details));
    }
    
    bpf_ringbuf_submit(e, 0);
}

// Process hiding detection
SEC("kprobe/do_fork")
int detect_process_hide(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 current_time = bpf_ktime_get_ns();
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    
    // Store process creation time
    bpf_map_update_elem(&process_cache, &pid, &current_time, BPF_ANY);
    
    // Count processes for anomaly detection
    __u32 key = 0;
    __u64 *count = bpf_map_lookup_elem(&process_cache, &key);
    __u64 new_count = count ? *count + 1 : 1;
    bpf_map_update_elem(&process_cache, &key, &new_count, BPF_ANY);
    
    // Alert on rapid process creation
    if (new_count > 100) {
        send_event(EVENT_PROCESS_HIDE, pid, comm, "Rapid process creation detected");
    }
    
    return 0;
}

// File hiding detection via timing analysis
SEC("kprobe/filldir64")
int detect_file_hide_start(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 key = (__u64)pid << 32;
    __u64 start_time = bpf_ktime_get_ns();
    
    bpf_map_update_elem(&file_timing, &key, &start_time, BPF_ANY);
    
    return 0;
}

SEC("kretprobe/filldir64")
int detect_file_hide_end(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 end_time = bpf_ktime_get_ns();
    __u64 key = (__u64)pid << 32;
    
    __u64 *start_time = bpf_map_lookup_elem(&file_timing, &key);
    if (start_time) {
        __u64 duration = end_time - *start_time;
        
        // If filldir64 takes unusually long, might be filtering entries
        if (duration > 1000000) { // 1ms threshold
            char comm[TASK_COMM_LEN];
            bpf_get_current_comm(&comm, sizeof(comm));
            send_event(EVENT_FILE_HIDE, pid, comm, "Unusual directory enumeration delay");
        }
        
        bpf_map_delete_elem(&file_timing, &key);
    }
    
    return 0;
}

// Module tampering detection
SEC("kprobe/load_module")
int detect_module_tamper(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    
    // Check if suspicious process is loading modules
    if (__builtin_memcmp(comm, "insmod", 6) != 0 && 
        __builtin_memcmp(comm, "modprobe", 8) != 0) {
        send_event(EVENT_MODULE_TAMPER, pid, comm, "Unexpected module loading detected");
    }
    
    return 0;
}

// Process execution monitoring
SEC("kprobe/sys_execve")
int monitor_execve(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    
    // Basic monitoring - in real implementation would read filename
    // For simplicity, just monitor execve calls from suspicious processes
    if (__builtin_memcmp(comm, "bash", 4) != 0 && 
        __builtin_memcmp(comm, "sh", 2) != 0 &&
        __builtin_memcmp(comm, "sshd", 4) != 0) {
        send_event(EVENT_PROCESS_HIDE, pid, comm, "Process execution monitored");
    }
    
    return 0;
}

// Syscall table integrity check
SEC("kprobe/do_syscall_64")
int detect_syscall_hook(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    
    // Monitor syscall patterns - simplified for eBPF
    // In real implementation would analyze syscall table integrity
    
    // Alert on suspicious processes making many syscalls
    static __u32 call_count = 0;
    call_count++;
    
    if (call_count % 1000 == 0) {
        send_event(EVENT_SYSCALL_HOOK, pid, comm, "High syscall activity detected");
    }
    
    return 0;
}

char _license[] SEC("license") = "GPL";


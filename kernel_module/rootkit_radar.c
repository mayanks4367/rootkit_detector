// SPDX-License-Identifier: GPL-2.0
/*
 * rootkit_radar.c — Linux Kernel Module for rootkit detection.
 *
 * Detection vectors:
 *   1. Syscall Hook Detection  — scans sys_call_table entries against kernel
 *                                text segment boundaries to find hijacked
 *                                function pointers.
 *   2. Hidden Process (DKOM)   — cross-references for_each_process() task list
 *                                against visible /proc PIDs via kernel side.
 *   3. Hidden Module Detection — walks the kset list and compares against the
 *                                modules list to find unlinked stealth modules.
 *
 * Events are delivered to userspace via a Netlink multicast socket (group
 * ROOTKIT_RADAR_NLGROUP).  A periodic timer (default 10 s) triggers each scan.
 * RCU read locks are used throughout; no heavy spinlocks are held across scans.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/pid.h>
#include <linux/fs.h>
#include <linux/kprobes.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/workqueue.h>
#include <linux/jiffies.h>
#include <linux/kallsyms.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/rcupdate.h>
#include <linux/list.h>
#include <linux/kobject.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <net/sock.h>
#include <linux/unistd.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("rootkit-radar");
MODULE_DESCRIPTION("Kernel-space rootkit detection engine");
MODULE_VERSION("1.0.0");

/* ─── Netlink configuration ──────────────────────────────────────────────── */
#define NETLINK_ROOTKIT_RADAR   31          /* custom netlink protocol number */
#define ROOTKIT_RADAR_NLGROUP    1          /* multicast group                */
#define NL_MAX_PAYLOAD         4096

/* ─── Scan interval ──────────────────────────────────────────────────────── */
#define SCAN_INTERVAL_SECS     10
#define MAX_PIDS               65536

/* ─── Event types (mirrored in the Rust daemon) ──────────────────────────── */
#define EVT_SYSCALL_HOOK       1
#define EVT_HIDDEN_PROCESS     2
#define EVT_HIDDEN_MODULE      3

/* ─── Wire-format event (fixed size, no padding surprises) ──────────────── */
struct rr_event {
    __u32 event_type;           /* EVT_* constants above                     */
    __u32 pid;                  /* relevant PID (0 if not applicable)         */
    __s64 timestamp_ns;         /* ktime_get_real_ns()                        */
    __u32 certainty;            /* 0=low, 1=high, 2=critical (verified)      */
    char  description[252];     /* human-readable detail                      */
};

/* ─── Globals ────────────────────────────────────────────────────────────── */
static struct sock          *nl_sock;
static struct delayed_work   scan_work;

/* Persistence tracking for hidden PIDs to avoid race-condition false positives */
static unsigned long *prev_hidden_pids;
/* Tracking CPU time to detect active hidden processes ("Ghost Catcher") */
static u64 *prev_cpu_times;

/* Typedef for kallsyms_lookup_name */
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t kallsyms_lookup_name_fn;

static unsigned long _stext_addr;
static unsigned long _etext_addr;

/* Resolved at init via kallsyms */
static unsigned long        *sys_call_table_ptr;

/* Saved baseline addresses for the syscalls we watch */
#define NR_WATCHED_SYSCALLS  10
static const int watched_nrs[NR_WATCHED_SYSCALLS] = {
    __NR_read,
    __NR_write,
    __NR_execve,
    __NR_getdents64,
    __NR_kill,
    __NR_ptrace,
    __NR_openat,
    __NR_socket,
    __NR_finit_module,
    __NR_init_module,
};
static unsigned long baseline_addrs[NR_WATCHED_SYSCALLS];

/* ─── Netlink helpers ────────────────────────────────────────────────────── */

/**
 * nl_send_event() - Broadcast a detection event to all Netlink subscribers.
 * @evt: Pointer to the event to send.
 */
static void nl_send_event(const struct rr_event *evt)
{
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    int    msg_size = sizeof(struct rr_event);
    int    ret;

    if (!nl_sock)
        return;

    skb = nlmsg_new(msg_size, GFP_ATOMIC);
    if (!skb) {
        pr_warn("rootkit_radar: failed to allocate skb for netlink event\n");
        return;
    }

    nlh = nlmsg_put(skb, 0, 0, NLMSG_DONE, msg_size, 0);
    if (!nlh) {
        kfree_skb(skb);
        return;
    }

    memcpy(nlmsg_data(nlh), evt, msg_size);

    ret = nlmsg_multicast(nl_sock, skb, 0, ROOTKIT_RADAR_NLGROUP, GFP_ATOMIC);
    if (ret < 0 && ret != -ESRCH)
        pr_debug("rootkit_radar: nlmsg_multicast error %d\n", ret);
}

/**
 * emit_event() - Fill an rr_event and broadcast it.
 */
static void emit_event(u32 type, u32 pid, u32 certainty, const char *fmt, ...)
{
    struct rr_event evt = {};
    va_list args;

    evt.event_type   = type;
    evt.pid          = pid;
    evt.certainty    = certainty;
    evt.timestamp_ns = ktime_get_real_ns();

    va_start(args, fmt);
    vsnprintf(evt.description, sizeof(evt.description), fmt, args);
    va_end(args);

    nl_send_event(&evt);
    pr_info("rootkit_radar: [EVT %u] [CERT %u] %s\n", type, certainty, evt.description);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Detection Vector 1: Syscall Hook Detection (Improved)
 * ═══════════════════════════════════════════════════════════════════════════
 */

static void scan_syscall_hooks(void)
{
    int    i;

    if (!sys_call_table_ptr)
        return;

    rcu_read_lock();

    for (i = 0; i < NR_WATCHED_SYSCALLS; i++) {
        unsigned long current_addr;
        int           nr = watched_nrs[i];
        u8            instr[5];
        bool          bad_instr = false;

        current_addr = sys_call_table_ptr[nr];

        /* Check 1: has the pointer changed from our baseline? */
        if (current_addr != baseline_addrs[i]) {
            /* 
             * Check 2: does the pointer lie outside the kernel text segment?
             * OR does it start with suspicious instructions (JMP/INT3)?
             */
            if (copy_from_kernel_nofault(instr, (void *)current_addr, 5) == 0) {
                if (instr[0] == 0xE9 || instr[0] == 0xCC) { /* JMP or INT3 */
                    bad_instr = true;
                }
            }

            if (current_addr < _stext_addr || current_addr >= _etext_addr || bad_instr) {
                emit_event(EVT_SYSCALL_HOOK, 0, 2, /* 2 = Critical */
                    "sys_call_table[%d] HOOKED: addr=0x%lx, outside_text=%d, bad_instr=%d",
                    nr, current_addr, 
                    (current_addr < _stext_addr || current_addr >= _etext_addr),
                    bad_instr);
            } else {
                /* Changed but still in text and no bad instr -> Low certainty */
                emit_event(EVT_SYSCALL_HOOK, 0, 0,
                    "sys_call_table[%d] changed: 0x%lx -> 0x%lx (still in text)",
                    nr, baseline_addrs[i], current_addr);
            }
        }
        cond_resched();
    }

    rcu_read_unlock();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Detection Vector 2: Hidden Process Detection (The "Ghost Catcher")
 * ═══════════════════════════════════════════════════════════════════════════
 */

static void scan_hidden_processes(void)
{
    unsigned long *kernel_pids;
    unsigned long *curr_hidden_pids;
    struct task_struct *task;
    struct pid    *p;
    int pid;

    kernel_pids = kzalloc(BITS_TO_LONGS(MAX_PIDS) * sizeof(unsigned long), GFP_KERNEL);
    curr_hidden_pids = kzalloc(BITS_TO_LONGS(MAX_PIDS) * sizeof(unsigned long), GFP_KERNEL);
    if (!kernel_pids || !curr_hidden_pids) {
        kfree(kernel_pids);
        kfree(curr_hidden_pids);
        return;
    }

    /* --- Phase 1: collect kernel-visible PIDs under RCU --- */
    rcu_read_lock();
    for_each_process(task) {
        if (task->pid > 0 && task->pid < MAX_PIDS)
            set_bit(task->pid, kernel_pids);
    }
    rcu_read_unlock();

    /* --- Phase 2: check each active PID in the hash table --- */
    for (pid = 2; pid < MAX_PIDS; pid++) {
        p = find_get_pid(pid);
        if (!p)
            continue;

        rcu_read_lock();
        task = pid_task(p, PIDTYPE_PID);
        if (task) {
            /* Check if PID is in hash but missing from task list */
            if (!test_bit(pid, kernel_pids) && !(task->flags & PF_KTHREAD)) {
                u64 curr_cpu_time = task->utime + task->stime;
                u32 certainty = 0;

                set_bit(pid, curr_hidden_pids);

                /* 
                 * Persistence + Activity Check:
                 * 1. Did it persist since the last scan?
                 * 2. Has it consumed CPU time since the last scan? (Ghost detection)
                 */
                if (prev_hidden_pids && test_bit(pid, prev_hidden_pids)) {
                    certainty = 1; /* High: Persists */
                    if (prev_cpu_times && curr_cpu_time > prev_cpu_times[pid]) {
                        certainty = 2; /* Critical: Persists AND Active */
                    }
                }

                if (certainty > 0) {
                    char comm[TASK_COMM_LEN];
                    strscpy(comm, task->comm, sizeof(comm));
                    emit_event(EVT_HIDDEN_PROCESS, (u32)pid, certainty,
                        "PID %d (%s) hidden: persists=%d, ghost_active=%d",
                        pid, comm, (certainty >= 1), (certainty == 2));
                }

                if (prev_cpu_times)
                    prev_cpu_times[pid] = curr_cpu_time;
            }
        }
        rcu_read_unlock();

        put_pid(p);
        if (pid % 1024 == 0)
            cond_resched();
    }

    /* Update persistence tracker */
    if (prev_hidden_pids) {
        memcpy(prev_hidden_pids, curr_hidden_pids, BITS_TO_LONGS(MAX_PIDS) * sizeof(unsigned long));
    } else {
        prev_hidden_pids = curr_hidden_pids;
        curr_hidden_pids = NULL;
    }

    kfree(kernel_pids);
    kfree(curr_hidden_pids);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Detection Vector 3: Hidden Module Detection
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Strategy: Walk the global kernel module kset (module_kset) to enumerate
 * all kobjects that the kernel knows about at the driver model level.
 * Then cross-reference with the modules linked list (which lsmod walks).
 * A module that has unlinked itself from the modules list (common rootkit
 * technique) will still appear in the kset but not in the list.
 *
 * RCU is used for the modules list walk; a kset spin_lock is used briefly
 * to snapshot the kset list (kernel internal — unavoidable but very short).
 */

/* Resolved via kallsyms at init */
static struct kset *module_kset_ptr;
/* modules list head, also resolved via kallsyms */
static struct list_head *modules_list_ptr;

static void scan_hidden_modules(void)
{
    struct kobject  *kobj;
    struct list_head *pos;
    char (*kset_names)[MODULE_NAME_LEN];
    int    kset_count = 0;
    int    i;

    if (!module_kset_ptr || !modules_list_ptr)
        return;

    kset_names = kmalloc_array(256, MODULE_NAME_LEN, GFP_KERNEL);
    if (!kset_names)
        return;

    /* --- Phase 1: snapshot kset member names (brief spinlock) --- */
    spin_lock(&module_kset_ptr->list_lock);
    list_for_each_entry(kobj, &module_kset_ptr->list, entry) {
        if (kset_count >= 256)
            break;
        if (kobj->name)
            strscpy(kset_names[kset_count++], kobj->name, MODULE_NAME_LEN);
    }
    spin_unlock(&module_kset_ptr->list_lock);

    /* --- Phase 2: for each kset name, check if it appears in modules list --- */
    for (i = 0; i < kset_count; i++) {
        bool found = false;
        struct module *mod;

        /* Ignore our own module and common noise */
        if (strcmp(kset_names[i], "rootkit_radar") == 0)
            continue;

        rcu_read_lock();
        list_for_each(pos, modules_list_ptr) {
            mod = list_entry(pos, struct module, list);
            if (strncmp(mod->name, kset_names[i], MODULE_NAME_LEN) == 0) {
                found = true;
                break;
            }
        }
        rcu_read_unlock();

        if (!found && strlen(kset_names[i]) > 0) {
            emit_event(EVT_HIDDEN_MODULE, 0, 2, /* 2 = Critical */
                "Module '%s' hidden (unlinked from modules list)", kset_names[i]);
        }
        cond_resched();
    }

    kfree(kset_names);
}

/* ─── Periodic scan worker ──────────────────────────────────────── */

static void run_all_scans(struct work_struct *work)
{
    scan_syscall_hooks();
    scan_hidden_processes();
    scan_hidden_modules();

    /* Re-arm the worker */
    schedule_delayed_work(&scan_work, SCAN_INTERVAL_SECS * HZ);
}

/* ─── Module init / exit ─────────────────────────────────────────────────── */

static struct netlink_kernel_cfg nl_cfg = {
    .groups = ROOTKIT_RADAR_NLGROUP,
    .flags  = NL_CFG_F_NONROOT_RECV,
};

static int __init rootkit_radar_init(void)
{
    int i;
    struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };

    pr_info("rootkit_radar: initialising advanced detection engine\n");

    /* ── 0. Resolve kallsyms_lookup_name ── */
    if (register_kprobe(&kp) < 0) {
        pr_err("rootkit_radar: failed to resolve kallsyms_lookup_name\n");
        return -ENOENT;
    }
    kallsyms_lookup_name_fn = (kallsyms_lookup_name_t)kp.addr;
    unregister_kprobe(&kp);

    if (!kallsyms_lookup_name_fn) return -ENOENT;

    _stext_addr = kallsyms_lookup_name_fn("_stext");
    _etext_addr = kallsyms_lookup_name_fn("_etext");

    /* ── 1. Resolve sys_call_table ── */
    sys_call_table_ptr = (unsigned long *)kallsyms_lookup_name_fn("sys_call_table");
    if (!sys_call_table_ptr) return -ENOENT;

    for (i = 0; i < NR_WATCHED_SYSCALLS; i++)
        baseline_addrs[i] = sys_call_table_ptr[watched_nrs[i]];

    /* ── 2. Resolve module_kset and modules list ── */
    {
        struct kset **module_kset_ptr_ptr = (struct kset **)
            kallsyms_lookup_name_fn("module_kset");
        if (module_kset_ptr_ptr)
            module_kset_ptr = *module_kset_ptr_ptr;
    }
    modules_list_ptr = (struct list_head *)kallsyms_lookup_name_fn("modules");

    /* ── 3. Initialize tracking structures ── */
    prev_cpu_times = kvzalloc(MAX_PIDS * sizeof(u64), GFP_KERNEL);
    if (!prev_cpu_times) return -ENOMEM;

    /* ── 4. Create Netlink socket ── */
    nl_sock = netlink_kernel_create(&init_net, NETLINK_ROOTKIT_RADAR, &nl_cfg);
    if (!nl_sock) {
        kvfree(prev_cpu_times);
        return -ENOMEM;
    }

    /* ── 5. Start periodic scan worker ── */
    INIT_DELAYED_WORK(&scan_work, run_all_scans);
    schedule_delayed_work(&scan_work, SCAN_INTERVAL_SECS * HZ);

    pr_info("rootkit_radar: armed and ready\n");
    return 0;
}

static void __exit rootkit_radar_exit(void)
{
    cancel_delayed_work_sync(&scan_work);

    if (nl_sock)
        netlink_kernel_release(nl_sock);

    if (prev_hidden_pids)
        kfree(prev_hidden_pids);
    
    if (prev_cpu_times)
        kvfree(prev_cpu_times);

    pr_info("rootkit_radar: unloaded\n");
}

module_init(rootkit_radar_init);
module_exit(rootkit_radar_exit);

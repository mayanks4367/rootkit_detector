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
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <linux/kallsyms.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/rcupdate.h>
#include <linux/list.h>
#include <linux/kset.h>
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

/* ─── Event types (mirrored in the Rust daemon) ──────────────────────────── */
#define EVT_SYSCALL_HOOK       1
#define EVT_HIDDEN_PROCESS     2
#define EVT_HIDDEN_MODULE      3

/* ─── Wire-format event (fixed size, no padding surprises) ──────────────── */
struct rr_event {
    __u32 event_type;           /* EVT_* constants above                     */
    __u32 pid;                  /* relevant PID (0 if not applicable)         */
    __s64 timestamp_ns;         /* ktime_get_real_ns()                        */
    char  description[256];     /* human-readable detail                      */
};

/* ─── Globals ────────────────────────────────────────────────────────────── */
static struct sock          *nl_sock;
static struct timer_list     scan_timer;

/* Resolved at init via kallsyms */
static unsigned long        *sys_call_table_ptr;

/* Saved baseline addresses for the syscalls we watch */
#define NR_WATCHED_SYSCALLS  4
static const int watched_nrs[NR_WATCHED_SYSCALLS] = {
    __NR_read,
    __NR_write,
    __NR_execve,
    __NR_getdents64,
};
static unsigned long baseline_addrs[NR_WATCHED_SYSCALLS];

/* ─── Netlink helpers ────────────────────────────────────────────────────── */

/**
 * nl_send_event() - Broadcast a detection event to all Netlink subscribers.
 * @evt: Pointer to the event to send.
 *
 * Uses nlmsg_new / nlmsg_put / genlmsg_multicast.  If the socket or skb
 * allocation fails we simply log and return; detection must never crash the
 * host.
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
static void emit_event(u32 type, u32 pid, const char *fmt, ...)
{
    struct rr_event evt = {};
    va_list args;

    evt.event_type   = type;
    evt.pid          = pid;
    evt.timestamp_ns = ktime_get_real_ns();

    va_start(args, fmt);
    vsnprintf(evt.description, sizeof(evt.description), fmt, args);
    va_end(args);

    nl_send_event(&evt);
    pr_info("rootkit_radar: [EVT %u] %s\n", type, evt.description);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Detection Vector 1: Syscall Hook Detection
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Strategy: At module load we snapshot the addresses stored in sys_call_table
 * for the syscalls we care about.  On each periodic scan we re-read those
 * slots and compare against:
 *   a) The saved baseline (pointer has changed → hook installed after us).
 *   b) The kernel text segment [_stext, _etext).  If the current pointer
 *      falls outside that range it is almost certainly a hooked trampoline
 *      in a module or injected page.
 *
 * We access sys_call_table read-only inside an RCU read-side critical section.
 * No write lock is needed because we are not restoring; only alerting.
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

        current_addr = sys_call_table_ptr[nr];

        /* Check 1: has the pointer changed from our baseline? */
        if (current_addr != baseline_addrs[i]) {
            emit_event(EVT_SYSCALL_HOOK, 0,
                "sys_call_table[%d] pointer changed: was 0x%lx, now 0x%lx",
                nr, baseline_addrs[i], current_addr);
        }

        /* Check 2: does the pointer lie outside the kernel text segment? */
        if (current_addr < (unsigned long)_stext ||
            current_addr >= (unsigned long)_etext) {
            emit_event(EVT_SYSCALL_HOOK, 0,
                "sys_call_table[%d]=0x%lx is OUTSIDE kernel text "
                "[0x%lx, 0x%lx) — likely hook trampoline",
                nr, current_addr,
                (unsigned long)_stext,
                (unsigned long)_etext);
        }
    }

    rcu_read_unlock();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Detection Vector 2: Hidden Process Detection (DKOM)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Strategy: Walk the kernel task_struct list with for_each_process() and
 * collect all PIDs visible at kernel level.  Then iterate /proc numerically
 * to collect PIDs visible in procfs.  Any PID present in the kernel list but
 * absent from /proc is DKOM-hidden.
 *
 * We use RCU for the task list traversal (held only during the walk) and
 * release it before the /proc lookup to avoid lock-order issues.
 *
 * Limitation: namespaced containers may legitimately show a process in the
 * global task list but not in the current /proc namespace.  A production
 * deployment should compare within the same PID namespace.  This
 * implementation targets the host (init_pid_ns) for simplicity.
 */

#define MAX_PIDS  65536

static void scan_hidden_processes(void)
{
    /* Bitmap of PIDs seen in the kernel task list */
    unsigned long *kernel_pids;
    struct task_struct *task;
    struct pid    *p;

    kernel_pids = kzalloc(BITS_TO_LONGS(MAX_PIDS) * sizeof(unsigned long),
                          GFP_KERNEL);
    if (!kernel_pids) {
        pr_warn("rootkit_radar: DKOM scan: failed to alloc pid bitmap\n");
        return;
    }

    /* --- Phase 1: collect kernel-visible PIDs under RCU --- */
    rcu_read_lock();
    for_each_process(task) {
        pid_t pid = task->pid;
        if (pid > 0 && pid < MAX_PIDS)
            set_bit(pid, kernel_pids);
    }
    rcu_read_unlock();

    /* --- Phase 2: check each kernel PID against procfs --- */
    for (int pid = 2; pid < MAX_PIDS; pid++) {
        if (!test_bit(pid, kernel_pids))
            continue;

        /*
         * find_get_pid() does a quick lookup in the pid hash table.
         * If it returns NULL the PID has already exited — not suspicious.
         * We then try to find the corresponding /proc/<pid> dentry.
         */
        p = find_get_pid(pid);
        if (!p)
            continue;

        {
            /* Try to look up /proc/<pid>. Use d_lookup on proc root. */
            struct dentry *proc_root = NULL;
            struct dentry *pid_dentry = NULL;
            char   pid_str[16];
            struct qstr  q;

            proc_root = proc_self->d_sb ? proc_self->d_sb->s_root : NULL;

            snprintf(pid_str, sizeof(pid_str), "%d", pid);
            q.name = pid_str;
            q.len  = strlen(pid_str);
            q.hash = full_name_hash(proc_root, pid_str, q.len);

            if (proc_root) {
                pid_dentry = d_lookup(proc_root, &q);
                if (!pid_dentry) {
                    /* PID is in task list but not findable in /proc → DKOM */
                    emit_event(EVT_HIDDEN_PROCESS, (u32)pid,
                        "PID %d present in kernel task_struct list but "
                        "absent from /proc — possible DKOM rootkit", pid);
                } else {
                    dput(pid_dentry);
                }
            }
        }

        put_pid(p);
    }

    kfree(kernel_pids);
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
    char   kset_names[256][MODULE_NAME_LEN];
    int    kset_count = 0;
    int    i;

    if (!module_kset_ptr || !modules_list_ptr)
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
            emit_event(EVT_HIDDEN_MODULE, 0,
                "Module '%s' present in kset but absent from modules list "
                "— possible stealth module (self-unlinked)", kset_names[i]);
        }
    }
}

/* ─── Periodic scan timer callback ──────────────────────────────────────── */

static void run_all_scans(struct timer_list *t)
{
    scan_syscall_hooks();
    scan_hidden_processes();
    scan_hidden_modules();

    /* Re-arm the timer */
    mod_timer(&scan_timer, jiffies + SCAN_INTERVAL_SECS * HZ);
}

/* ─── Module init / exit ─────────────────────────────────────────────────── */

static struct netlink_kernel_cfg nl_cfg = {
    .groups = ROOTKIT_RADAR_NLGROUP,
    .flags  = NL_CFG_F_NONROOT_RECV,
};

static int __init rootkit_radar_init(void)
{
    int i;

    pr_info("rootkit_radar: initialising detection engine\n");

    /* ── 1. Resolve sys_call_table ── */
    sys_call_table_ptr = (unsigned long *)
        kallsyms_lookup_name("sys_call_table");
    if (!sys_call_table_ptr) {
        pr_err("rootkit_radar: cannot resolve sys_call_table via kallsyms\n");
        return -ENOENT;
    }

    /* Snapshot baseline syscall addresses */
    for (i = 0; i < NR_WATCHED_SYSCALLS; i++)
        baseline_addrs[i] = sys_call_table_ptr[watched_nrs[i]];

    pr_info("rootkit_radar: syscall baseline captured (%d entries)\n",
            NR_WATCHED_SYSCALLS);

    /* ── 2. Resolve module_kset and modules list ── */
    module_kset_ptr  = (struct kset *)
        kallsyms_lookup_name("module_kset");
    modules_list_ptr = (struct list_head *)
        kallsyms_lookup_name("modules");

    if (!module_kset_ptr || !modules_list_ptr)
        pr_warn("rootkit_radar: module scan unavailable "
                "(kallsyms resolution failed)\n");

    /* ── 3. Create Netlink socket ── */
    nl_sock = netlink_kernel_create(&init_net, NETLINK_ROOTKIT_RADAR, &nl_cfg);
    if (!nl_sock) {
        pr_err("rootkit_radar: failed to create netlink socket\n");
        return -ENOMEM;
    }

    /* ── 4. Start periodic scan timer ── */
    timer_setup(&scan_timer, run_all_scans, 0);
    mod_timer(&scan_timer, jiffies + SCAN_INTERVAL_SECS * HZ);

    pr_info("rootkit_radar: armed — scanning every %d seconds\n",
            SCAN_INTERVAL_SECS);
    return 0;
}

static void __exit rootkit_radar_exit(void)
{
    del_timer_sync(&scan_timer);

    if (nl_sock)
        netlink_kernel_release(nl_sock);

    pr_info("rootkit_radar: unloaded\n");
}

module_init(rootkit_radar_init);
module_exit(rootkit_radar_exit);

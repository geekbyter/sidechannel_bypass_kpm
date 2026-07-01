/*
 * sidechannel_bypass_kpm v0.5.1
 *
 * Uses hook_syscalln (syscall table hook) to intercept faccessat/newfstatat/
 * unlinkat at the syscall dispatch level. Injects CNTVCT-based delay on
 * unlinkat to compensate for sucompat overhead, defeating Hunter's
 * side-channel timing detection.
 */

#include <ktypes.h>
#include <kpmodule.h>
#include <hook.h>
#include <syscall.h>
#include <kallsyms.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <asm/current.h>

#ifndef MODULE_VERSION
#define MODULE_VERSION "0.5.1"
#endif

#define LOG_TAG "SCBypass"
#define log_info(...) pr_info(LOG_TAG ": " __VA_ARGS__)
#define log_warn(...) pr_warn(LOG_TAG ": " __VA_ARGS__)

KPM_NAME("sidechannel_bypass_kpm");
KPM_VERSION(MODULE_VERSION);
KPM_LICENSE("GPLv3");
KPM_AUTHOR("geekbyte");
KPM_DESCRIPTION("Bypass Hunter side-channel syscall timing detection");

#define APP_UID_MIN 10000

/* Default delay: 2 CNTVCT cycles ~= 104ns at 19.2MHz (Qualcomm arch timer).
 * Tunable via "delay=<cycles>" module argument. */
#define DEFAULT_DELAY_CYCLES 2

static unsigned long g_delay_cycles = DEFAULT_DELAY_CYCLES;

/* Track which hooks were installed for proper cleanup */
static int g_hooked_faccessat = 0;
static int g_hooked_newfstatat = 0;
static int g_hooked_unlinkat = 0;

/* Syscall numbers (ARM64) */
#ifndef __NR_faccessat
#define __NR_faccessat 48
#endif
#ifndef __NR3264_fstatat
#define __NR3264_fstatat 79
#endif
#ifndef __NR_unlinkat
#define __NR_unlinkat 35
#endif

static inline uid_t get_current_uid(void)
{
    struct task_struct *task = current;
    if (!task || task_struct_offset.cred_offset <= 0 ||
        cred_offset.uid_offset <= 0)
        return 0;
    struct cred *cred = *(struct cred **)((uintptr_t)task +
                                          task_struct_offset.cred_offset);
    if (!cred)
        return 0;
    return *(uid_t *)((uintptr_t)cred + cred_offset.uid_offset);
}

/* CNTVCT-based busy-wait delay (wall-clock time, CPU-frequency independent) */
static inline void cntvct_delay(unsigned long cycles)
{
    unsigned long start, now;
    asm volatile("mrs %0, cntvct_el0" : "=r"(start));
    do {
        asm volatile("mrs %0, cntvct_el0" : "=r"(now));
    } while ((now - start) < cycles);
}

static inline unsigned long read_cntvct(void)
{
    unsigned long v;
    asm volatile("mrs %0, cntvct_el0" : "=r"(v));
    return v;
}

/* hook_syscalln callbacks */
static void before_faccessat(hook_fargs3_t *a, void *udata)
{
    (void)a;
    (void)udata;
}

static void before_newfstatat(hook_fargs4_t *a, void *udata)
{
    (void)a;
    (void)udata;
}

static void before_unlinkat(hook_fargs3_t *a, void *udata)
{
    uid_t uid;
    (void)a;
    (void)udata;

    uid = get_current_uid();
    if (uid < APP_UID_MIN)
        return;

    cntvct_delay(g_delay_cycles);
}

static long install_hooks(void)
{
    hook_err_t err;
    long cnt = 0;

    err = hook_syscalln(__NR_faccessat, 3,
                        (void *)before_faccessat, 0, 0);
    if (err) {
        log_warn("hook_syscalln(faccessat) fail: %d\n", err);
    } else {
        log_info("hooked faccessat\n");
        g_hooked_faccessat = 1;
        cnt++;
    }

    err = hook_syscalln(__NR3264_fstatat, 4,
                        (void *)before_newfstatat, 0, 0);
    if (err) {
        log_warn("hook_syscalln(newfstatat) fail: %d\n", err);
    } else {
        log_info("hooked newfstatat\n");
        g_hooked_newfstatat = 1;
        cnt++;
    }

    err = hook_syscalln(__NR_unlinkat, 3,
                        (void *)before_unlinkat, 0, 0);
    if (err) {
        log_warn("hook_syscalln(unlinkat) fail: %d\n", err);
    } else {
        log_info("hooked unlinkat\n");
        g_hooked_unlinkat = 1;
        cnt++;
    }

    return cnt > 0 ? 0 : -1;
}

static void uninstall_hooks(void)
{
    /* Must unhook BEFORE module code is freed, otherwise callbacks
     * point to freed memory -> kernel panic on next syscall. */
    if (g_hooked_faccessat) {
        unhook_syscalln(__NR_faccessat,
                        (void *)before_faccessat, 0);
        g_hooked_faccessat = 0;
        log_info("unhooked faccessat\n");
    }
    if (g_hooked_newfstatat) {
        unhook_syscalln(__NR3264_fstatat,
                        (void *)before_newfstatat, 0);
        g_hooked_newfstatat = 0;
        log_info("unhooked newfstatat\n");
    }
    if (g_hooked_unlinkat) {
        unhook_syscalln(__NR_unlinkat,
                        (void *)before_unlinkat, 0);
        g_hooked_unlinkat = 0;
        log_info("unhooked unlinkat\n");
    }
}

static long module_init(const char *args, const char *event, void *reserved)
{
    long rc;
    unsigned long cntvct_before, cntvct_after;

    (void)event;
    (void)reserved;

    log_info("init v%s\n", MODULE_VERSION);

    /* Parse optional "delay=<cntvct_cycles>" argument */
    if (args && args[0]) {
        const char *p = args;
        while (*p) {
            if (p[0] == 'd' && p[1] == 'e' && p[2] == 'l' &&
                p[3] == 'a' && p[4] == 'y' && p[5] == '=') {
                unsigned long val = 0;
                int j;
                for (j = 6; p[j] >= '0' && p[j] <= '9'; j++)
                    val = val * 10 + (unsigned long)(p[j] - '0');
                if (val > 0 && val < 1000) {
                    g_delay_cycles = val;
                    log_info("delay=%lu CNTVCT cycles\n", val);
                }
                break;
            }
            while (*p && *p != ' ')
                p++;
            while (*p == ' ')
                p++;
        }
    }

    if (task_struct_offset.cred_offset <= 0) {
        log_warn("err: task_struct_offset not ready\n");
        return -1;
    }
    if (cred_offset.uid_offset <= 0) {
        log_warn("err: cred_offset not ready\n");
        return -2;
    }

    /* Measure CNTVCT resolution */
    cntvct_before = read_cntvct();
    cntvct_delay(1);
    cntvct_after = read_cntvct();
    log_info("CNTVCT: 1 cycle = %lu ticks\n", cntvct_after - cntvct_before);

    rc = install_hooks();
    if (rc == 0)
        log_info("active: delay=%lu cycles (~%lu ns @19.2MHz)\n",
                 g_delay_cycles, g_delay_cycles * 52);
    return rc;
}

static long module_exit(void *reserved)
{
    (void)reserved;
    uninstall_hooks();
    log_info("exited\n");
    return 0;
}

KPM_INIT(module_init);
KPM_EXIT(module_exit);

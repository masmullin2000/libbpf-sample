#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "exec.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct exec_params_t {
    u64 __unused;
    u64 __unused2;

    char *file;
};

SEC("tp/syscalls/sys_enter_execve")
int handle_execve(struct exec_params_t *params)
{
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    struct exec_evt *evt = {0};

    evt = bpf_ringbuf_reserve(&rb, sizeof(*evt), 0);
    if (!evt) {
        bpf_printk("ringbuffer not reserved\n");
        return 0;
    }

    evt->tgid = BPF_CORE_READ(task, tgid);
    evt->pid = BPF_CORE_READ(task, pid);
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
    bpf_probe_read_user_str(evt->file, sizeof(evt->file), params->file);
    bpf_ringbuf_submit(evt, 0);
    bpf_printk("Exec Called\n");
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

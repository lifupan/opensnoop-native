import os
from bcc import (
    BPF,
    DEBUG_LLVM_IR,
    DEBUG_PREPROCESSOR,
    DEBUG_SOURCE,
    DEBUG_BPF_REGISTER_STATE,
)
from debug import generate_c_function

# Names of the various BPF maps declared in `bpf_text_template`.
TABLE_NAMES = ["currsock"]

# define BPF program
bpf_text_template = """
#include <uapi/linux/ptrace.h>
#include <uapi/linux/sockios.h>
#include <uapi/linux/if.h>
#include <uapi/linux/in.h>
#include <linux/fs.h>
#include <bcc/proto.h>

BPF_HASH(currsock, u32, unsigned long);

int kprobe__sock_ioctl(struct pt_regs *ctx, struct file *file, unsigned cmd, unsigned long arg)
{
        if (cmd != SIOCGIFCONF ) {
            return 0;
        }

	u32 pid = bpf_get_current_pid_tgid();

	// stash the sock ptr for lookup on return
	currsock.update(&pid, &arg);

	return 0;
};

int kretprobe__sock_ioctl(struct pt_regs *ctx)
{
	int ret = PT_REGS_RC(ctx);
	u32 pid = bpf_get_current_pid_tgid();

        // the ip addr: 192.168.0.2
        uint32_t addr_filter = 33597632;

        unsigned long *arg;
	arg = currsock.lookup(&pid);
	if (arg == NULL) {
		return 0;	// missed entry
	}

        struct ifconf ifc;

        bpf_probe_read_user(&ifc, sizeof(ifc), (const void *)*arg);

        struct ifreq *req = (struct ifreq *)(ifc.ifc_buf + ifc.ifc_len - sizeof(struct ifreq));
        
        struct sockaddr *sockaddr = &(req->ifr_addr);
        struct sockaddr_in * sockaddrin = (struct sockaddr_in *)sockaddr;

        uint32_t addr;
        bpf_probe_read_user(&addr, sizeof(uint32_t), (uint32_t *)(&(sockaddrin->sin_addr).s_addr));

        if (addr != addr_filter) {
            return 0;
        }

        ifc.ifc_len -= sizeof(struct ifreq);
        int retn = bpf_probe_write_user((void *)*arg, &ifc, sizeof(ifc));

        unsigned char * str_addr = (unsigned char *)&addr;
	bpf_trace_printk("trace_sock_ioctl %u, %u\\n", str_addr[0], str_addr[1]);
	bpf_trace_printk("trace_sock_ioctl %u, %u\\n", str_addr[2], str_addr[3]);

	currsock.delete(&pid);

	return 0;
}
"""


def gen_c(name, bpf_fn, filter_value="", placeholder=None):
    """Returns the C code for the function and the number of instructions in
    the array the C function generates."""
    bpf = BPF(text=bpf_text_template.replace("FILTER", filter_value), debug=0)
    bytecode = bpf.dump_func(bpf_fn)
    fd_to_table_name = {}
    for sort_index, table_name in enumerate(TABLE_NAMES):
        table = bpf.get_table(table_name)
        fd_to_table_name[table.map_fd] = sort_index, table_name
    bpf.cleanup()  # Reset fds before next BPF is created.
    num_insns = len(bytecode) / 8
    c_code, rust_code = generate_c_function(
        name, bytecode, num_insns, fd_to_table_name, placeholder=placeholder
    )
    return c_code, rust_code, num_insns


PLACEHOLDER_TID = 123456
PLACEHOLDER_PID = 654321

# Note that we cannot call gen_c() while another file is open
# (such as generated_bytecode.h) or else it will throw off the
# file descriptor numbers in the generated code.
c_entry, rust_entry, entry_size, = gen_c("generate_trace_entry", "trace_entry")
c_execve_entry, rust_execve_entry, execve_entry_size, = gen_c(
    "generate_execve_entry", "execve_entry"
)
c_exit_group_entry, rust_exit_group_entry, exit_group_entry_size, = gen_c(
    "generate_exit_group_entry", "exit_group_entry"
)
c_entry_progeny, rust_entry_progeny, entry_progeny_size = gen_c(
    "generate_trace_entry_progeny",
    "trace_entry",
    filter_value="if (progeny_pids.lookup(&pid) == NULL) { return 0; }",
)
c_entry_tid, rust_entry_tid, entry_tid_size = gen_c(
    "generate_trace_entry_tid",
    "trace_entry",
    filter_value="if (tid != %d) { return 0; }" % PLACEHOLDER_TID,
    placeholder={"param_type": "int", "param_name": "tid", "imm": PLACEHOLDER_TID},
)
c_entry_pid, rust_entry_pid, entry_pid_size = gen_c(
    "generate_trace_entry_pid",
    "trace_entry",
    filter_value="if (pid != %d) { return 0; }" % PLACEHOLDER_PID,
    placeholder={"param_type": "int", "param_name": "pid", "imm": PLACEHOLDER_PID},
)
c_ret, rust_ret, ret_size = gen_c("generate_trace_return", "trace_return")

c_file = (
    (
        """\
// GENERATED FILE: See opensnoop.py.
#include <bcc/libbpf.h>
#include <stdlib.h>

#define MAX_NUM_TRACE_ENTRY_INSTRUCTIONS %d
#define NUM_TRACE_ENTRY_INSTRUCTIONS %d

#define NUM_TRACE_ENTRY_PROGENY_INSTRUCTIONS %d
#define NUM_EXECVE_ENTRY_INSTRUCTIONS %d
#define NUM_EXIT_GROUP_ENTRY_INSTRUCTIONS %d

#define NUM_TRACE_ENTRY_TID_INSTRUCTIONS %d
#define NUM_TRACE_ENTRY_PID_INSTRUCTIONS %d
#define NUM_TRACE_RETURN_INSTRUCTIONS %d

"""
        % (
            max(entry_size, entry_progeny_size, entry_tid_size, entry_pid_size),
            entry_size,
            entry_progeny_size,
            execve_entry_size,
            exit_group_entry_size,
            entry_tid_size,
            entry_pid_size,
            ret_size,
        )
    )
    + c_entry
    + c_entry_progeny
    + c_execve_entry
    + c_exit_group_entry
    + c_entry_tid
    + c_entry_pid
    + c_ret
)

__dir = os.path.dirname(os.path.realpath(__file__))
with open(os.path.join(__dir, "generated_bytecode.h"), "w") as f:
    f.write(c_file)

rust_file = (
    (
        """\
// GENERATED FILE: See opensnoop.py.
extern crate libbpf;

use libbpf::BpfMap;

pub const MAX_NUM_TRACE_ENTRY_INSTRUCTIONS: usize = %d;
pub const NUM_TRACE_ENTRY_INSTRUCTIONS: usize = %d;

pub const NUM_TRACE_ENTRY_PROGENY_INSTRUCTIONS: usize = %d;
pub const NUM_EXECVE_ENTRY_INSTRUCTIONS: usize = %d;
pub const NUM_EXIT_GROUP_ENTRY_INSTRUCTIONS: usize = %d;

pub const NUM_TRACE_ENTRY_TID_INSTRUCTIONS: usize = %d;
pub const NUM_TRACE_ENTRY_PID_INSTRUCTIONS: usize = %d;
pub const NUM_TRACE_RETURN_INSTRUCTIONS: usize = %d;
"""
        % (
            max(entry_size, entry_progeny_size, entry_tid_size, entry_pid_size),
            entry_size,
            entry_progeny_size,
            execve_entry_size,
            exit_group_entry_size,
            entry_tid_size,
            entry_pid_size,
            ret_size,
        )
    )
    + rust_entry
    + rust_entry_progeny
    + rust_execve_entry
    + rust_exit_group_entry
    + rust_entry_tid
    + rust_entry_pid
    + rust_ret
)

with open(os.path.join(__dir, "rust/opensnoop/src/generated_bytecode.rs"), "w") as f:
    f.write(rust_file)

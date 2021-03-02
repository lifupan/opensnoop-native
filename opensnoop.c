#include "opensnoop.h"
#include "generated_bytecode.h"
#include <bcc/libbpf.h>
#include <bcc/perf_reader.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <linux/version.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

char bpf_log_buf[LOG_BUF_SIZE];

/**
 * If a positive integer is parsed successfully, returns the value.
 * If not, returns -1 and errno is set.
 */
int parseNonNegativeInteger(const char *str) {
  errno = 0;
  int value = strtol(str, /* endptr */ NULL, /* base */ 10);
  if (errno != 0) {
    return -1;
  } else if (value < 0) {
    errno = EINVAL;
    return -1;
  } else {
    return value;
  }
}

int opt_timestamp = 0;
int opt_failed = 0;
int opt_pid = -1;
int opt_tid = -1;
int opt_duration = -1;
char *opt_name = NULL;

void printHeader() {
  if (opt_timestamp) {
    printf("%-14s", "TIME(s)");
  }
  printf("%-6s %-16s %4s %3s %s\n", opt_tid != -1 ? "TID" : "PID", "COMM", "FD",
         "ERR", "PATH");
}

int main(int argc, char **argv) {

  bpf_log_buf[0] = '\0';
  int hashMapFd = -1, eventsMapFd = -1, entryProgFd = -1, kprobeFd = -1,
      returnProgFd, kretprobeFd;
  struct perf_reader **readers = NULL;
  int exitCode = 1;


  // On my system (Ubuntu 18.04.1 LTS), `uname -r` returns "4.15.0-33-generic".
  // KERNEL_VERSION(4, 15, 0) is 265984, but LINUX_VERSION_CODE is in
  // /usr/include/linux/version.h is 266002, so the values do not match.
  // Ideally, we would use uname(2) to compute kern_version at runtime so this
  // binary would not have to be rebuilt for a minor kernel upgrade, but if
  // kern_version does not match LINUX_VERSION_CODE exactly, then
  // bcc_prog_load(BPF_PROG_TYPE_KPROBE) will fail with EINVAL:
  // https://github.com/torvalds/linux/blob/v4.15/kernel/bpf/syscall.c#L1140-L1142.
  // Note this issue has come up in the bcc project itself:
  // https://github.com/iovisor/bcc/commit/bfecc243fc8e822417836dd76a9b4028a5d8c2c9.
  unsigned int kern_version = LINUX_VERSION_CODE;

  // BPF_HASH
  const char *hashMapName = "hashMap name for debugging";
  hashMapFd = bcc_create_map(BPF_MAP_TYPE_HASH, hashMapName,
                             /* key_size */ sizeof(__u32),
                             /* value_size */ sizeof(__u64),
                             /* max_entries */ 10240,
                             /* map_flags */ 0);
  if (hashMapFd < 0) {
    perror("Failed to create BPF_HASH");
    return 0;
  }

  const char *prog_name_for_kprobe = "some kprobe";
  int numTraceEntryInstructions;
  struct bpf_insn trace_entry_insns[MAX_NUM_TRACE_ENTRY_INSTRUCTIONS];
  kprobe__sock_ioctl(trace_entry_insns, hashMapFd);
  numTraceEntryInstructions = NUM_TRACE_ENTRY_INSTRUCTIONS;

  entryProgFd = bcc_prog_load(
      BPF_PROG_TYPE_KPROBE, prog_name_for_kprobe, trace_entry_insns,
      /* prog_len */ numTraceEntryInstructions * sizeof(struct bpf_insn),
      /* license */ "GPL", kern_version,
      /* log_level */ 1, bpf_log_buf, LOG_BUF_SIZE);
  if (entryProgFd == -1) {
    perror("Error calling bcc_prog_load() for kprobe");
    return 0;
  }

  //kprobeFd = bpf_attach_kprobe(entryProgFd, BPF_PROBE_ENTRY, "p_sock_ioctl",
  kprobeFd = bpf_attach_kprobe(entryProgFd, BPF_PROBE_ENTRY, NULL,
                               "sock_ioctl",
                               /* fn_offset */ 0, /* maxactive */ 0);
  if (kprobeFd < 0) {
    perror("Error calling bpf_attach_kprobe() for kprobe");
    return 0;
  }

  const char *prog_name_for_kretprobe = "some kretprobe";
  struct bpf_insn trace_return_insns[NUM_EXECVE_ENTRY_INSTRUCTIONS];
  kretprobe__sock_ioctl(trace_return_insns, hashMapFd);

  returnProgFd = bcc_prog_load(
      BPF_PROG_TYPE_KPROBE, prog_name_for_kretprobe, trace_return_insns,
      /* prog_len */ NUM_EXECVE_ENTRY_INSTRUCTIONS * sizeof(struct bpf_insn),
      /* license */ "GPL", kern_version,
      /* log_level */ 1, bpf_log_buf, LOG_BUF_SIZE);
  if (returnProgFd == -1) {
    perror("Error calling bcc_prog_load() for kretprobe");
    return 0;
  }

  kretprobeFd = bpf_attach_kprobe(returnProgFd, BPF_PROBE_RETURN,
                                 // "r_sock_ioctl", "sock_ioctl",
                                  NULL, "sock_ioctl",
                                  /* fn_offset */ 0, /* maxactive */ 0);
  if (kretprobeFd < 0) {
    perror("Error calling bpf_attach_kprobe() for kretprobe");
    return 0;
  }

  printHeader();

  pause();

  return exitCode;
}

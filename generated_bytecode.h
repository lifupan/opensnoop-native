// GENERATED FILE: See opensnoop.py.
#include <bcc/libbpf.h>
#include <stdlib.h>

#define MAX_NUM_TRACE_ENTRY_INSTRUCTIONS 68
#define NUM_TRACE_ENTRY_INSTRUCTIONS 16

#define NUM_EXECVE_ENTRY_INSTRUCTIONS 68

void kprobe__sock_ioctl(struct bpf_insn instructions[], int currsock_fd) {
  instructions[0] = (struct bpf_insn) {
      .code    = 0x61,
      .dst_reg = BPF_REG_2,
      .src_reg = BPF_REG_1,
      .off     = 104,
      .imm     = 0,
  };
  instructions[1] = (struct bpf_insn) {
      .code    = 0x79,
      .dst_reg = BPF_REG_1,
      .src_reg = BPF_REG_1,
      .off     = 96,
      .imm     = 0,
  };
  instructions[2] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_1,
      .off     = -8,
      .imm     = 0,
  };
  instructions[3] = (struct bpf_insn) {
      .code    = 0x55,
      .dst_reg = BPF_REG_2,
      .src_reg = BPF_REG_0,
      .off     = 10,
      .imm     = 35090,
  };
  instructions[4] = (struct bpf_insn) {
      .code    = 0x85,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 14,
  };
  instructions[5] = (struct bpf_insn) {
      .code    = 0x63,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_0,
      .off     = -12,
      .imm     = 0,
  };
  instructions[6] = (struct bpf_insn) {
      .code    = 0x18,
      .dst_reg = BPF_REG_1,
      .src_reg = BPF_REG_1,
      .off     = 0,
      .imm     = currsock_fd,
  };
  instructions[7] = (struct bpf_insn) {
      .code    = 0x0,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 0,
  };
  instructions[8] = (struct bpf_insn) {
      .code    = 0xbf,
      .dst_reg = BPF_REG_2,
      .src_reg = BPF_REG_10,
      .off     = 0,
      .imm     = 0,
  };
  instructions[9] = (struct bpf_insn) {
      .code    = 0x7,
      .dst_reg = BPF_REG_2,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = -12,
  };
  instructions[10] = (struct bpf_insn) {
      .code    = 0xbf,
      .dst_reg = BPF_REG_3,
      .src_reg = BPF_REG_10,
      .off     = 0,
      .imm     = 0,
  };
  instructions[11] = (struct bpf_insn) {
      .code    = 0x7,
      .dst_reg = BPF_REG_3,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = -8,
  };
  instructions[12] = (struct bpf_insn) {
      .code    = 0xb7,
      .dst_reg = BPF_REG_4,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 0,
  };
  instructions[13] = (struct bpf_insn) {
      .code    = 0x85,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 2,
  };
  instructions[14] = (struct bpf_insn) {
      .code    = 0xb7,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 0,
  };
  instructions[15] = (struct bpf_insn) {
      .code    = 0x95,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 0,
  };
}

void kretprobe__sock_ioctl(struct bpf_insn instructions[], int currsock_fd) {
  instructions[0] = (struct bpf_insn) {
      .code    = 0x85,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 14,
  };
  instructions[1] = (struct bpf_insn) {
      .code    = 0x63,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_0,
      .off     = -4,
      .imm     = 0,
  };
  instructions[2] = (struct bpf_insn) {
      .code    = 0x18,
      .dst_reg = BPF_REG_1,
      .src_reg = BPF_REG_1,
      .off     = 0,
      .imm     = currsock_fd,
  };
  instructions[3] = (struct bpf_insn) {
      .code    = 0x0,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 0,
  };
  instructions[4] = (struct bpf_insn) {
      .code    = 0xbf,
      .dst_reg = BPF_REG_2,
      .src_reg = BPF_REG_10,
      .off     = 0,
      .imm     = 0,
  };
  instructions[5] = (struct bpf_insn) {
      .code    = 0x7,
      .dst_reg = BPF_REG_2,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = -4,
  };
  instructions[6] = (struct bpf_insn) {
      .code    = 0x85,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 1,
  };
  instructions[7] = (struct bpf_insn) {
      .code    = 0xbf,
      .dst_reg = BPF_REG_6,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 0,
  };
  instructions[8] = (struct bpf_insn) {
      .code    = 0x15,
      .dst_reg = BPF_REG_6,
      .src_reg = BPF_REG_0,
      .off     = 57,
      .imm     = 0,
  };
  instructions[9] = (struct bpf_insn) {
      .code    = 0x79,
      .dst_reg = BPF_REG_3,
      .src_reg = BPF_REG_6,
      .off     = 0,
      .imm     = 0,
  };
  instructions[10] = (struct bpf_insn) {
      .code    = 0xbf,
      .dst_reg = BPF_REG_1,
      .src_reg = BPF_REG_10,
      .off     = 0,
      .imm     = 0,
  };
  instructions[11] = (struct bpf_insn) {
      .code    = 0x7,
      .dst_reg = BPF_REG_1,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = -24,
  };
  instructions[12] = (struct bpf_insn) {
      .code    = 0xb7,
      .dst_reg = BPF_REG_2,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 16,
  };
  instructions[13] = (struct bpf_insn) {
      .code    = 0x85,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 4,
  };
  instructions[14] = (struct bpf_insn) {
      .code    = 0x61,
      .dst_reg = BPF_REG_1,
      .src_reg = BPF_REG_10,
      .off     = -24,
      .imm     = 0,
  };
  instructions[15] = (struct bpf_insn) {
      .code    = 0x67,
      .dst_reg = BPF_REG_1,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 32,
  };
  instructions[16] = (struct bpf_insn) {
      .code    = 0xc7,
      .dst_reg = BPF_REG_1,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 32,
  };
  instructions[17] = (struct bpf_insn) {
      .code    = 0x79,
      .dst_reg = BPF_REG_3,
      .src_reg = BPF_REG_10,
      .off     = -16,
      .imm     = 0,
  };
  instructions[18] = (struct bpf_insn) {
      .code    = 0xf,
      .dst_reg = BPF_REG_3,
      .src_reg = BPF_REG_1,
      .off     = 0,
      .imm     = 0,
  };
  instructions[19] = (struct bpf_insn) {
      .code    = 0x7,
      .dst_reg = BPF_REG_3,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = -20,
  };
  instructions[20] = (struct bpf_insn) {
      .code    = 0xbf,
      .dst_reg = BPF_REG_1,
      .src_reg = BPF_REG_10,
      .off     = 0,
      .imm     = 0,
  };
  instructions[21] = (struct bpf_insn) {
      .code    = 0x7,
      .dst_reg = BPF_REG_1,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = -28,
  };
  instructions[22] = (struct bpf_insn) {
      .code    = 0xb7,
      .dst_reg = BPF_REG_2,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 4,
  };
  instructions[23] = (struct bpf_insn) {
      .code    = 0x85,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 4,
  };
  instructions[24] = (struct bpf_insn) {
      .code    = 0x61,
      .dst_reg = BPF_REG_1,
      .src_reg = BPF_REG_10,
      .off     = -28,
      .imm     = 0,
  };
  instructions[25] = (struct bpf_insn) {
      .code    = 0x55,
      .dst_reg = BPF_REG_1,
      .src_reg = BPF_REG_0,
      .off     = 40,
      .imm     = 33597632,
  };
  instructions[26] = (struct bpf_insn) {
      .code    = 0x61,
      .dst_reg = BPF_REG_1,
      .src_reg = BPF_REG_10,
      .off     = -24,
      .imm     = 0,
  };
  instructions[27] = (struct bpf_insn) {
      .code    = 0x7,
      .dst_reg = BPF_REG_1,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = -40,
  };
  instructions[28] = (struct bpf_insn) {
      .code    = 0x63,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_1,
      .off     = -24,
      .imm     = 0,
  };
  instructions[29] = (struct bpf_insn) {
      .code    = 0x79,
      .dst_reg = BPF_REG_1,
      .src_reg = BPF_REG_6,
      .off     = 0,
      .imm     = 0,
  };
  instructions[30] = (struct bpf_insn) {
      .code    = 0xbf,
      .dst_reg = BPF_REG_2,
      .src_reg = BPF_REG_10,
      .off     = 0,
      .imm     = 0,
  };
  instructions[31] = (struct bpf_insn) {
      .code    = 0x7,
      .dst_reg = BPF_REG_2,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = -24,
  };
  instructions[32] = (struct bpf_insn) {
      .code    = 0xb7,
      .dst_reg = BPF_REG_3,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 16,
  };
  instructions[33] = (struct bpf_insn) {
      .code    = 0x85,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 36,
  };
  instructions[34] = (struct bpf_insn) {
      .code    = 0xb7,
      .dst_reg = BPF_REG_6,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 0,
  };
  instructions[35] = (struct bpf_insn) {
      .code    = 0x73,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_6,
      .off     = -40,
      .imm     = 0,
  };
  instructions[36] = (struct bpf_insn) {
      .code    = 0x18,
      .dst_reg = BPF_REG_7,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 745874720,
  };
  instructions[37] = (struct bpf_insn) {
      .code    = 0x0,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 175449376,
  };
  instructions[38] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_7,
      .off     = -48,
      .imm     = 0,
  };
  instructions[39] = (struct bpf_insn) {
      .code    = 0x18,
      .dst_reg = BPF_REG_8,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 1767861091,
  };
  instructions[40] = (struct bpf_insn) {
      .code    = 0x0,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 1819566959,
  };
  instructions[41] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_8,
      .off     = -56,
      .imm     = 0,
  };
  instructions[42] = (struct bpf_insn) {
      .code    = 0x18,
      .dst_reg = BPF_REG_9,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 1667330676,
  };
  instructions[43] = (struct bpf_insn) {
      .code    = 0x0,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 1869832037,
  };
  instructions[44] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_9,
      .off     = -64,
      .imm     = 0,
  };
  instructions[45] = (struct bpf_insn) {
      .code    = 0x71,
      .dst_reg = BPF_REG_3,
      .src_reg = BPF_REG_10,
      .off     = -28,
      .imm     = 0,
  };
  instructions[46] = (struct bpf_insn) {
      .code    = 0x71,
      .dst_reg = BPF_REG_4,
      .src_reg = BPF_REG_10,
      .off     = -27,
      .imm     = 0,
  };
  instructions[47] = (struct bpf_insn) {
      .code    = 0xbf,
      .dst_reg = BPF_REG_1,
      .src_reg = BPF_REG_10,
      .off     = 0,
      .imm     = 0,
  };
  instructions[48] = (struct bpf_insn) {
      .code    = 0x7,
      .dst_reg = BPF_REG_1,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = -64,
  };
  instructions[49] = (struct bpf_insn) {
      .code    = 0xb7,
      .dst_reg = BPF_REG_2,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 25,
  };
  instructions[50] = (struct bpf_insn) {
      .code    = 0x85,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 6,
  };
  instructions[51] = (struct bpf_insn) {
      .code    = 0x73,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_6,
      .off     = -40,
      .imm     = 0,
  };
  instructions[52] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_7,
      .off     = -48,
      .imm     = 0,
  };
  instructions[53] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_8,
      .off     = -56,
      .imm     = 0,
  };
  instructions[54] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_9,
      .off     = -64,
      .imm     = 0,
  };
  instructions[55] = (struct bpf_insn) {
      .code    = 0x71,
      .dst_reg = BPF_REG_3,
      .src_reg = BPF_REG_10,
      .off     = -26,
      .imm     = 0,
  };
  instructions[56] = (struct bpf_insn) {
      .code    = 0x71,
      .dst_reg = BPF_REG_4,
      .src_reg = BPF_REG_10,
      .off     = -25,
      .imm     = 0,
  };
  instructions[57] = (struct bpf_insn) {
      .code    = 0xbf,
      .dst_reg = BPF_REG_1,
      .src_reg = BPF_REG_10,
      .off     = 0,
      .imm     = 0,
  };
  instructions[58] = (struct bpf_insn) {
      .code    = 0x7,
      .dst_reg = BPF_REG_1,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = -64,
  };
  instructions[59] = (struct bpf_insn) {
      .code    = 0xb7,
      .dst_reg = BPF_REG_2,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 25,
  };
  instructions[60] = (struct bpf_insn) {
      .code    = 0x85,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 6,
  };
  instructions[61] = (struct bpf_insn) {
      .code    = 0x18,
      .dst_reg = BPF_REG_1,
      .src_reg = BPF_REG_1,
      .off     = 0,
      .imm     = currsock_fd,
  };
  instructions[62] = (struct bpf_insn) {
      .code    = 0x0,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 0,
  };
  instructions[63] = (struct bpf_insn) {
      .code    = 0xbf,
      .dst_reg = BPF_REG_2,
      .src_reg = BPF_REG_10,
      .off     = 0,
      .imm     = 0,
  };
  instructions[64] = (struct bpf_insn) {
      .code    = 0x7,
      .dst_reg = BPF_REG_2,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = -4,
  };
  instructions[65] = (struct bpf_insn) {
      .code    = 0x85,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 3,
  };
  instructions[66] = (struct bpf_insn) {
      .code    = 0xb7,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 0,
  };
  instructions[67] = (struct bpf_insn) {
      .code    = 0x95,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 0,
  };
}


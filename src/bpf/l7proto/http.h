#include "vmlinux.h"
#include "bpf_helpers.h"

#include "include/helper.h"
#include "include/maps.h"

/*
 * ---------------Kernel---------------------------------------------------------
 * | recv ------> prog read data from socket                      <--(ts begin)
 *                                      |                         |
 *                                      |                         |
 *                                prog write data to socket       | (the time
 * app cost) |                         | | socket close          <---(ts end)
 *                                      |
 *                                     send
 */

enum http_method {
  HTTP_METHOD_GET,
  HTTP_METHOD_HEAD,
  HTTP_METHOD_POST,
  HTTP_METHOD_PUT,
  HTTP_METHOD_DELETE,
  HTTP_METHOD_CONNECT,
  HTTP_METHOD_OPTIONS,
  HTTP_METHOD_TRACE,
  HTTP_METHOD_PATCH,
  HTTP_METHOD_MOVE,
  HTTP_METHOD_COPY,
  HTTP_METHOD_LINK,
  HTTP_METHOD_UNLINK,
  HTTP_METHOD_WRAPPED,
  HTTP_METHOD_EXTENSION,
  HTTP_METHOD_UNKNOWN,
};

struct http_event_t {
  u8 method;    // get,post,put,head
  u16 protocol; // http协议, http1.0 或者 http2.0....
  char url[16];
  u64 delay;
  char msg[64];
  u32 s_addr;
  u32 s_port;
};

BPF_PERF_EVENT_ARRAY(perf_event_l7_http_map, 4096)

SEC("tracepoint/syscalls/sys_enter_accept4")
int tp__syscalls__sys_enter_accept4(struct pt_regs *ctx) { return BPF_OK; }

SEC("tracepoint/syscalls/sys_exit_accept4")
int tp__syscalls__sys_exit_accept4(struct pt_regs *ctx, long ret) {
  return BPF_OK;
}

// read
SEC("tracepoint/syscalls/sys_enter_read")
int tp__syscalls__sys_enter_read(struct pt_regs *ctx, unsigned int fd,
                                 char *buf, size_t count) {
  /* u64 pid_tgid = bpf_get_current_pid_tgid();

  struct http_sk_rw_args data_args = {
      .fd = fd,
      .buf = buf,
      .count = count,
  };
  bpf_map_update_elem(&http_rw_args_buffer, &pid_tgid, &data_args, BPF_ANY); */
  return BPF_OK;
}

SEC("tracepoint/syscalls/sys_exit_read")
int tp__syscalls__sys_exit_read(struct pt_regs *ctx, long ret) {
  u64 pid_tgid = bpf_get_current_pid_tgid();

  /* struct http_sk_rw_args *r_args = bpf_hashmap_pop(&http_rw_args_buffer,
  &pid_tgid); if (!r_args) return BPF_OK;

  struct http_fds_ctx *fds_args = bpf_map_lookup_elem(&http_fds_ctx_buffer,
  &r_args->fd); if (!fds_args) return BPF_OK;
 */
  return BPF_OK;
}

// write
SEC("tracepoint/syscalls/sys_enter_write")
int tp__syscalls__sys_enter_write(struct pt_regs *ctx, unsigned int fd,
                                  const char *buf, size_t count) {
  /* u64 pid_tgid = bpf_get_current_pid_tgid();

  struct http_sk_rw_args data_args = {
      .fd = fd,
      .buf = buf,
      .count = count,
  };
  bpf_map_update_elem(&http_rw_args_buffer, &pid_tgid, &data_args, BPF_ANY); */

  return BPF_OK;
}

SEC("tracepoint/syscalls/sys_exit_write")
int tp__syscalls__sys_exit_write(struct pt_regs *ctx, long ret) {
  /* u64 pid_tgid = bpf_get_current_pid_tgid();

  struct http_sk_rw_args *r_args = bpf_hashmap_pop(&http_rw_args_buffer,
  &pid_tgid); if (!r_args) return BPF_OK;

  struct http_fds_ctx *fds_args = bpf_map_lookup_elem(&http_fds_ctx_buffer,
  &r_args->fd); if (!fds_args) return BPF_OK; */

  return BPF_OK;
}

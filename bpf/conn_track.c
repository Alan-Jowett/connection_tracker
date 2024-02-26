// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "bpf.h"
#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "net/ip.h"
#include "..\conn_tracker\conn_tracker.h"


// Connection history map containing tuple and connection duration.
SEC("maps")
struct bpf_map_def history_map = {.type = BPF_MAP_TYPE_RINGBUF, .max_entries = 256 * 1024};

__attribute__((always_inline)) int
log_sockaddr(bpf_sock_addr_t* sock_addr)
{
    connection_history_t connection_history;
    __builtin_memset(&connection_history, 0, sizeof(connection_history));
    connection_history.is_ipv4 = sock_addr->family == AF_INET;
    if (connection_history.is_ipv4) {
        connection_history.tuple.dst_ip.ipv4 = sock_addr->user_ip4;
        connection_history.tuple.src_ip.ipv4 = sock_addr->msg_src_ip4;
    }
    else {
        __builtin_memcpy(connection_history.tuple.dst_ip.ipv6, sock_addr->user_ip6, sizeof(connection_history.tuple.dst_ip.ipv6));
        __builtin_memcpy(connection_history.tuple.src_ip.ipv6, sock_addr->msg_src_ip6, sizeof(connection_history.tuple.src_ip.ipv6));
    }
    connection_history.tuple.dst_port = sock_addr->user_port;
    connection_history.tuple.src_port = sock_addr->msg_src_port;
    connection_history.tuple.protocol = sock_addr->protocol;
    connection_history.tuple.compartment_id = sock_addr->compartment_id;
    connection_history.tuple.interface_luid = sock_addr->interface_luid;
    connection_history.tgidpid = bpf_sock_addr_get_current_pid_tgid(sock_addr);
    bpf_ringbuf_output(&history_map, &connection_history, sizeof(connection_history), 0);
    return BPF_SOCK_ADDR_VERDICT_PROCEED;
}

SEC("cgroup/connect4")
int
connection_tracker_v4(bpf_sock_addr_t* sock_addr) 
{
    return log_sockaddr(sock_addr);
}

SEC("cgroup/connect6")
int
connection_tracker_v6(bpf_sock_addr_t* sock_addr) 
{
    return log_sockaddr(sock_addr);
}

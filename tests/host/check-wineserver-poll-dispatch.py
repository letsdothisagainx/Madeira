#!/usr/bin/env python3
"""Execute production poll registration/dispatch against descriptor ABA and mask changes."""
from pathlib import Path
import os
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
source = (root / 'build/wineserver/fd_ios.c').read_text()

def function(signature, text=source):
    start = text.index(signature)
    brace = text.index('{', start)
    depth = 0
    for token in re.finditer(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{}]', text[brace:], re.S):
        if token.group() == '{': depth += 1
        elif token.group() == '}':
            depth -= 1
            if not depth: return text[start:brace + token.end()]
    raise AssertionError(signature)

snapshot = re.search(r'struct ios_poll_snapshot\n\{.*?\};', source, re.S).group()
functions = '\n'.join(function(s) for s in (
    'static int ios_fd_uses_io_probe(',
    'static int ios_fd_needs_real_poll(',
    'static int ios_fd_probe_events(',
    'static struct ios_poll_snapshot ios_poll_snapshot(',
    'static int ios_poll_dispatch_snapshot(',
    'static int add_poll_user(',
    'static void remove_poll_user(',
    'void set_fd_events(',
    'static void ios_poll_owner_census('))

code = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
struct type_descr { int unused; };
static struct type_descr thread_type, process_type, other_type;
struct object_ops { const struct type_descr *type; };
struct object { const struct object_ops *ops; };
static const struct object_ops thread_ops = {&thread_type}, process_ops = {&process_type}, other_ops = {&other_type};
static struct object thread_user = {&thread_ops}, process_user = {&process_ops}, queue_user = {&other_ops};
struct fd {
    int unix_fd, poll_index;
    unsigned long long poll_generation;
    unsigned open_pid, open_tid;
    struct object *user;
};
static struct fd **poll_users, **freelist;
static struct pollfd *pollfd;
static int nb_users, active_users, allocated_users;
static unsigned long long ios_poll_generation, ios_poll_stale, ios_poll_masked, ios_poll_delivered;
static unsigned long long ios_poll_hup, ios_poll_error, ios_poll_invalid;
static unsigned lines, owner_lines, forgets, callbacks, last_events;
static int reuse_during_callback, b_number, replacement[2];
static struct fd master, a, b;
static int inet_override;
static signed char ios_fd_is_inet(int user, int fd) { assert(user >= 0 && fd >= 0); return inet_override; }
static void init_epoll(void) {}
static void remove_epoll_user(struct fd *fd, int user) { assert(fd && user >= 0); }
static void set_fd_epoll_events(struct fd *fd, int user, int events) { assert(fd && user >= 0); (void)events; }
static void ios_fd_inet_forget(int user) { assert(user >= 0); forgets++; }
static int ios_srv_log_sample(unsigned long *count) { (*count)++; return 0; }
static void ws_log(const char *format, ...) { (void)format; }
static int diagnostic(FILE *stream, const char *format, ...) {
    assert(stream == stderr && format); lines++;
    if (strstr(format,"srv-poll-owner-v1")) owner_lines++;
    errno = ERANGE; return 0;
}
static void fd_poll_event(struct fd *fd, int event);
#define fprintf diagnostic
''' + snapshot + '\n' + functions + r'''
static void fd_poll_event(struct fd *fd, int event) {
    callbacks++; last_events = event;
    if (fd == &a && reuse_during_callback) {
        reuse_during_callback = 0;
        char byte; assert(read(a.unix_fd, &byte, 1) == 1);
        remove_poll_user(&b, b.poll_index);
        assert(!close(b_number));
        assert(dup2(replacement[0], b_number) == b_number);
        b.unix_fd = b_number; b.open_pid = 0x90; b.open_tid = 0x94;
        b.poll_index = add_poll_user(&b);
        assert(b.poll_index == 2);
        set_fd_events(&b, POLLIN);
    }
}
int main(void) {
    int pa[2], pb[2]; assert(!socketpair(AF_UNIX,SOCK_STREAM,0,pa));
    assert(!socketpair(AF_UNIX,SOCK_STREAM,0,pb));
    assert(!socketpair(AF_UNIX,SOCK_STREAM,0,replacement));
    master.unix_fd = -1; master.poll_index = add_poll_user(&master);
    assert(master.poll_index == 0);
    a.unix_fd = pa[0]; a.open_pid = 0x20; a.open_tid = 0x24; a.user = &thread_user; a.poll_index = add_poll_user(&a);
    b.unix_fd = pb[0]; b.open_pid = 0x64; b.open_tid = 0x68; b.user = &process_user; b.poll_index = add_poll_user(&b);
    assert(a.poll_index == 1 && b.poll_index == 2 && a.poll_generation && b.poll_generation);
    set_fd_events(&a,POLLIN); set_fd_events(&b,POLLIN);
    assert(write(pa[1],"a",1) == 1 && write(pb[1],"b",1) == 1);
    struct pollfd ready[2] = {{pa[0],POLLIN,0},{pb[0],POLLIN,0}};
    struct ios_poll_snapshot owners[2] = {ios_poll_snapshot(1),ios_poll_snapshot(2)};
    assert(poll(ready,2,0) == 2);
    b_number = pb[0]; reuse_during_callback = 1;
    assert(ios_poll_dispatch_snapshot(&owners[0],ready[0].revents));
    assert(b.poll_generation != owners[1].generation && b.unix_fd == owners[1].unix_fd);
    errno = EDOM;
    assert(!ios_poll_dispatch_snapshot(&owners[1],ready[1].revents));
    assert(errno == EDOM && callbacks == 1 && ios_poll_stale == 1);
    struct pollfd empty = {b.unix_fd,POLLIN,0}; assert(poll(&empty,1,0) == 0);
    assert(write(replacement[1],"c",1) == 1 && poll(&empty,1,0) == 1);
    struct ios_poll_snapshot now = ios_poll_snapshot(2);
    assert(ios_poll_dispatch_snapshot(&now,empty.revents) && callbacks == 2);

    set_fd_events(&b,POLLOUT);
    assert(!ios_poll_dispatch_snapshot(&now,POLLIN) && ios_poll_masked == 1);
    assert(ios_poll_dispatch_snapshot(&now,POLLIN|POLLOUT) && last_events == POLLOUT);
    set_fd_events(&b,0); /* error-only watch, not disabled */
    assert(pollfd[2].fd == b.unix_fd && !pollfd[2].events);
    assert(!ios_poll_dispatch_snapshot(&now,POLLIN));
    int terminal = POLLERR|POLLHUP|POLLNVAL;
    assert(ios_poll_dispatch_snapshot(&now,POLLIN|terminal) && last_events == (unsigned)terminal);
    assert(ios_poll_hup == 1 && ios_poll_error == 1 && ios_poll_invalid == 1);
    set_fd_events(&b,-1); /* completely disabled */
    unsigned before = callbacks;
    assert(!ios_poll_dispatch_snapshot(&now,terminal) && callbacks == before);
    assert(pollfd[2].fd == -1 && pollfd[2].events == POLLERR);
    set_fd_events(&b,POLLIN);
    /* A reused client slot below any old injection threshold still gets its
     * typed I/O probe. The classification does not consult array positions. */
    assert(ios_fd_uses_io_probe(&a) && ios_fd_uses_io_probe(&b));
    assert(!ios_fd_needs_real_poll(2) && ios_fd_probe_events(&b,0,POLLIN,1) == POLLIN);
    assert(!ios_fd_probe_events(&b,0,POLLIN,0));
    assert(ios_fd_probe_events(&b,0,POLLOUT,0) == POLLOUT);
    assert(!ios_fd_probe_events(&b,1,POLLIN|POLLOUT,1));
    assert(!ios_fd_probe_events(&b,0,-1,1));
    inet_override = 1; assert(ios_fd_needs_real_poll(2)); inet_override = 0;
    struct object no_ops = {0}; struct fd unknown = {.user = &no_ops};
    assert(!ios_fd_uses_io_probe(0) && !ios_fd_uses_io_probe(&unknown));
    unknown.user = 0; assert(!ios_fd_uses_io_probe(&unknown));
    unknown.user = &queue_user; assert(!ios_fd_uses_io_probe(&unknown));
    assert(!ios_fd_probe_events(&unknown,0,POLLIN|POLLOUT,1));

    /* Queue/device-style callbacks above an old injection threshold receive
     * actual readiness, including zero-interest terminal events, never fake POLLIN. */
    struct fd filler[100] = {{0}}, queue = {.user = &queue_user, .open_pid = 0x90};
    for (unsigned i = 0; i < 100; i++) { filler[i].unix_fd = -1; filler[i].poll_index = add_poll_user(&filler[i]); }
    int pq[2]; assert(!socketpair(AF_UNIX,SOCK_STREAM,0,pq));
    queue.unix_fd = pq[0]; queue.poll_index = add_poll_user(&queue); set_fd_events(&queue,POLLIN);
    assert(queue.poll_index >= 100 && ios_fd_needs_real_poll(queue.poll_index));
    assert(!ios_fd_probe_events(&queue,0,POLLIN,1));
    struct pollfd queue_poll = {pq[0],POLLIN,0}; assert(!poll(&queue_poll,1,0));
    assert(write(pq[1],"q",1) == 1 && poll(&queue_poll,1,0) == 1);
    struct ios_poll_snapshot queue_owner = ios_poll_snapshot(queue.poll_index);
    assert(ios_poll_dispatch_snapshot(&queue_owner,queue_poll.revents) && last_events == POLLIN);
    char qbyte; assert(read(pq[0],&qbyte,1) == 1); close(pq[1]);
    set_fd_events(&queue,0); queue_poll.events = 0; queue_poll.revents = 0;
    /* Darwin and Linux report stream EOF differently. An invalid descriptor
     * deterministically supplies a kernel terminal event with interest zero;
     * explicit HUP/ERR forwarding is checked independently above. */
    assert(!close(pq[0]));
    assert(ios_fd_needs_real_poll(queue.poll_index) && poll(&queue_poll,1,0) == 1 && (queue_poll.revents & POLLNVAL));
    assert(ios_poll_dispatch_snapshot(&queue_owner,queue_poll.revents) && (last_events & POLLNVAL));
    remove_poll_user(&queue,queue.poll_index);
    for (unsigned i = 0; i < 100; i++) remove_poll_user(&filler[i],filler[i].poll_index);
    now = ios_poll_snapshot(2); now.generation = 0;
    assert(!ios_poll_dispatch_snapshot(&now,POLLIN));
    before = lines;
    for (unsigned i = 0; i < 83968; i++) assert(!ios_poll_dispatch_snapshot(&owners[1],POLLIN));
    assert(lines - before < 24); /* logarithmic stale-drop records */
    for (unsigned i = 0; i < 100; i++) ios_poll_owner_census();
    assert(owner_lines == 24); /* two creator PIDs, twelve snapshots */

    unsigned long long prior = ios_poll_generation;
    int old_active = active_users, old_high = nb_users;
    ios_poll_generation = ~0ull;
    struct fd extra = { .unix_fd = -1 };
    errno = 0; assert(add_poll_user(&extra) == -1 && errno == EOVERFLOW);
    assert(active_users == old_active && nb_users == old_high && !extra.poll_generation);
    ios_poll_generation = prior;
    remove_poll_user(&b,2); remove_poll_user(&a,1); remove_poll_user(&master,0);
    assert(!active_users && forgets >= 8);
    free(poll_users); free(pollfd);
    close(pa[0]); close(pa[1]); close(b_number); close(pb[1]); close(replacement[0]); close(replacement[1]);
    puts("PASS: actual batch dispatch rejects same-slot/same-fd/same-address ABA, honors current masks and zero-interest terminal events, bounds logs, and refuses generation wrap");
    puts("PASS: typed probes survive low-slot reuse; high-slot queues and unknown owners never receive synthetic readiness; actual queue data and zero-interest invalid-FD events still dispatch");
}
'''
assert source.count('ios_poll_dispatch_snapshot( &rp_owner[k], rp[k].revents )') == 2
assert 'rp_owner[nrp++] = ios_poll_snapshot( i );' in source
assert 'if (pollfd[i].fd < 0) continue; /* zero interest still watches ERR/HUP/NVAL */' in source
assert 'poll-slots-highwater=%d live-objects=%d' in source
with tempfile.TemporaryDirectory() as temp:
    src = Path(temp) / 'check.c'; src.write_text(code)
    exe = Path(temp) / 'check'
    subprocess.run([os.environ.get('CC','cc'),'-std=c11','-O1','-g',
                    '-fsanitize=address,undefined','-fno-sanitize-recover=all',str(src),'-o',str(exe)],check=True)
    subprocess.run([str(exe)],check=True,env=dict(os.environ,ASAN_OPTIONS='detect_leaks=0'))

request = (root / 'build/wineserver/request_ios.c').read_text()
protocol = (root / 'wine/include/wine/server_protocol.h').read_text()
request_enum = re.search(r'enum request\s*\{.*?\};', protocol, re.S).group()
counters = re.search(r'static unsigned long long ios_request_headers[^\n]*;\nstatic unsigned long long ios_request_partial;', request).group()
request_functions = '\n'.join(function(s, request) for s in (
    'static const char *ios_req_name(', 'static void ios_req_census(',
    'void ios_srv_request_progress(', 'void read_request('))
request_code = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
typedef uint64_t timeout_t;
typedef unsigned data_size_t, obj_handle_t;
#define TICKS_PER_SEC 10000000ULL
#define MAXIMUM_WAIT_OBJECTS 64
#define SELECT_ALERTABLE 1
#define min(a,b) ((a)<(b)?(a):(b))
static timeout_t monotonic_time;
struct process { unsigned id; };
union generic_request {
    struct { unsigned req, request_size; } request_header;
    struct { unsigned size, flags; } select_request;
    struct { unsigned flags; } set_cursor_request;
    unsigned char pad[64];
};
struct fd { int number; };
struct thread {
    unsigned id, req_toread;
    struct process *process;
    union generic_request req;
    void *req_data;
    struct fd *request_fd;
};
union apc_result { uint64_t unused; };
enum select_opcode { SELECT_WAIT, SELECT_WAIT_ALL, SELECT_SIGNAL_AND_WAIT, SELECT_KEYED_EVENT_WAIT, SELECT_KEYED_EVENT_RELEASE };
union select_op { enum select_opcode op; struct {enum select_opcode op; obj_handle_t handles[64];} wait; };
struct type_descr { int unused; };
static struct type_descr semaphore_type,event_type,mutex_type,thread_type,process_type,timer_type,completion_type;
struct object_ops { const struct type_descr *type; };
struct object { const struct object_ops *ops; };
static struct object *get_handle_obj(struct process *p,unsigned h,unsigned access,void *type) {(void)p;(void)h;(void)access;(void)type;return 0;}
static void clear_error(void) {}
static void release_object(void *p) {(void)p;}
static size_t get_req_data_size(void) {return 0;}
static void *get_req_data(void) {static union apc_result data;return &data;}
static unsigned handled,killed,fatal,histograms,progress_lines;
static unsigned long last_window,ios_clip_repeats_skipped;
static char last_histogram[1500];
static int get_unix_fd(struct fd *fd) {return fd->number;}
static void call_req_handler(struct thread *thread) {(void)thread;handled++;}
static void kill_thread(struct thread *thread,int violent) {(void)thread;(void)violent;killed++;}
static void fatal_protocol_error(struct thread *thread,const char *format,...) {(void)thread;(void)format;fatal++;}
static int diagnostic(FILE *stream,const char *format,...) {
    assert(stream==stderr);va_list args;va_start(args,format);
    if(strstr(format,"[srv-req-v2]")){
        histograms++;last_window=va_arg(args,unsigned long);(void)va_arg(args,double);
        snprintf(last_histogram,sizeof(last_histogram),"%s",va_arg(args,const char*));
    }
    if(strstr(format,"[srv-request-progress-v1]"))progress_lines++;
    va_end(args);return 0;
}
#define fprintf diagnostic
''' + request_enum + '\n' + counters + '\n' + request_functions + r'''
int main(void) {
    struct process process={0x64}; struct thread thread={.id=0x124,.process=&process};
    for(unsigned i=0;i<5000;i++)ios_req_census(&thread,REQ_remove_completion);
    monotonic_time=10*TICKS_PER_SEC;ios_req_census(&thread,REQ_add_completion);
    assert(histograms==1&&last_window==5001&&strstr(last_histogram,"remove_completion")&&strstr(last_histogram,"pid 0064"));
    monotonic_time+=TICKS_PER_SEC;ios_req_census(&thread,REQ_get_thread_completion);
    monotonic_time+=10*TICKS_PER_SEC;ios_req_census(&thread,REQ_get_thread_completion);
    assert(histograms==2&&last_window==2); /* low traffic after a stall still reports */
    for(unsigned i=0;i<100;i++){
        monotonic_time+=TICKS_PER_SEC;ios_req_census(&thread,REQ_event_op);
        monotonic_time+=10*TICKS_PER_SEC;ios_req_census(&thread,REQ_event_op);
    }
    assert(histograms==12);
    int pipefd[2];assert(!pipe(pipefd));assert(fcntl(pipefd[0],F_SETFL,O_NONBLOCK)!=-1);
    struct fd fd={pipefd[0]};thread.request_fd=&fd;
    read_request(&thread);assert(ios_request_empty==1&&!handled);
    union generic_request req={0};req.request_header.req=REQ_event_op;
    assert(write(pipefd[1],&req,sizeof(req))==sizeof(req));read_request(&thread);
    assert(handled==1&&ios_request_headers==1);
    req.request_header.request_size=4;
    assert(write(pipefd[1],&req,sizeof(req))==sizeof(req));read_request(&thread);
    assert(thread.req_toread==4&&ios_request_partial==1&&ios_request_headers==2&&handled==1);
    assert(write(pipefd[1],"data",4)==4);read_request(&thread);
    assert(!thread.req_toread&&!thread.req_data&&handled==2&&ios_request_headers==2);
    assert(write(pipefd[1],"bad",3)==3);read_request(&thread);
    assert(fatal==1&&ios_request_errors==1);
    close(pipefd[1]);read_request(&thread);assert(killed==1&&ios_request_eof==1);close(pipefd[0]);
    fd.number=-1;read_request(&thread);assert(fatal==2&&ios_request_errors==2);
    for(unsigned i=0;i<1000;i++)ios_srv_request_progress();
    assert(progress_lines==12);
    puts("PASS: actual request histograms report low post-stall traffic and stop at twelve windows; empty probes, header progress, partial payload, EOF and errors remain distinct");
}
'''
with tempfile.TemporaryDirectory() as temp:
    src = Path(temp) / 'request.c'; src.write_text(request_code)
    exe = Path(temp) / 'request'
    subprocess.run([os.environ.get('CC','cc'),'-std=c11','-O1','-g',
                    '-fsanitize=address,undefined','-fno-sanitize-recover=all',str(src),'-o',str(exe)],check=True)
    subprocess.run([str(exe)],check=True,env=dict(os.environ,ASAN_OPTIONS='detect_leaks=0'))

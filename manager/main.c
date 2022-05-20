#define _GNU_SOURCE 

#include <err.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/signalfd.h>
#include <sys/signal.h>
#include <errno.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/wait.h>
#include <sched.h>
#include <time.h>


typedef enum {
    CREATED, /* just created, should be started asap */
    STARTING, /* started, waiting for confirmation of success */
    RUNNING, /* running normally */
    RESTARTING, /* crashed and now we are starting it again */
    FAILED, /* crashed repeatedly, we are no longer trying to start it up */
} process_state_t;

typedef enum {
    KRESD,
    MANAGER,
    GC
} process_type_t;

typedef struct {
    uint32_t id;
    process_type_t process_type;
    process_state_t process_state;
    pid_t pid;
    uint16_t restart_count;
    uint64_t startup_timestamp_ms;
} process_t;

typedef struct {
    int signalfd;
    int controlfd;
    int timerfd;
    int context_memfile_fd;
    uint32_t last_used_id;
    size_t procesess_len;
    uint64_t _padding[8];
    process_t processes[];
} context_t;

typedef void (*event_handler_f)(context_t*);

const int MAX_RESTART_COUNT = 5;
const int KRESD_MAX_ARGS = 32;
const char* ENV_STATE_FD = "_STATE_FD";
const char* ENV_KRESD_START_ARGS = "_KR_KRESD_START";
const char* ENV_GC_START_ARGS = "_KR_GC_START";
const char* MANAGER_COMMAND_PREFIX[4] = {"env", "python3", "-m", "knot_resolver_manager"};
//const char* MANAGER_COMMAND_PREFIX[1] = {"bash"};
#define CONTROL_SOCKET_NAME "knot-resolver-control-socket"
#define NOTIFY_SOCKET_NAME "NOTIFY_SOCKET"
#define NOTIFY_SOCKET_READY_MSG "READY=1"
const uint64_t STARTUP_TIME_LIMIT_MS = 3600*5*1000;

const int CONTROL_CONNECTION_BACKLOG = 16;
const uint64_t INTERVAL_SEC = 3;
#define MAX_PROCESSES 256
const size_t CONTEXT_MAX_SIZE = sizeof(context_t) + MAX_PROCESSES*sizeof(process_t);


static size_t starting_list_first_empty = 0;
static process_t* starting_list[MAX_PROCESSES];
static char** global_argv;
static int global_argc;

static uint64_t current_timestamp_ms() {
    struct timespec res;
    int r = clock_gettime(CLOCK_MONOTONIC, &res);
    if (r < 0) err(1, "clock_gettime");

    return ((uint64_t)res.tv_sec)*1000ull + ((uint64_t)res.tv_nsec / 1000000ull);
}

static void starting_list_add(process_t* proc) {
    assert(starting_list_first_empty < MAX_PROCESSES);
    starting_list[starting_list_first_empty] = proc;
    starting_list_first_empty++;
}

static void starting_list_remove(process_t* proc) {
    size_t i;
    for (i = 0; i < starting_list_first_empty + 1; i++) {
        if (starting_list[i] == proc) break;
        assert(starting_list_first_empty == i); // the loop is one longer so that this fails when we can't find anything
    }

    if (starting_list_first_empty == 1) {
        /* only one element in list */
        starting_list_first_empty = 0;
        starting_list[i] = NULL;
    } else {
        /* more then one element => move the last over the removed element */
        starting_list[i] = starting_list[starting_list_first_empty - 1];
        starting_list[starting_list_first_empty - 1] = NULL;
        starting_list_first_empty--;
    }
}


static process_t* get_process_by_pid(context_t* ctx, pid_t pid) {
    for (size_t i = 0; i < ctx->procesess_len; i++) {
        if (ctx->processes[i].pid == pid)
            return &(ctx->processes[i]);
    }
    assert(false);
    return NULL;
}

static process_t* get_process_manager(context_t* ctx) {
    assert(ctx->procesess_len >= 1);
    assert(ctx->processes[0].process_type == MANAGER);

    return &(ctx->processes[0]);
}

static void preexec_cleanup(context_t* ctx) {
    close(ctx->controlfd);
    close(ctx->timerfd);
    close(ctx->signalfd);

    int ctx_fd = ctx->context_memfile_fd;

    int res = munmap(ctx, CONTEXT_MAX_SIZE);
    if (res < 0) err(1, "munmap");

    close(ctx_fd);

    unsetenv(ENV_STATE_FD);
}

static void start_manager(context_t* ctx) {
    preexec_cleanup(ctx);

    /* allocate array for args (no need to worry about cleanup) */
    const int MANAGER_PREFIX_LEN = sizeof(MANAGER_COMMAND_PREFIX) / sizeof(char*);
    int arg_count = (global_argc - 1) + MANAGER_PREFIX_LEN + 1;
    char** args = (char**) malloc(sizeof(char*) * arg_count);

    /* create args array */
    args[arg_count - 1] = NULL;
    for (int i = 0; i < MANAGER_PREFIX_LEN; i++) {
        args[i] = MANAGER_COMMAND_PREFIX[i];
    }
    for (int i = 1; i < global_argc; i++) {
        args[i + MANAGER_PREFIX_LEN - 1] = global_argv[i];
    }

    execvp(args[0], args);
    err(1, "execvp");
}

static void start_kresd(context_t* ctx) {
    preexec_cleanup(ctx);

    /* allocate args */
    char* args[KRESD_MAX_ARGS];
    
    /* fill args */
    char name[sizeof(ENV_KRESD_START_ARGS) + 16]; // name + number
    for (int i = 0; i < KRESD_MAX_ARGS; i++) {
        snprintf(name, sizeof(name), "%s%d", ENV_KRESD_START_ARGS, i);
        args[i] = getenv(name);
        if (args[i] == NULL) break;
    }

    execvp(args[0], args);
    err(1, "execvp");
}

static void start_gc(context_t* ctx) {
    preexec_cleanup(ctx);

    /* allocate args */
    char* args[KRESD_MAX_ARGS];
    
    /* fill args */
    char name[sizeof(ENV_GC_START_ARGS) + 16]; // name + number
    for (int i = 0; i < KRESD_MAX_ARGS; i++) {
        snprintf(name, sizeof(name), "%s%d", ENV_GC_START_ARGS, i);
        args[i] = getenv(name);
        if (args[i] == NULL) break;
    }

    execvp(args[0], args);
    err(1, "execvp");
}

static void process_transition(context_t* ctx, process_t* proc, process_state_t target_state) {
    if (target_state == STARTING) {
        assert(proc->process_state == CREATED || proc->process_state == RESTARTING);

        pid_t pid = fork();
        if (pid == 0) {
            /* child */
            switch (proc->process_type) {
                case KRESD: {
                    start_kresd(ctx);
                    break;
                }
                case GC: {
                    start_gc(ctx);
                    break;
                }
                case MANAGER: {
                    start_manager(ctx);
                    break;
                }
                default:
                    assert(false);
            }
        } else {
            /* parent */
            proc->pid = pid;
            proc->process_state = STARTING;
            proc->startup_timestamp_ms = current_timestamp_ms();
            starting_list_add(proc);
            return;
        }
    } else if (target_state == RUNNING) {
        assert(proc->process_state == STARTING);
        proc->process_state = RUNNING;
        starting_list_remove(proc);
        /* nothing special */
    } else {
        assert(false);
    }
}

static void process_create(context_t* ctx, process_type_t type) {
    size_t i = ctx->procesess_len;
    ctx->procesess_len++;
    assert(i < MAX_PROCESSES);

    process_t* proc = &(ctx->processes[i]);
    proc->process_type = type;
    proc->process_state = CREATED;
    proc->restart_count = 0;
    proc->pid = -1;
    proc->id = ++ctx->last_used_id;

    process_transition(ctx, proc, STARTING);
}

static bool should_we_do_full_system_boot(context_t* ctx) {
    return ctx->procesess_len == 0;
}



static int init_signalfd() {
    /* block normal delivery of signals */
    sigset_t mask;
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGHUP);
    int res = sigprocmask(SIG_BLOCK, &mask, NULL);
    if (res != 0) err(1, "sigprocmask");

    /* send the blocked signals via signalfd */
    int signal_fd = signalfd(-1, &mask, SFD_NONBLOCK);
    if (signal_fd == -1) err(1, "signalfd");

    return signal_fd;
}

int init_control_socket() {
    /* create socket */
    int controlfd = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (controlfd == -1) err(1, "socket");

    /* create address */
    struct sockaddr_un server_addr;
    bzero(&server_addr, sizeof(server_addr));
    server_addr.sun_family = AF_UNIX;
    server_addr.sun_path[0] = '\0';  // mark it as abstract namespace socket
    strcpy(server_addr.sun_path + 1, CONTROL_SOCKET_NAME);
    size_t addr_len = offsetof(struct sockaddr_un, sun_path) + strlen(CONTROL_SOCKET_NAME) + 1;

    /* bind to the address */
    int res = bind(controlfd, (struct sockaddr*)&server_addr, addr_len);
    if (res < 0) err(1, "bind");

    /* make sure that we are send credentials */
    int data = (int) true;
    res = setsockopt(controlfd, SOL_SOCKET, SO_PASSCRED, &data, sizeof(data));
    if (res < 0) err(1, "setsockopt");

    /* store the name of the socket in env to fake systemd */
    char* old_value = getenv(NOTIFY_SOCKET_NAME);
    if (old_value != NULL) {
        printf("[init] warning, running under systemd and overwriting $%s\n", NOTIFY_SOCKET_NAME);
        // fixme
    }
    
    res = setenv(NOTIFY_SOCKET_NAME, "@" CONTROL_SOCKET_NAME, 1);
    if (res < 0) err(1, "setenv");

    return controlfd;
}

int init_timerfd() {
    /* create timerfd */
    int timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (timerfd < 0) err(1, "timerfd_create");

    /* arm the timer */
    struct itimerspec timer_value;
    bzero(&timer_value, sizeof(timer_value));
    timer_value.it_interval.tv_sec = INTERVAL_SEC;
    timer_value.it_value.tv_sec = INTERVAL_SEC;
    int res = timerfd_settime(timerfd, 0, &timer_value, NULL);
    if (res < 0) err(1, "timerfd_settime");

    return timerfd;
}

context_t* map_persistent_state_to_memory(int state_fd) {
    /* make sure we have enough space for all our data */
    int res = ftruncate(state_fd, CONTEXT_MAX_SIZE);
    if (res < 0) err(1, "ftruncate");

    /* map the memory file to memeory */
    context_t* ctx = mmap(NULL, CONTEXT_MAX_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, state_fd, 0);
    if (ctx == MAP_FAILED) err(1, "mmap");

    ctx->context_memfile_fd = state_fd;
    return ctx;
}

static void handle_control_socket_connection_event(context_t* ctx) {
    /* read command assuming it fits and it was sent all at once */
    // prepare space to read filedescriptors
    struct msghdr msg;
    msg.msg_name = NULL;
    msg.msg_namelen = 0;

    // prepare a place to read the actual message
    char place_for_data[1500];
    bzero(&place_for_data, sizeof(place_for_data));
    struct iovec iov = {
        .iov_base = &place_for_data,
        .iov_len = sizeof(place_for_data)
    };
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    char cmsg[CMSG_SPACE(sizeof(struct ucred))];
    msg.msg_control = cmsg;
    msg.msg_controllen = sizeof(cmsg);

    /* Receive real plus ancillary data */
    int len = recvmsg(ctx->controlfd, &msg, 0);
    if (len == -1) err(1, "recvmsg");

    /* read the sender pid */
    struct cmsghdr *cmsgp = CMSG_FIRSTHDR(&msg);
    pid_t pid = -1;
    while (cmsgp != NULL) {
        if (cmsgp->cmsg_type == SCM_CREDENTIALS) {
            
            assert(cmsgp->cmsg_len == CMSG_LEN(sizeof(struct ucred)));
            assert(cmsgp->cmsg_level == SOL_SOCKET);

            struct ucred cred;
            memcpy(&cred, CMSG_DATA(cmsgp), sizeof(cred));
            pid = cred.pid;
        }
        cmsgp = CMSG_NXTHDR(&msg, cmsgp);
    }
    if (pid == -1) {
        printf("[control] ignoring received data without credentials: %s\n", place_for_data);
        return;
    }

    /* handle command */
    int res = strncmp(place_for_data, NOTIFY_SOCKET_READY_MSG, sizeof(NOTIFY_SOCKET_READY_MSG));
    if (res == 0) {
        /* it's ready notification */
        
        printf("[control] ready notification from pid=%d\n", pid);
        process_t* proc = get_process_by_pid(ctx, pid);
        process_transition(ctx, proc, RUNNING);
    } else {
        /* it's something else */
        printf("[control] received unknown command: %s\n", place_for_data);
    }
}



static void handle_signal_fd_event(context_t* ctx) {
    struct signalfd_siginfo info;
    int res = read(ctx->signalfd, &info, sizeof(info));
    if (res < 0) err(1, "read");

    switch (info.ssi_signo) {
        case SIGINT:
        case SIGTERM: {
            printf("[signal] forcefully terminating everything with SIGKILL\n");
            for (size_t i = 0; i < ctx->procesess_len; i++) {
                process_t* proc = &(ctx->processes[i]);
                if (proc->pid != -1) {
                    kill(proc->pid, SIGKILL);
                }
            }
            /* we should technically wait for the children, but this is a hack and init cleans up after us */
            /* TODO stop everything cleanly */
            exit(0);
        }
        case SIGHUP: {
            printf("[signal] SIGHUP => performing restart\n");
            execv(global_argv[0], global_argv);
            err(1, "execv");
        }
        case SIGCHLD: {
            printf("[signal] SIGCHLD\n");
            int status;
            pid_t pid = waitpid(-1, &status, WNOHANG);
            if (pid < 0) err(1, "waitpid");
            if (pid > 0) {
                process_t* proc = get_process_by_pid(ctx, pid);
                proc->restart_count++;
                if (proc->restart_count < MAX_RESTART_COUNT) {
                    proc->process_state = RESTARTING;
                    process_transition(ctx, proc, STARTING);
                } else {
                    proc->process_state = FAILED;
                    assert(("too many restarts of a process", false)); //fixme handling
                }

            }
            break;
        }
        default: {
            printf("[signal] unknown %u\n", info.ssi_signo);
        }
    }
}

static void handle_timer_event(context_t* ctx) {
    uint64_t data;
    int res = read(ctx->timerfd, &data, sizeof(data));
    if (res < 0) err(1, "read");

    printf("[timer] tick %lu\n", data);

    uint64_t currtime = current_timestamp_ms();
    for (size_t i = 0; i < starting_list_first_empty; i++) {
        uint64_t dt = currtime - starting_list[i]->startup_timestamp_ms;
        if (dt > STARTUP_TIME_LIMIT_MS) {
            printf("[timer] process pid=%d exceeded max startup time\n", starting_list[i]->pid);
            assert(false);
        }
    }
}

int main(int argc, char** argv) {
    /* save args for later exec */
    global_argv = argv;
    global_argc = argc;


    const char* state_fd_env = getenv(ENV_STATE_FD);
    int state_fd;
    if (state_fd_env != NULL) {
        /* we are running after restart, so we can just read the old state and be done */
        errno = 0;
        state_fd = (int) strtol(state_fd_env, NULL, 10);
        assert(state_fd > 2);
        if (errno != 0) err(1, "strol");
        
    } else {
        /* generate new anonymous file for state storage */
        state_fd = memfd_create("state", 0); // specifically no MFD_CLOEXEC
        if (state_fd == -1) err(1, "memfd_create");

        /* save the state FD to env variable, so that we can access it after restart */
        char buff[16];
        snprintf(buff, 16, "%d", state_fd);
        int res = setenv(ENV_STATE_FD, buff, 1);
        if (res != 0) err(1, "setenv");
    }

    context_t* ctx = map_persistent_state_to_memory(state_fd);

    if (should_we_do_full_system_boot(ctx)) {
        printf("[init] performing full system startup\n");

        /* open control unix socket */
        ctx->controlfd = init_control_socket();
        
        /* open signalfd file descriptor */
        ctx->signalfd = init_signalfd();

        /* start timer */
        ctx->timerfd = init_timerfd();

        /* redundant, this should be zero due to ftruncate() */
        ctx->procesess_len = 0;
        ctx->last_used_id = 0;

        /* start manager process */
        process_create(ctx, MANAGER);
        //ctx->procesess_len++;
    }



    int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd < 0) err(1, "epoll_create");

    /* register control socket */
    struct epoll_event control_event = {
        .events = EPOLLIN,
        .data = ((void*) &handle_control_socket_connection_event),
    };
    int res = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ctx->controlfd, &control_event);
    if (res < 0) err(1, "epoll_ctl");

    /* register signal socket */
    struct epoll_event signal_event = {
        .events = EPOLLIN,
        .data = ((void*) &handle_signal_fd_event),
    };
    res = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ctx->signalfd, &signal_event);
    if (res < 0) err(1, "epoll_ctl");

    /* register timerfd */
    struct epoll_event timer_event = {
        .events = EPOLLIN,
        .data = ((void*) &handle_timer_event),
    };
    res = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ctx->timerfd, &timer_event);
    if (res < 0) err(1, "epoll_ctl");


    printf("[main loop] starting\n");
    while (true) {
        /* wait for an event */
        struct epoll_event event;
        res = epoll_wait(epoll_fd, &event, 1, -1);
        if (res < 0) err(1, "epoll_wait");

        /* invoke handler for the appropriate event */
        event_handler_f handler = (event_handler_f) event.data.ptr;
        handler(ctx);
    }

}


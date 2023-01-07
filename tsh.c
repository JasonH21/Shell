/**
 * @file tsh.c
 * @brief A tiny shell program with job control
 *
 * TODO: Delete this comment and replace it with your own.
 * <The line above is not a sufficient documentation.
 *  You will need to write your program documentation.
 *  Follow the 15-213/18-213/15-513 style guide at
 *  http://www.cs.cmu.edu/~213/codeStyle.html.>
 *
 * @author Your Name <andrewid@andrew.cmu.edu>
 * TODO: Include your name and Andrew ID here.
 */

#include "csapp.h"
#include "tsh_helper.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 * If DEBUG is defined, enable contracts and printing on dbg_printf.
 */
#ifdef DEBUG
/* When debugging is enabled, these form aliases to useful functions */
#define dbg_printf(...) printf(__VA_ARGS__)
#define dbg_requires(...) assert(__VA_ARGS__)
#define dbg_assert(...) assert(__VA_ARGS__)
#define dbg_ensures(...) assert(__VA_ARGS__)
#else
/* When debugging is disabled, no code gets generated for these */
#define dbg_printf(...)
#define dbg_requires(...)
#define dbg_assert(...)
#define dbg_ensures(...)
#endif

/* Function prototypes */
void eval(const char *cmdline);

void sigchld_handler(int sig);
void sigtstp_handler(int sig);
void sigint_handler(int sig);
void sigquit_handler(int sig);
void cleanup(void);

/**
 * @brief <Write main's function header documentation. What does main do?>
 *
 * TODO: Delete this comment and replace it with your own.
 *
 * "Each function should be prefaced with a comment describing the purpose
 *  of the function (in a sentence or two), the function's arguments and
 *  return value, any error cases that are relevant to the caller,
 *  any pertinent side effects, and any assumptions that the function makes."
 */
int main(int argc, char **argv) {
    char c;
    char cmdline[MAXLINE_TSH]; // Cmdline for fgets
    bool emit_prompt = true;   // Emit prompt (default)

    // Redirect stderr to stdout (so that driver will get all output
    // on the pipe connected to stdout)
    if (dup2(STDOUT_FILENO, STDERR_FILENO) < 0) {
        perror("dup2 error");
        exit(1);
    }

    // Parse the command line
    while ((c = getopt(argc, argv, "hvp")) != EOF) {
        switch (c) {
        case 'h': // Prints help message
            usage();
            break;
        case 'v': // Emits additional diagnostic info
            verbose = true;
            break;
        case 'p': // Disables prompt printing
            emit_prompt = false;
            break;
        default:
            usage();
        }
    }

    // Create environment variable
    if (putenv("MY_ENV=42") < 0) {
        perror("putenv error");
        exit(1);
    }

    // Set buffering mode of stdout to line buffering.
    // This prevents lines from being printed in the wrong order.
    if (setvbuf(stdout, NULL, _IOLBF, 0) < 0) {
        perror("setvbuf error");
        exit(1);
    }

    // Initialize the job list
    init_job_list();

    // Register a function to clean up the job list on program termination.
    // The function may not run in the case of abnormal termination (e.g. when
    // using exit or terminating due to a signal handler), so in those cases,
    // we trust that the OS will clean up any remaining resources.
    if (atexit(cleanup) < 0) {
        perror("atexit error");
        exit(1);
    }

    // Install the signal handlers
    Signal(SIGINT, sigint_handler);   // Handles Ctrl-C
    Signal(SIGTSTP, sigtstp_handler); // Handles Ctrl-Z
    Signal(SIGCHLD, sigchld_handler); // Handles terminated or stopped child

    Signal(SIGTTIN, SIG_IGN);
    Signal(SIGTTOU, SIG_IGN);

    Signal(SIGQUIT, sigquit_handler);

    // Execute the shell's read/eval loop
    while (true) {
        if (emit_prompt) {
            printf("%s", prompt);

            // We must flush stdout since we are not printing a full line.
            fflush(stdout);
        }

        if ((fgets(cmdline, MAXLINE_TSH, stdin) == NULL) && ferror(stdin)) {
            perror("fgets error");
            exit(1);
        }

        if (feof(stdin)) {
            // End of file (Ctrl-D)
            printf("\n");
            return 0;
        }

        // Remove any trailing newline
        char *newline = strchr(cmdline, '\n');
        if (newline != NULL) {
            *newline = '\0';
        }

        // Evaluate the command line
        eval(cmdline);
    }

    return -1; // control never reaches here
}
void bgfgHelper(struct cmdline_tokens token, bool isBg) {

    jid_t jid;
    pid_t pid;
    sigset_t mask;
    sigfillset(&mask);
    sigprocmask(SIG_BLOCK, &mask, NULL);
    if (token.argc < 2) {
        sio_printf("%s arg isnt processID or %%jobID\n", token.argv[0]);
        return;
    } else if (token.argv[1][0] == '%') {
        jid = atoi(&token.argv[1][1]);
        pid = job_get_pid(jid);
        if (!job_exists(jid)) {
            sio_printf("%%%d: Job does not exist\n", (int)jid);
            return;
        }
    } else {
        pid = atoi(&token.argv[1][0]);
        jid = job_from_pid(pid);
        if (pid == 0) {
            sio_printf("%s arg isnt processID or %%jobID\n", token.argv[0]);
            return;
        } else if (pid < 1) {
            return;
        }
    }

    kill(-pid, SIGCONT);
    if (!isBg) {
        job_set_state(jid, FG);

        sigset_t suspension;
        sigemptyset(&suspension);

        while (fg_job()) {
            sigsuspend(&suspension);
        }
    } else {
        job_set_state(jid, BG);
        sio_printf("[%d] (%d) %s\n", jid, pid, job_get_cmdline(jid));
    }
    sigprocmask(SIG_UNBLOCK, &mask, NULL);
}
/**
 * @brief <What does eval do?>
 *
 * TODO: Delete this comment and replace it with your own.
 *
 * NOTE: The shell is supposed to be a long-running process, so this function
 *       (and its helpers) should avoid exiting on error.  This is not to say
 *       they shouldn't detect and print (or otherwise handle) errors!
 *   Code taken/ inspired by Textbook
 */
void eval(const char *cmdline) {
    parseline_return parse_result;
    struct cmdline_tokens token;

    pid_t processID;
    jid_t jobID;

    // Parse command line
    parse_result = parseline(cmdline, &token);

    if (parse_result == PARSELINE_ERROR || parse_result == PARSELINE_EMPTY) {
        return;
    }

    sigset_t mask;
    sigfillset(&mask);

    // TODO: Implement commands here.
    if (token.builtin == 8) {
        sigprocmask(SIG_BLOCK, &mask, NULL);
        if ((processID = fork()) == 0) {
            sigprocmask(SIG_UNBLOCK, &mask, NULL);
            setpgid(0, 0);
            if (execve(token.argv[0], token.argv, environ) < 0) {
                if (errno == EACCES) {
                    printf("Command not found");
                    exit(0);
                }
            }
        }
        sigprocmask(SIG_BLOCK, &mask, NULL);
        jobID =
            add_job(processID, parse_result == PARSELINE_FG ? FG : BG, cmdline);
        sigprocmask(SIG_UNBLOCK, &mask, NULL);
        sigprocmask(SIG_BLOCK, &mask, NULL);

        if (parse_result == PARSELINE_FG) {
            sigset_t suspension;
            sigemptyset(&suspension);
            while (fg_job()) {
                sigsuspend(&suspension);
            }
        } else {
            printf("[%d] (%d) %s\n", jobID, processID, cmdline);
        }
        sigprocmask(SIG_UNBLOCK, &mask, NULL);
    } else if (token.builtin == 9) {
        exit(0);
    } else if (token.builtin == 10) {
        sigprocmask(SIG_BLOCK, &mask, NULL);
        list_jobs(STDOUT_FILENO);
        sigprocmask(SIG_UNBLOCK, &mask, NULL);
    } else if (token.builtin == 11) {
        bgfgHelper(token, true);

    } else if (token.builtin == 12) {
        bgfgHelper(token, false);
    }
    return;
}

/*****************
 * Signal handlers
 *****************/

/**
 * @brief <What does sigchld_handler do?>
 *
 * TODO: Delete this comment and replace it with your own.
 */
void sigchld_handler(int sig) {
    int olderrno = errno;
    sigset_t mask_all, prev_all;
    int status;
    pid_t pid;
    jid_t jid;
    sigfillset(&mask_all);
    sigprocmask(SIG_BLOCK, &mask_all, &prev_all);

    while ((pid = waitpid(-1, &status, WNOHANG | WUNTRACED)) > 0) {
        jid = job_from_pid(pid);
        if ((WIFSIGNALED(status))) {
            sio_printf("Job [%d] (%d) terminated by signal %d\n", jid, pid,
                       WTERMSIG(status));
            delete_job(jid);
        } else if ((WIFSTOPPED(status))) {
            job_set_state(jid, ST);
            sio_printf("Job [%d] (%d) stopped by signal %d\n", jid, pid,
                       WSTOPSIG(status));
        } else if (WIFEXITED(status)) {
            delete_job(jid);
        }
    }

    sigprocmask(SIG_UNBLOCK, &mask_all, NULL);
    errno = olderrno;
}
void sigHelper(int sig, bool isInt) {
    int olderrno = errno;
    sigset_t mask_all;
    sigfillset(&mask_all);
    sigprocmask(SIG_BLOCK, &mask_all, NULL);
    jid_t jid;
    pid_t pid;

    jid = fg_job();
    if (job_exists(jid)) {
        pid = job_get_pid(jid);
        if (pid > 1) {
            if (isInt) {
                kill(-pid, SIGINT);
            } else {
                kill(-pid, SIGTSTP);
            }
        }
    }
    sigprocmask(SIG_UNBLOCK, &mask_all, NULL);
    errno = olderrno;
}
/**
 * @brief <What does sigint_handler do?>
 *
 * TODO: Delete this comment and replace it with your own.
 */
void sigint_handler(int sig) {
    sigHelper(sig, true);
}

/**
 * @brief <What does sigtstp_handler do?>
 *
 * TODO: Delete this comment and replace it with your own.
 */
void sigtstp_handler(int sig) {
    sigHelper(sig, false);
}

/**
 * @brief Attempt to clean up global resources when the program exits.
 *
 * In particular, the job list must be freed at this time, since it may
 * contain leftover buffers from existing or even deleted jobs.
 */
void cleanup(void) {
    // Signals handlers need to be removed before destroying the joblist
    Signal(SIGINT, SIG_DFL);  // Handles Ctrl-C
    Signal(SIGTSTP, SIG_DFL); // Handles Ctrl-Z
    Signal(SIGCHLD, SIG_DFL); // Handles terminated or stopped child

    destroy_job_list();
}

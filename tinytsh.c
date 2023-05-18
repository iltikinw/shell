/**
 * @file tinytsh.c
 * @brief A tiny shell program with job control
 *
 * A shell a program that takes commands from the keyboard and gives them
 * to the operating system to perform. It continuously read and evaluates
 * command line arguments in a loop.
 *
 * My implementation uses the main function to parse the command line and
 * initialize all environment variables, structures, and values. It then
 * repeatedly uses the <eval> function to evaluate the command line.
 *
 * High-level overview:
 *     1. Command line parsed.
 *     2. Built-in commands evaluated.
 *     3. Child process forked, non-built-in command run within child.
 *     4. Global resources cleaned up upon program exit.
 *
 * I provide custom functions to handle signals to parent and child processes.
 * Additionally, I handle background and foreground processes in their
 * respective functions.
 *
 * Descriptions of individual functions, data structures, and global variables
 * are provided in their respective leading comments.
 *
 * @author Iltikin Wayet
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

/* Helper function prototypes **********/
static int get_fd(struct cmdline_tokens *token, bool output);
static bool set_id(struct cmdline_tokens *token, int *pid, int *jid,
                   sigset_t *mask_all, sigset_t *mask_prev, bool fg);
static void execvp_w(struct cmdline_tokens *token);

/* Eval function prototypes ************/
void eval(const char *cmdline);
static bool builtin_eval(struct cmdline_tokens *token);
static void foreground_eval(struct cmdline_tokens *token);
static void background_eval(struct cmdline_tokens *token);
static bool jobs_eval(struct cmdline_tokens *token, sigset_t *mask_all,
                      sigset_t *mask_prev);

/* Signal handler prototypes ***********/
void sigchld_handler(int sig);
void sigtstp_handler(int sig);
void sigint_handler(int sig);
void sigquit_handler(int sig);
void cleanup(void);

/**********************************
         EVAL SHELL FUNCTIONS
 **********************************/

/**
 * @brief Executes the shell's read/evaluate loop.
 *     First parses command line, creates environment, install signal handlers
 *
 * @param[in] argc : number of command line arguments.
 * @param[in] argv : command line input.
 *
 * @return 0 is successful execution, nonzero if failure.
 */
int main(int argc, char **argv) {
    int c;
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
    if (putenv(strdup("MY_ENV=42")) < 0) {
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

/**
 * @brief Parses and evaluates command line arguments.
 *     Fills signal set and runs command line instructions via child process.
 *     Adds respective jobs to job list.
 *
 * @param[in] cmdline : command line input text.
 */
void eval(const char *cmdline) {
    parseline_return parse_result;
    struct cmdline_tokens token;

    // Parse command line
    parse_result = parseline(cmdline, &token);
    if (parse_result == PARSELINE_ERROR || parse_result == PARSELINE_EMPTY) {
        return;
    }

    sigset_t mask_all, prev_one;
    if (!builtin_eval(&token)) {
        // Fill signal set. Block all signals as suggested by Prof.
        sigfillset(&mask_all);
        sigprocmask(SIG_BLOCK, &mask_all, &prev_one);

        // Run command line instructions via child process.
        pid_t child_pid = fork();
        if (child_pid == 0) {
            // Unblock signals.
            sigprocmask(SIG_SETMASK, &prev_one, NULL);

            // Set a process group ID matching child process ID.
            // Handle possible error accordingly.
            int setpgid_ret = setpgid(child_pid, child_pid);
            if (setpgid_ret < 0) {
                perror("setpgid Error\n");
                exit(0);
            }

            // Setting input/output file descriptor values.
            int output_fd = get_fd(&token, true);
            int input_fd = get_fd(&token, false);

            // If we have 2 valid file descriptors
            // update standard input and output accordingly.
            // Else, we exit.
            if (output_fd >= 0 && input_fd >= 0) {
                dup2(output_fd, 1);
                dup2(input_fd, 0);
            } else {
                exit(0);
            }

            // Stuffed in wrapper since looks nicer.
            execvp_w(&token);
            exit(0);
        }

        // Add respective jobs to job list.
        if (parse_result == PARSELINE_FG) {
            add_job(child_pid, FG, cmdline);
            // Wait for foreground child process to terminate.
            while (fg_job() > 0) {
                sigsuspend(&prev_one);
            }
        } else if (parse_result == PARSELINE_BG) {
            add_job(child_pid, BG, cmdline);
            jid_t jid = job_from_pid(child_pid);
            // Since background task, simply print info no waiting.
            printf("[%d] (%d) %s\n", jid, child_pid, job_get_cmdline(jid));
        }
        sigprocmask(SIG_SETMASK, &prev_one, NULL);
    }
}

/**
 * @brief Helper function to check if token is a builtin command.
 *     If builtin, handles accordingly. If not, returns false.
 *
 * @param[in] token : tokens from parsing command line.
 * @return true if builtin function, false if not.
 *     Still returns true if errors in opening file.
 */
static bool builtin_eval(struct cmdline_tokens *token) {
    sigset_t mask_all, mask_prev;
    sigfillset(&mask_all);

    switch (token->builtin) {
    case BUILTIN_NONE:
        return false;
    case BUILTIN_QUIT:
        exit(0);
        return true;
    case BUILTIN_JOBS:
        // Listing jobs via helper.
        return jobs_eval(token, &mask_all, &mask_prev);
    case BUILTIN_BG:
        background_eval(token);
        return true;
    case BUILTIN_FG:
        foreground_eval(token);
        return true;
    default:
        return false;
    }
}

/**
 * @brief Evaluates a foreground process.
 *     Sets process and job ids according to command line tokens.
 *     Afterwards, sets the state of the job and waits for termination.
 *
 * @param[in] token : tokens from parsing command line.
 */
static void foreground_eval(struct cmdline_tokens *token) {
    sigset_t mask_all, mask_prev;
    pid_t pid;
    jid_t jid;

    // First, check for valid command.
    if (token->argc != 2) {
        fprintf(stderr, "fg command requires PID or %%jobid argument\n");
        return;
    }

    sigfillset(&mask_all);
    // Set process and job ids according to token values.
    if (!set_id(token, &pid, &jid, &mask_all, &mask_prev, true))
        return;

    sigprocmask(SIG_BLOCK, &mask_all, &mask_prev);
    // Update status of the job id.
    if (job_get_state(jid) == UNDEF) {
        fprintf(stderr, "Job ID undefined error.\n");
    } else {
        job_set_state(jid, FG);
        pid = getpgid(pid);
        kill(-pid, SIGCONT);
        while (fg_job() > 0) {
            sigsuspend(&mask_prev);
        }
    }
    sigprocmask(SIG_SETMASK, &mask_prev, NULL);
}

/**
 * @brief Evaluates a background process.
 *     Sets process and job ids according to command line tokens.
 *     Afterwards, sets the state of the job and prints relevant info.
 *
 * @param[in] token : tokens from parsing command line.
 */
static void background_eval(struct cmdline_tokens *token) {
    sigset_t mask_all, mask_prev;
    pid_t pid;
    jid_t jid;

    // First, check for valid command.
    if (token->argc != 2) {
        fprintf(stderr, "bg command requires PID or %%jobid argument\n");
        return;
    }

    sigfillset(&mask_all);
    // Set process and job ids according to token values.
    if (!set_id(token, &pid, &jid, &mask_all, &mask_prev, false))
        return;

    sigprocmask(SIG_BLOCK, &mask_all, &mask_prev);
    // Update status of job id
    if (job_get_state(jid) == UNDEF) {
        fprintf(stderr, "Job ID undefined error.\n");
    } else {
        job_set_state(jid, BG);
        pid = getpgid(pid);
        kill(-pid, SIGCONT);
        printf("[%d] (%d) %s\n", jid, job_get_pid(jid), job_get_cmdline(jid));
    }
    sigprocmask(SIG_SETMASK, &mask_prev, NULL);
}

/**
 * @brief Helper function to list running jobs.
 *     Sets output file descriptor (fd) according to filename.
 *     Checks validity of fd, blocks signals and lists jobs accordingly.
 *
 * @param[in] token     : tokens from parsing command line.
 * @param[in] mask_all  : pointer to mask_all integer declared in caller.
 * @param[in] mask_prev : pointer to mask_prev integer declared in caller.
 */
static bool jobs_eval(struct cmdline_tokens *token, sigset_t *mask_all,
                      sigset_t *mask_prev) {
    int output_fd = get_fd(token, true);
    // If we have a valid file descriptor.
    // i.e. no errors in opening the file, list jobs from file descriptor.
    if (output_fd > -1) {
        sigprocmask(SIG_BLOCK, mask_all, mask_prev);
        list_jobs(output_fd);
        sigprocmask(SIG_SETMASK, mask_prev, NULL);
    }
    return true;
}

/**********************************
          SIGNAL HANDLERS
 **********************************/

/**
 * @brief Handles a SIGCHLD signal.
 *     Preserves <errno> during execution.
 *     Handles child process stop/termination cases.
 *
 * @param[in] sig : input signal
 */
void sigchld_handler(int sig) {
    sigset_t mask_all, mask_prev;

    int errno_prev = errno;
    pid_t pid = waitpid(-1, &sig, WNOHANG | WUNTRACED);
    sigfillset(&mask_all);

    while (pid > 0) {
        // Block all other signals while checking.
        sigprocmask(SIG_BLOCK, &mask_all, &mask_prev);
        jid_t jid = job_from_pid(pid);

        // Check signals in order: terminate, exit, stop.
        if (WIFSIGNALED(sig)) {
            printf("Job [%d] (%d) terminated by signal %d\n", jid, pid,
                   WTERMSIG(sig));
            delete_job(jid);
        } else if (WIFEXITED(sig)) {
            delete_job(jid);
        } else if (WIFSTOPPED(sig)) {
            printf("Job [%d] (%d) stopped by signal %d\n", jid, pid,
                   WSTOPSIG(sig));
            job_set_state(jid, ST);
        }

        // Restore signals and update pid.
        sigprocmask(SIG_SETMASK, &mask_prev, NULL);
        pid = waitpid(-1, &sig, WNOHANG | WUNTRACED);
    }
    errno = errno_prev;
}

/**
 * @brief Handles a SIGINT signal.
 *     Preserves <errno> during execution.
 *     Handles foreground job accordingly.
 *
 * @param[in] sig : input signal
 */
void sigint_handler(int sig) {
    sigset_t mask_all, mask_prev;

    int errno_prev = errno;
    sigfillset(&mask_all);
    sigprocmask(SIG_BLOCK, &mask_all, &mask_prev);

    // Check if foreground job running and kill process group.
    jid_t jid = fg_job();
    if (jid != 0) {
        pid_t pid = getpgid(job_get_pid(fg_job()));
        kill(-pid, SIGINT);
    }

    // If no foreground job, unblock signals and restore errno.
    sigprocmask(SIG_SETMASK, &mask_prev, NULL);
    errno = errno_prev;
}

/**
 * @brief Handles a SIGSTP signal.
 *     Preserves <errno> during execution.
 *     Handles foreground job accordingly.
 *
 * @param[in] sig : input signal
 */
void sigtstp_handler(int sig) {
    sigset_t mask_all, mask_prev;

    int errno_prev = errno;
    sigfillset(&mask_all);
    sigprocmask(SIG_BLOCK, &mask_all, &mask_prev);

    // Check if foreground job running and kill process group.
    jid_t jid = fg_job();
    if (jid != 0) {
        pid_t pid = getpgid(job_get_pid(fg_job()));
        kill(-pid, SIGTSTP);
    }

    // If no foreground job, unblock signals and restore errno.
    sigprocmask(SIG_SETMASK, &mask_prev, NULL);
    errno = errno_prev;
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

/**********************************
          HELPER ROUTINES
 **********************************/

/**
 * @brief Returns specified file descriptor of a given token.
 *     If <output> true, returns output file descriptor.
 *     If <output> false, returns input file descriptor.
 *
 * @param[in] token  : tokens from parsing command line.
 * @param[in] output : boolean value specifying desired file descriptor.
 *
 * @return desired file descriptor if successful, negative value if error.
 */
static int get_fd(struct cmdline_tokens *token, bool output) {
    char *filename = output ? token->outfile : token->infile;
    int ret_fd;
    if (filename == NULL) {
        ret_fd = output ? 1 : 0;
    } else {
        ret_fd = output ? open(token->outfile, O_WRONLY | O_CREAT | O_TRUNC,
                               DEF_MODE)
                        : open(token->infile, O_RDONLY);
        // If error in opening the file.
        if (ret_fd < 0) {
            if (errno == EACCES) {
                fprintf(stderr, "%s: Permission denied\n", filename);
            } else {
                fprintf(stderr, "%s: No such file or directory\n", filename);
            }
        }
    }
    return ret_fd;
}

/**
 * @brief Sets job and process ids of a given token accordingly.
 *     Takes process id, job id pointers as input, to be set.
 *     fg parameter purely used to output relevant error message.
 *
 * @param[in] token     : tokens from parsing command line.
 * @param[in] pid       : process id to be set by function.
 * @param[in] jid       : job id to be set by function.
 * @param[in] mask_all  : mask value to be used in blocking signals.
 * @param[in] mask_prev : previous mask value to be used in unblock/restoring
 * signals.
 * @param[in] fg        : true if foreground process, false if background
 * process. Only used to output relevant process error message.
 *
 * @return true if successful, false if error.
 */
static bool set_id(struct cmdline_tokens *token, int *pid, int *jid,
                   sigset_t *mask_all, sigset_t *mask_prev, bool fg) {
    // Check if job id or process id inputted.
    // % if job id.
    if (token->argv[1][0] == '%') {
        // Major risk for errors here.
        // But if invalid will be handled by job_exists() anyway.
        *jid = (int)strtol(&token->argv[1][1], NULL, 0);
        sigprocmask(SIG_BLOCK, mask_all, mask_prev);

        if (job_exists(*jid)) {
            *pid = job_get_pid(*jid);
            sigprocmask(SIG_SETMASK, mask_prev, NULL);
        } else {
            fprintf(stderr, "%%%d: No such job\n", *jid);
            sigprocmask(SIG_SETMASK, mask_prev, NULL);
            return false;
        }
    } else {
        // Not % if process id.
        *pid = (int)strtol(token->argv[1], NULL, 0);
        sigprocmask(SIG_BLOCK, mask_all, mask_prev);
        *jid = job_from_pid(*pid);

        if (job_exists(*jid)) {
            sigprocmask(SIG_SETMASK, mask_prev, NULL);
        } else {
            // If foreground process, print following error message.
            if (fg) {
                fprintf(stderr, "fg: argument must be a PID or %%jobid\n");

                // If background process, print following error message.
            } else {
                fprintf(stderr, "bg: argument must be a PID or %%jobid\n");
            }
            sigprocmask(SIG_SETMASK, mask_prev, NULL);
            return false;
        }
    }
    return true;
}

/**
 * @brief Wrapper function for execvp C library function.
 *     Allows handling errors in a more aesthetic manner.
 *
 * @param[in] token : tokens from parsing command line.
 */
static void execvp_w(struct cmdline_tokens *token) {
    int execvp_ret = execvp(token->argv[0], token->argv);
    // If returns in error.
    if (execvp_ret < 0) {
        if (errno == EACCES) {
            fprintf(stderr, "%s: Permission denied\n", token->argv[0]);
        } else {
            fprintf(stderr, "%s: No such file or directory\n", token->argv[0]);
        }
        exit(0);
    }
}

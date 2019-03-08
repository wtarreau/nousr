/*
 * Copyright (C) 2015 Willy Tarreau <w@1wt.eu>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#define _GNU_SOURCE // for RTLD_NEXT

#include <sys/epoll.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#include <dlfcn.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int intercepting;
extern char **_dl_argv;

/* copies of certain paths and their real paths */
static const char *env_strict;
static const char *env_trace;
static const char *env_tmpdir;
static const char *env_tcbase;
static const char *env_prjbase;
static const char *env_tmpdir_rp;
static const char *env_tcbase_rp;
static const char *env_prjbase_rp;
static int tmpdir_len;
static int tcbase_len;
static int prjbase_len;
static int tmpdir_rp_len;
static int tcbase_rp_len;
static int prjbase_rp_len;

enum ev_type {
	/* handled syscalls */
	EV_T_LXSTAT,
	EV_T_XSTAT,
	EV_T_ACCESS,
	EV_T_OPEN,
	EV_T_OPEN64,
	/* must always be last */
	EV_T_NUM
};

/* all the syscalls we can intercept */
const char *syscall_names[EV_T_NUM] = {
	[EV_T_XSTAT]        = "__xstat",
	[EV_T_LXSTAT]       = "__lxstat",
	[EV_T_OPEN]         = "open",
	[EV_T_OPEN64]       = "open64",
	[EV_T_ACCESS]       = "access",
};

static void *orig_syscalls[EV_T_NUM];

static char prog_full_path[PATH_MAX];
static char *prog_name;
static int  prog_name_len;

/* returns true if <path> is located under <pattern>, which means that either
 * it's a perfect match, or path is longer and starts with a / at the first
 * difference. If <pattern> is NULL, returns false. <pattern> may not end with
 * a slash and may be empty for the root directory. <patlen> indicates how many
 * chars from <pattern> have to be considered (allows to ignore trailing
 * slashes).
 */
static int is_under(const char *path, const char *pattern, int patlen)
{
	if (!pattern)
		return 0;

	if (!patlen)
		return 1;

	while (patlen && *path == *pattern) {
		path++;
		pattern++;
		patlen--;
	}

	if (patlen)
		return 0;

	if (!*path || *path == '/')
		return 1;
	return 0;
}

/* gets pointer to environment variable <name> and optionally sets its length
 * into <len> after trimming any optional trailing slashes.
 */
static const char *get_path_env(const char *name, int *len)
{
	name = getenv(name);
	if (!name) {
		if (len)
			*len = 0;
		return NULL;
	}
	if (len) {
		int l = strlen(name);

		while (l && name[l - 1] == '/')
			l--;
		*len = l;
	}
	return name;
}

/* returns true if access to <path> is possible according to the rules below :
 *   - allow relative paths not starting with a '/' in their path
 *   - /dev and /tmp are always permitted
 *   - TMPDIR, if set, is always permitted
 *   - PRJBASE, if set, is always permitted
 *   - TCBASE, if set, is always permitted
 *   - deny /usr
 *   - if both TCBASE and PRJDIR are set, deny anything else
 *   - allow anything else
 */
static int is_path_ok(const char *path)
{
	if (*path != '/')
		return 1;

	if (is_under(path, env_tcbase, tcbase_len))
		return 1;

	if (is_under(path, env_tcbase_rp, tcbase_rp_len))
		return 1;

	if (is_under(path, env_prjbase, prjbase_len))
		return 1;

	if (is_under(path, env_prjbase_rp, prjbase_rp_len))
		return 1;

	if (is_under(path, env_tmpdir, tmpdir_len))
		return 1;

	if (is_under(path, env_tmpdir_rp, tmpdir_rp_len))
		return 1;

	if (is_under(path, "/usr", 4))
		return 0;

	if (!env_strict || !env_prjbase || !env_tcbase)
		return 1;

	if (is_under(path, "/dev", 4))
		return 1;

	if (is_under(path, "/tmp", 4))
		return 1;

	return 0;
}


/* fails the syscall by returning exit code 127. Since it is also provides the
 * return code for the intercepted syscalls, it's easy to disable exit() and
 * replace it with a return -1 instead for debugging.
 */
static int fail_syscall(const char *culprit, const char *path)
{
	char cwd[PATH_MAX];

	fprintf(stderr, "FATAL: nousr: program '%s' attempted to access '%s' using %s().\n",
		prog_name, path, culprit);
	fprintf(stderr, "     | full path to program             : %s\n", prog_full_path);
	fprintf(stderr, "     | working directory at call        : %s\n", getcwd(cwd, sizeof(cwd)));
	fprintf(stderr, "     | path to project (NOUSR_PRJBASE)  : %s\n", env_prjbase ? env_prjbase : "[anything not under /usr]");
	fprintf(stderr, "     | path to toolchain (NOUSR_TCBASE) : %s\n", env_tcbase ? env_tcbase : "[anything not under /usr]");
	exit(127);
	return -1;
}

/** below we have the new definitions for the syscalls that we can intercept **/

int open(const char *pathname, int flags, ...)
{
	int (*orig)(const char *, int, ...) = orig_syscalls[EV_T_OPEN];
	int mode;
	va_list args;

	va_start(args, flags);
	mode = va_arg(args, int);
	va_end(args);

	if (intercepting && !is_path_ok(pathname))
		return fail_syscall("open", pathname);

	return orig(pathname, flags, mode);
}

int open64(const char *pathname, int flags, ...)
{
	int (*orig)(const char *, int, ...) = orig_syscalls[EV_T_OPEN64];
	int mode;
	va_list args;

	va_start(args, flags);
	mode = va_arg(args, int);
	va_end(args);

	if (intercepting && !is_path_ok(pathname))
		return fail_syscall("open64", pathname);

	return orig(pathname, flags, mode);
}

int __xstat(int ver, const char *pathname, struct stat *buf)
{
	int (*orig)(int ver, const char *, struct stat *) = orig_syscalls[EV_T_XSTAT];

	if (intercepting && !is_path_ok(pathname))
		return fail_syscall("xstat", pathname);

	return orig(ver, pathname, buf);
}

int __lxstat(int ver, const char *pathname, struct stat *buf)
{
	int (*orig)(int ver, const char *, struct stat *) = orig_syscalls[EV_T_LXSTAT];

	if (intercepting && !is_path_ok(pathname))
		return fail_syscall("lxstat", pathname);

	return orig(ver, pathname, buf);
}

int access(const char *pathname, int mode)
{
	int (*orig)(const char *, int) = orig_syscalls[EV_T_ACCESS];

	if (intercepting && !is_path_ok(pathname))
		return fail_syscall("access", pathname);

	return orig(pathname, mode);
}


/* retrieves the program's name, tries the fast method first */
static char *get_prog_name()
{
	int sz;

	prog_full_path[0] = 0;
	sz = readlink("/proc/self/exe", prog_full_path, sizeof(prog_full_path) - 1);
	if (sz != -1)
		prog_full_path[sz] = 0;

	prog_name = strrchr(prog_full_path, '/');
	if (prog_name)
		prog_name++;
	else
		prog_name = prog_full_path;

	prog_name_len = strlen(prog_name);
	return prog_name;
}

static int program_ends(const char *end)
{
	int len = strlen(end);

	if (prog_name_len < len)
		return 0;

	if (strcmp(prog_name + prog_name_len - len, end) != 0)
		return 0;

	return 1;
}

__attribute__((constructor))
static void nousr_prepare()
{
	int i;

	/* save original syscalls before going any further */
	for (i = 0; i < EV_T_NUM; i++)
		orig_syscalls[i] = dlsym(RTLD_NEXT, syscall_names[i]);

	env_trace      = getenv("NOUSR_TRACE");
	if (env_trace && atoi(env_trace) >= 2) {
		fprintf(stderr, "##nousr##");
		for (i = 0; _dl_argv[i]; i++)
			fprintf(stderr, " %s", _dl_argv[i]);
		fprintf(stderr, "\n");
	}

	/* get some environment variables and the program's name and path */
	env_strict     = getenv("NOUSR_STRICT");
	env_tmpdir     = get_path_env("TMPDIR",        &tmpdir_len);
	env_tcbase     = get_path_env("NOUSR_TCBASE",  &tcbase_len);
	env_prjbase    = get_path_env("NOUSR_PRJBASE", &prjbase_len);

	env_tmpdir_rp  = env_tmpdir  ? realpath(env_tmpdir, NULL)  : NULL;
	env_tcbase_rp  = env_tcbase  ? realpath(env_tcbase, NULL)  : NULL;
	env_prjbase_rp = env_prjbase ? realpath(env_prjbase, NULL) : NULL;

	tmpdir_rp_len  = env_tmpdir_rp  ? strlen(env_tmpdir_rp)  : 0;
	tcbase_rp_len  = env_tcbase_rp  ? strlen(env_tcbase_rp)  : 0;
	prjbase_rp_len = env_prjbase_rp ? strlen(env_prjbase_rp) : 0;

	get_prog_name();

	/* decide whether we want to apply the filtering or not.
	 * If TCBASE is set, we only apply the filtering if the full path starts
	 * with TCBASE. Otherwise we only apply it if the path doesn't start
	 * with /usr.
	 */
	if (env_tcbase && !is_under(prog_full_path, env_tcbase, tcbase_len) &&
	    (!env_tcbase_rp || !is_under(prog_full_path, env_tcbase_rp, tcbase_rp_len)))
		return;

	if (!env_tcbase && is_under(prog_full_path, "/usr", 4))
		return;

	/* OK we know this possibly applies, let's check if the program name
	 * matches one of the well-known ones, or ends ends as one of the well
	 * known suffixes. NOTE: ideally we should only check the suffixes if
	 * TCBASE is set.
	 */
	if (!strcmp(prog_name, "ar")  || !strcmp(prog_name, "as") ||
	    !strcmp(prog_name, "c++") || !strcmp(prog_name, "cc") ||
	    !strcmp(prog_name, "cc1") || !strcmp(prog_name, "cc1plus") ||
	    !strcmp(prog_name, "cpp") || !strcmp(prog_name, "g++") ||
	    !strcmp(prog_name, "gcc") || !strcmp(prog_name, "ld")) {
		intercepting = 1;
	}
	else if (program_ends("-ar") || program_ends("-as") ||
		 program_ends("-c++") || program_ends("-cc") ||
		 program_ends("-cpp") || program_ends("-g++") ||
		 program_ends("-gcc") || program_ends("-ld")) {
		intercepting = 1;
	}

	if (intercepting && env_trace && atoi(env_trace) == 1) {
		fprintf(stderr, "##nousr##");
		for (i = 0; _dl_argv[i]; i++)
			fprintf(stderr, " %s", _dl_argv[i]);
		fprintf(stderr, "\n");
	}
}

/* Called in wrapper mode */
int main(int argc, char **argv)
{
	char *preload;
	int plen;

	/* disable interception that could have been setup by nousr_prepare() */
	intercepting = 0;

	if (argc < 2) {
		fprintf(stderr,
			"nousr - simple guard against accidental use of /usr by toolchains\n"
			"Usage: <%s> [cmd [args...]]\n"
			"       Will install itself in LD_PRELOAD before calling <cmd> with args.\n"
			"\n"
			"Other variables of interest :\n"
			"  - NOUSR_TRACE (1|2) : trace intercepted or all programs [%s]\n"
			"  - NOUSR_PRJBASE     : allow project sources to be there [%s]\n"
			"  - NOUSR_TCBASE      : only consider toolchain there [%s]\n"
			"  - NOUSR_STRICT      : only allow access to project sources and toolchain [%s]\n"
			"",
			argv[0],
			env_trace ? env_trace : "not set",
			env_prjbase ? env_prjbase : "not set",
			env_tcbase ? env_tcbase : "not set",
			env_strict ? "set" : "not set");
		exit(1);
	}

	argc--;
	argv++;

	/* now we'll concatenate ourselves at the end of the LD_PRELOAD variable */
	plen = strlen(prog_full_path);
	preload = getenv("LD_PRELOAD");
	if (preload) {
		int olen = strlen(preload);
		preload = realloc(preload, olen + 1 + plen + 1);
		if (!preload) {
			perror("realloc");
			exit(2);
		}
		preload[olen] = ' ';
		memcpy(preload + olen + 1, prog_full_path, plen);
		preload[olen + 1 + plen] = 0;
	}
	else {
		preload = prog_full_path;
	}

	if (setenv("LD_PRELOAD", preload, 1) < 0) {
		perror("setenv");
		exit(2);
	}

	execvp(*argv, argv);
	perror("execve");
	exit(2);
}

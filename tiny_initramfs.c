/*
 * tiny_initramfs - Minimalistic initramfs implementation
 * Copyright (C) 2016 Christian Seiler <christian@iwakd.de>
 *
 * tiny_initramfs.c: main program
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "tiny_initramfs.h"
#include <stdlib.h>
#include <unistd.h>
#include <sys/mount.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#if defined(ENABLE_MODULES)
#if !defined(HAVE_FINIT_MODULE) && !defined(HAVE_SYS_FINIT_MODULE)
#include <sys/stat.h>
#include <sys/mman.h>
#elif defined(HAVE_SYS_FINIT_MODULE)
#include <sys/syscall.h>
#endif
#endif

static void parse_cmdline();
static int parse_cmdline_helper(void *data, const char *line, int line_is_incomplete);
static void try_exec(int orig_argc, char *const orig_argv[], const char *binary);

static void cleanup_initramfs();

#ifdef ENABLE_DEBUG
static void debug_dump_file(const char *fn);
static int debug_dump_file_helper(void *data, const char *line, int line_is_incomplete);
#endif

#ifdef ENABLE_MODULES
static void load_modules();
static int load_module_helper(void *data, const char *line, int line_is_incomplete);
static int cleanup_module_helper(void *data, const char *line, int line_is_incomplete);
extern int init_module(void *module_image, unsigned long len, const char *param_values);
#endif

static int required_mounts = -1;
static char mount_device[MAX_ROOT_MOUNTS][MAX_PATH_LEN];
static char mount_target[MAX_ROOT_MOUNTS][MAX_PATH_LEN];
static char mount_options[MAX_ROOT_MOUNTS][MAX_LINE_LEN];
static char mount_fstype[MAX_ROOT_MOUNTS][MAX_FILESYSTEM_TYPE_LEN];

static int root_delay;
static int root_wait_indefinitely;
static char init_binary[MAX_PATH_LEN];

int main(int argc, char **argv)
{
  int r;
  int timeout_togo = DEVICE_TIMEOUT;
  char real_device_name[MAX_PATH_LEN] = { 0 };

#ifdef ENABLE_DEBUG
  warn("Began execution", NULL);
#endif

#ifdef ENABLE_MODULES
  load_modules();
#ifdef ENABLE_DEBUG
  warn("Loaded all kernel modules", NULL);
#endif
#endif /* defined(ENABLE_MODULES) */

  r = mount("proc", "/proc", "proc", MS_NODEV | MS_NOEXEC | MS_NOSUID, NULL);
  if (r < 0)
    panic(errno, "Could not mount /proc", NULL);

#ifdef ENABLE_DEBUG
  warn("Mounted /proc", NULL);
#endif

  r = mount("sys", "/sys", "sysfs", MS_NODEV | MS_NOEXEC | MS_NOSUID, NULL);
  if (r < 0)
    panic(errno, "Could not mount /sys", NULL);

#ifdef ENABLE_DEBUG
  warn("Mounted /sys", NULL);
#endif

  r = mount("udev", "/dev", "devtmpfs", 0, DEVTMPFS_MOUNTOPTS);
  if (r < 0)
    panic(errno, "Could not mount /dev (as devtmpfs)", NULL);

#ifdef ENABLE_DEBUG
  warn("Mounted /dev", NULL);
#endif

  parse_cmdline();

#ifdef ENABLE_DEBUG
  warn("Parsed ", PROC_CMDLINE_FILENAME, NULL);
#endif

  if(required_mounts < 0) {
      panic(0, "No root filesystem (mountdevice=... mount_target=/) specified", NULL);
  }

  for (int mount_idx = 0; mount_idx <= required_mounts; mount_idx++) {
    if (strlen(mount_target[mount_idx]) == 0) {
      panic(0, "No mount target for device ", mount_device[mount_idx], " specified", NULL);\
    }
  }
  
  if (root_wait_indefinitely)
    timeout_togo = -1;
  for (int mount_idx = 0; mount_idx <= required_mounts; mount_idx++) {
    wait_for_device(real_device_name, &timeout_togo, mount_device[mount_idx], root_delay);
  }
  
#ifdef ENABLE_DEBUG
  warn("Waited for root device", NULL);
#endif

  for (int mount_idx = 0; mount_idx <= required_mounts; mount_idx++) {
    r = mount_filesystem(real_device_name, mount_target[mount_idx], strlen(mount_fstype[mount_idx]) ? mount_fstype[mount_idx] : NULL, mount_options[mount_idx]);
    if (r < 0)
      panic(-r, "Failed to mount filesystem from ", mount_device[mount_idx], " into ", mount_target[mount_idx], NULL);
  }

#ifdef ENABLE_DEBUG
  warn("Mounted root filesystem", NULL);
#endif

  /* We need these regardless of /usr handling */
  if (access(TARGET_DIRECTORY "/dev", F_OK) != 0)
    panic(errno, "/dev doesn't exist on root filesystem", NULL);
  if (access(TARGET_DIRECTORY "/sys", F_OK) != 0)
    panic(errno, "/sys doesn't exist on root filesystem", NULL);
  if (access(TARGET_DIRECTORY "/proc", F_OK) != 0)
    panic(errno, "/proc doesn't exist on root filesystem", NULL);

  /* Don't support fstab */

  /* move mounts */
  r = mount("/dev", TARGET_DIRECTORY "/dev", NULL, MS_MOVE, NULL);

#ifdef ENABLE_DEBUG
    warn("Moved /dev mount", NULL);
#endif

  if (!r)
    r = mount("/proc", TARGET_DIRECTORY "/proc", NULL, MS_MOVE, NULL);

#ifdef ENABLE_DEBUG
    warn("Moved /proc mount", NULL);
#endif

  if (!r)
    r = mount("/sys", TARGET_DIRECTORY "/sys", NULL, MS_MOVE, NULL);

#ifdef ENABLE_DEBUG
    warn("Moved /sys mount", NULL);
#endif

  if (r < 0)
    panic(errno, "Couldn't move /dev or /sys or /proc from initramfs to root filesystem", NULL);

  /* clean up initramfs contents to free memory */
  cleanup_initramfs();

  /* switch root */
  r = chdir(TARGET_DIRECTORY);
  if (!r)
    r = mount(TARGET_DIRECTORY, "/", NULL, MS_MOVE, NULL);
  if (!r)
    r = chroot(".");
  if (r < 0)
    panic(errno, "Couldn't switch root filesystem", NULL);

#ifdef ENABLE_DEBUG
    warn("Switched root file system, contents of /proc/self/mountinfo:", NULL);
    debug_dump_file("/proc/self/mountinfo");
    //warn("Sleeping for 5s", NULL);
    //sleep(5);
    warn("Booting the system", NULL);
#endif

  if (strlen(init_binary)) {
    try_exec(argc, argv, init_binary);
  } else {
    try_exec(argc, argv, "/sbin/init");
    try_exec(argc, argv, "/init"); // NixOS compatibility
    try_exec(argc, argv, "/etc/init");
    try_exec(argc, argv, "/bin/init");
    try_exec(argc, argv, "/bin/sh");
  }

  /* Message stolen from Linux's init/main.c */
  panic(0, "No working init found. Try passing init= option to kernel. "
           "See Linux's Documentation/init.txt for guidance.", NULL);
  _exit(1);
  return 1;
}

void parse_cmdline()
{
  int r;
  r = traverse_file_by_line(PROC_CMDLINE_FILENAME, (traverse_line_t)parse_cmdline_helper, NULL);
  if (r < 0)
    panic(-r, "Could not parse ", PROC_CMDLINE_FILENAME, NULL);
}

int parse_cmdline_helper(void *data, const char *line, int line_is_incomplete)
{
  char *token;
  char *saveptr;
  char *endptr;
  unsigned long lval;

  (void)data;
  /* this really shouldn't happen, but don't try to interpret garbage */
  if (line_is_incomplete)
    return 0;

  for (token = strtok_r((char *)line, " \t", &saveptr); token != NULL; token = strtok_r(NULL, " \t", &saveptr)) {
    if (!strncmp(token, "mountdevice=", 12)) {
      token += 12;
      required_mounts += 1;
      if(required_mounts == MAX_ROOT_MOUNTS)
        panic(0, "Too many mounts, max is 32");
      if (strlen(token) > MAX_PATH_LEN - 1)
        panic(0, "Parameter mountdevice=", token, " too long", NULL);
      if (!is_valid_device_name(token, NULL, NULL, NULL, NULL, NULL))
        panic(0, "Parameter root=", token, " unsupported (only /dev/"
              ", 0xMAJMIN, SERIAL= and UUID= are "
              " supported)", NULL);
      set_buf(mount_device[required_mounts], MAX_PATH_LEN, token, NULL);
    } else if (!strncmp(token, "mounttarget=", 12)) {
      token += 12;
      if(required_mounts < 0)
        panic(0, "Please specify mountdevice=... before mounttarget=...");
      if (strlen(token) > MAX_PATH_LEN - 1 - strlen(TARGET_DIRECTORY))
        panic(0, "Parameter mounttarget=", token, " too long", NULL);
      set_buf(mount_target[required_mounts], MAX_PATH_LEN, TARGET_DIRECTORY, token, NULL);
    } else if (!strncmp(token, "mountflags=", 11)) {
      token += 11;
      if(required_mounts < 0)
        panic(0, "Please specify mountdevice=... before mountflags=...");
      /* this will automatically be at least 10 bytes shorter than
       * MAX_LINE_LEN */
      set_buf(mount_options[required_mounts], MAX_PATH_LEN, token, NULL);
    } else if (!strncmp(token, "mountfstype=", 12)) {
      token += 12;
      if(required_mounts < 0)
        panic(0, "Please specify mountdevice=... before mountfstype=...");
      if (strlen(token) > MAX_FILESYSTEM_TYPE_LEN - 1)
        panic(0, "Parameter mountfstype=", token, " too long", NULL);
      set_buf(mount_fstype[required_mounts], MAX_FILESYSTEM_TYPE_LEN, token, NULL);
    } else if (!strncmp(token, "rootdelay=", 10)) {
      token += 10;
      lval = strtoul(token, &endptr, 10);
      if (!*token || !endptr || *endptr || lval > INT_MAX)
        panic(0, "Invalid rootdelay=", token," value, must be integer (and must fit into integer data type)", NULL);
      root_delay = (int) lval;
    } else if (!strcmp(token, "rootwait")) {
      root_wait_indefinitely = 1;
    } else if (!strncmp(token, "init=", 5)) {
      token += 5;
      if (strlen(token) > MAX_PATH_LEN - 1)
        panic(0, "Parameter init=", token, " too long", NULL);
      set_buf(init_binary, MAX_PATH_LEN, token, NULL);
    }
  }
  return 0;
}

void try_exec(int orig_argc, char *const orig_argv[], const char *binary)
{
  char *argv[256];
  int i;

  if (orig_argc > 255)
    panic(0, "Too many arguments to init.", NULL);

  argv[0] = (char *)binary;
  for (i = 1; i < orig_argc; i++)
    argv[i] = orig_argv[i];
  argv[i] = NULL;

  execv(binary, argv);
}

#ifdef ENABLE_DEBUG
void debug_dump_file(const char *fn)
{
  (void)traverse_file_by_line(fn, (traverse_line_t)debug_dump_file_helper, NULL);
}

static int debug_dump_file_helper(void *data, const char *line, int line_is_incomplete)
{
  (void)data;
  (void)line_is_incomplete;
  warn(line, NULL);
  return 0;
}
#endif

void cleanup_initramfs()
{
  /* Try to remove files and directories that are no longer needed. As
   * this is optional, ignore the return values, because at worst this
   * is a tiny memory leak. (/init is small anyway.) /dev and /proc
   * have been moved to /target at the point when this function is
   * called. We can't remove /target, because the rootfs is mounted
   * there. */
  (void) rmdir("/dev");
  (void) rmdir("/proc");
  (void) rmdir("/sys");
  (void) unlink("/init");
#ifdef ENABLE_MODULES
  (void) traverse_file_by_line(MODULES_FILE, (traverse_line_t) cleanup_module_helper, NULL);
  (void) unlink(MODULES_FILE);
#endif
}

#ifdef ENABLE_MODULES
void load_modules()
{
  (void) traverse_file_by_line(MODULES_FILE, (traverse_line_t) load_module_helper, NULL);
}

int load_module_helper(void *data, const char *line, int line_is_incomplete)
{
  (void)data;
  int r, fd;
  char *ptr;
  const char *opts;

  if (line_is_incomplete)
    return 0;

  if (!*line)
    return 0;

  ptr = strchr(line, ' ');
  if (ptr) {
    *ptr = '\0';
    opts = ptr + 1;
  } else {
    opts = "";
  }

#ifdef ENABLE_DEBUG
  if (*opts)
    warn("Loading kernel module ", line, " (with options: ", opts, ")", NULL);
  else
    warn("Loading kernel module ", line, NULL);
#endif

  fd = open(line, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    warn("Couldn't load ", line, ": ", strerror(errno), NULL);
    return 0;
  }
#if defined(HAVE_FINIT_MODULE)
  r = finit_module(fd, opts, 0);
  if (r < 0)
    r = -errno;
#elif defined(HAVE_SYS_FINIT_MODULE)
  r = syscall(SYS_finit_module, fd, opts, 0);
  if (r < 0)
    r = -errno;
#else
  {
    void *contents;
    struct stat st;

    r = fstat(fd, &st);
    if (r < 0) {
      warn("Couldn't stat ", line, ": ", strerror(errno), NULL);
      close(fd);
      return 0;
    }

    contents = mmap(NULL, (size_t) st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (!contents) {
      warn("Couldn't mmap ", line, ": ", strerror(errno), NULL);
      close(fd);
      return 0;
    }
    r = init_module(contents, (unsigned long) st.st_size, opts);
    if (r < 0)
      r = -errno;
    munmap(contents, (size_t) st.st_size);
  }
#endif

  /* Ignore duplicate modules, this simplifies initramfs creation logic
   * a bit. */
  if (r < 0 && r != -EEXIST)
    warn("Couldn't load ", line, ": ", strerror(-r), NULL);

  close(fd);

  return 0;
}

int cleanup_module_helper(void *data, const char *line, int line_is_incomplete)
{
  (void)data;
  char *ptr;

  if (line_is_incomplete)
    return 0;

  ptr = strchr(line, ' ');
  if (ptr)
    *ptr = '\0';

  (void) unlink(line);
  return 0;
}
#endif

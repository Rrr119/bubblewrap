/* bubblewrap
 * SPDX-License-Identifier: LGPL-2.0-or-later
 *
 * cgroup v2 resource limits.
 *
 * The process that creates the cgroup must be able to write to the
 * cgroup filesystem, which normally means either running as root or
 * running inside a delegated cgroup.  That process also has to outlive
 * the sandbox so that the cgroup can be removed after the sandboxed
 * processes have exited, even if bwrap itself has already dropped its
 * privileges.  We therefore fork a small manager process before entering
 * any user namespace and before creating the sandbox.
 */

#include "config.h"

#include "cgroup.h"
#include "utils.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <math.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#define CGROUP_PERIOD_US 100000ULL
#define CGROUP_STATUS_READY 'R'
#define CGROUP_STATUS_ERROR 'E'
#define CGROUP_COMMAND_CHILD 'C'
#define CGROUP_COMMAND_DONE 'D'

typedef struct
{
  char command;
  int  pid;
} CgroupCommand;

typedef struct
{
  CgroupConfig config;
  char        *mount;
  char        *parent_path;
  char        *holder_path;
  char        *manager_path;
  char        *limit_path;
  bool         added_cpu;
  bool         added_memory;
  bool         moved_manager;
  pid_t        launcher_pid;
} CgroupState;

static void
close_fd (int *fd)
{
  if (*fd >= 0)
    {
      (void) close (*fd);
      *fd = -1;
    }
}

static bool
write_all (int         fd,
           const char *data,
           size_t      len)
{
  while (len > 0)
    {
      ssize_t written = TEMP_FAILURE_RETRY (write (fd, data, len));

      if (written < 0)
        return false;
      if (written == 0)
        {
          errno = EIO;
          return false;
        }

      data += written;
      len -= written;
    }

  return true;
}

static bool
read_all (int    fd,
          char  *buffer,
          size_t len)
{
  size_t offset = 0;

  while (offset < len)
    {
      ssize_t n = TEMP_FAILURE_RETRY (read (fd, buffer + offset, len - offset));

      if (n < 0)
        return false;
      if (n == 0)
        {
          errno = EPIPE;
          return false;
        }

      offset += n;
    }

  return true;
}

static char *
read_text_file (const char *path)
{
  return load_file_at (AT_FDCWD, path);
}

static bool
write_text_file (const char *path,
                 const char *text)
{
  cleanup_fd int fd = -1;

  fd = TEMP_FAILURE_RETRY (open (path, O_WRONLY | O_CLOEXEC));
  if (fd < 0)
    return false;

  return write_all (fd, text, strlen (text));
}

static bool
write_pid_to_cgroup (const char *cgroup_path,
                     pid_t       pid)
{
  cleanup_free char *procs = xasprintf ("%s/cgroup.procs", cgroup_path);
  cleanup_free char *pid_string = xasprintf ("%d", (int) pid);

  return write_text_file (procs, pid_string);
}

static bool
word_in_list (const char *list,
              const char *word)
{
  const char *p = list;
  size_t word_len = strlen (word);

  while (p != NULL && *p != '\0')
    {
      while (*p != '\0' && isspace ((unsigned char) *p))
        p++;

      if (*p == '\0')
        break;

      if (strncmp (p, word, word_len) == 0 &&
          (p[word_len] == '\0' || isspace ((unsigned char) p[word_len])))
        return true;

      while (*p != '\0' && !isspace ((unsigned char) *p))
        p++;
    }

  return false;
}

static char *
find_cgroup2_mount (void)
{
  cleanup_free char *mountinfo = NULL;
  char *line;
  char *saveptr = NULL;

  mountinfo = read_text_file ("/proc/self/mountinfo");
  if (mountinfo == NULL)
    die_with_error ("Can't read /proc/self/mountinfo");

  for (line = strtok_r (mountinfo, "\n", &saveptr);
       line != NULL;
       line = strtok_r (NULL, "\n", &saveptr))
    {
      char *fields[32];
      int n_fields = 0;
      char *field_saveptr = NULL;
      char *field;
      int i;

      for (field = strtok_r (line, " ", &field_saveptr);
           field != NULL && n_fields < (int) N_ELEMENTS (fields);
           field = strtok_r (NULL, " ", &field_saveptr))
        fields[n_fields++] = field;

      for (i = 0; i + 3 < n_fields && n_fields >= 5; i++)
        {
          if (strcmp (fields[i], "-") == 0 &&
              strcmp (fields[i + 1], "cgroup2") == 0)
            {
              char *mount_path = fields[4];
              char *unescaped = xstrdup (mount_path);
              char *src = unescaped;
              char *dst = unescaped;

              while (*src != '\0')
                {
                  if (src[0] == '\\' &&
                      src[1] >= '0' && src[1] <= '7' &&
                      src[2] >= '0' && src[2] <= '7' &&
                      src[3] >= '0' && src[3] <= '7')
                    {
                      *dst++ = (char) (((src[1] - '0') << 6) |
                                       ((src[2] - '0') << 3) |
                                       (src[3] - '0'));
                      src += 4;
                    }
                  else
                    {
                      *dst++ = *src++;
                    }
                }
              *dst = '\0';

              return unescaped;
            }
        }
    }

  return NULL;
}

static char *
find_current_cgroup (const char *mount)
{
  cleanup_free char *cgroup = NULL;
  char *line;
  char *saveptr = NULL;

  cgroup = read_text_file ("/proc/self/cgroup");
  if (cgroup == NULL)
    die_with_error ("Can't read /proc/self/cgroup");

  for (line = strtok_r (cgroup, "\n", &saveptr);
       line != NULL;
       line = strtok_r (NULL, "\n", &saveptr))
    {
      char *first_colon = strchr (line, ':');
      char *second_colon;
      char *endptr = NULL;
      unsigned long hierarchy_id;
      char *path;

      if (first_colon == NULL)
        continue;

      second_colon = strchr (first_colon + 1, ':');
      if (second_colon == NULL)
        continue;

      errno = 0;
      hierarchy_id = strtoul (line, &endptr, 10);
      if (errno != 0 || endptr != first_colon)
        continue;

      path = second_colon + 1;
      if (hierarchy_id == 0 && second_colon == first_colon + 1)
        {
          char *result = xasprintf ("%s%s", mount, path);
          return result;
        }
    }

  return NULL;
}

static char *
canonicalize_cgroup_path (const char *mount,
                          const char *path)
{
  cleanup_free char *candidate = NULL;
  char *resolved;
  size_t mount_len = strlen (mount);

  if (path == NULL || path[0] == '\0')
    return NULL;

  if (strcmp (path, mount) == 0 ||
      (strncmp (path, mount, mount_len) == 0 && path[mount_len] == '/'))
    candidate = xstrdup (path);
  else if (path[0] == '/')
    candidate = xasprintf ("%s%s", mount, path);
  else
    candidate = xasprintf ("%s/%s", mount, path);

  resolved = realpath (candidate, NULL);
  if (resolved == NULL)
    return NULL;

  if (strcmp (resolved, mount) != 0 &&
      (strncmp (resolved, mount, mount_len) != 0 || resolved[mount_len] != '/'))
    {
      free (resolved);
      errno = EINVAL;
      return NULL;
    }

  return resolved;
}

static char *
normalize_percent (const char *value)
{
  char *endptr = NULL;
  long double percent;
  unsigned long long quota;

  errno = 0;
  percent = strtold (value, &endptr);
  if (errno != 0 || endptr == value || strcmp (endptr, "%") != 0 ||
      !isfinite (percent) || percent <= 0 ||
      percent > (long double) ULLONG_MAX * 100.0L / (long double) CGROUP_PERIOD_US)
    return NULL;

  quota = (unsigned long long) (percent * (long double) CGROUP_PERIOD_US / 100.0L);
  if (quota == 0)
    quota = 1;

  return xasprintf ("%llu %llu", quota, CGROUP_PERIOD_US);
}

static char *
normalize_cpu_pair (const char *value)
{
  char *copy = xstrdup (value);
  char *p = copy;
  char *endptr = NULL;
  unsigned long long quota;
  unsigned long long period = CGROUP_PERIOD_US;
  bool saw_separator = false;

  while (*p != '\0')
    {
      if (*p == '/' || isspace ((unsigned char) *p))
        {
          *p = ' ';
          saw_separator = true;
        }
      p++;
    }

  if (!saw_separator)
    {
      free (copy);
      return NULL;
    }

  p = copy;
  while (isspace ((unsigned char) *p))
    p++;

  if (strncmp (p, "max", 3) == 0 && (p[3] == ' ' || p[3] == '\0'))
    quota = 0;
  else
    {
      errno = 0;
      quota = strtoull (p, &endptr, 10);
      if (errno != 0 || endptr == p)
        {
          free (copy);
          return NULL;
        }
      p = endptr;
    }

  if (quota == 0)
    {
      while (*p != '\0' && p[0] != ' ')
        p++;
    }

  while (isspace ((unsigned char) *p))
    p++;

  if (*p != '\0')
    {
      errno = 0;
      period = strtoull (p, &endptr, 10);
      if (errno != 0 || endptr == p)
        {
          free (copy);
          return NULL;
        }
      p = endptr;
      while (isspace ((unsigned char) *p))
        p++;
      if (*p != '\0')
        {
          free (copy);
          return NULL;
        }
    }

  if (period < 1000 || period > 1000000)
    {
      free (copy);
      return NULL;
    }

  if (quota == 0)
    {
      char *result = xasprintf ("max %llu", period);
      free (copy);
      return result;
    }

  {
    char *result = xasprintf ("%llu %llu", quota, period);
    free (copy);
    return result;
  }
}

char *
cgroup_parse_cpu (const char *option,
                  const char *value)
{
  cleanup_free char *trimmed = NULL;
  char *result;
  char *endptr = NULL;
  long double cores;

  if (value == NULL || value[0] == '\0')
    die ("%s takes a non-empty argument", option);

  trimmed = xstrdup (value);
  {
    char *start = trimmed;
    char *end;

    while (isspace ((unsigned char) *start))
      start++;
    end = start + strlen (start);
    while (end > start && isspace ((unsigned char) end[-1]))
      end--;
    *end = '\0';

    if (start != trimmed)
      memmove (trimmed, start, strlen (start) + 1);
  }

  if (strcmp (trimmed, "max") == 0)
    return xasprintf ("max %llu", CGROUP_PERIOD_US);

  if (strchr (trimmed, '%') != NULL)
    {
      result = normalize_percent (trimmed);
      if (result == NULL)
        die ("Invalid CPU limit '%s' for %s", value, option);
      return result;
    }

  result = normalize_cpu_pair (trimmed);
  if (result != NULL)
    return result;

  errno = 0;
  cores = strtold (trimmed, &endptr);
  if (errno != 0 || endptr == trimmed)
    die ("Invalid CPU limit '%s' for %s", value, option);

  if (endptr[0] == 'm' && endptr[1] == '\0')
    {
      cores /= 1000.0L;
      endptr++;
    }

  if (*endptr != '\0' ||
      !isfinite (cores) || cores <= 0 ||
      cores > (long double) ULLONG_MAX / (long double) CGROUP_PERIOD_US)
    die ("Invalid CPU limit '%s' for %s", value, option);

  /* A large integer is almost certainly a raw quota in microseconds
   * (as used by cpu.max), whereas small values are CPU cores. */
  if (cores >= 1000 && cores == (long double) (unsigned long long) cores)
    {
      unsigned long long quota = (unsigned long long) cores;
      return xasprintf ("%llu %llu", quota, CGROUP_PERIOD_US);
    }

  {
    long double scaled = cores * (long double) CGROUP_PERIOD_US;
    unsigned long long quota = (unsigned long long) (scaled + 0.5L);

    if (quota == 0)
      quota = 1;

    return xasprintf ("%llu %llu", quota, CGROUP_PERIOD_US);
  }
}

char *
cgroup_parse_memory (const char *option,
                     const char *value,
                     bool        value_is_megabytes)
{
  cleanup_free char *trimmed = NULL;
  char *endptr = NULL;
  long double number;
  long double multiplier = 1.0L;
  long double bytes;
  const char *suffix;

  if (value == NULL || value[0] == '\0')
    die ("%s takes a non-empty argument", option);

  trimmed = xstrdup (value);
  {
    char *start = trimmed;
    char *end;

    while (isspace ((unsigned char) *start))
      start++;
    end = start + strlen (start);
    while (end > start && isspace ((unsigned char) end[-1]))
      end--;
    *end = '\0';

    if (start != trimmed)
      memmove (trimmed, start, strlen (start) + 1);
  }

  if (strcmp (trimmed, "max") == 0)
    return xstrdup ("max");

  errno = 0;
  number = strtold (trimmed, &endptr);
  if (errno != 0 || endptr == trimmed || !isfinite (number) || number <= 0)
    die ("Invalid memory limit '%s' for %s", value, option);

  suffix = endptr;
  while (isspace ((unsigned char) *suffix))
    suffix++;

  if (*suffix == '\0')
    {
      /* Be forgiving about the unit for small bare values: a limit of
       * "64" is much more likely to mean 64 MiB than 64 bytes.  Larger
       * values are treated as bytes, which makes it possible to pass the
       * exact value read from memory.max. */
      if (value_is_megabytes || number < 1024.0L * 1024.0L)
        multiplier = 1024.0L * 1024.0L;
    }
  else if (strcasecmp (suffix, "b") == 0)
    multiplier = 1.0L;
  else if (strcasecmp (suffix, "k") == 0 ||
           strcasecmp (suffix, "ki") == 0 ||
           strcasecmp (suffix, "kb") == 0 ||
           strcasecmp (suffix, "kib") == 0)
    multiplier = 1024.0L;
  else if (strcasecmp (suffix, "m") == 0 ||
           strcasecmp (suffix, "mi") == 0 ||
           strcasecmp (suffix, "mb") == 0 ||
           strcasecmp (suffix, "mib") == 0)
    multiplier = 1024.0L * 1024.0L;
  else if (strcasecmp (suffix, "g") == 0 ||
           strcasecmp (suffix, "gi") == 0 ||
           strcasecmp (suffix, "gb") == 0 ||
           strcasecmp (suffix, "gib") == 0)
    multiplier = 1024.0L * 1024.0L * 1024.0L;
  else if (strcasecmp (suffix, "t") == 0 ||
           strcasecmp (suffix, "ti") == 0 ||
           strcasecmp (suffix, "tb") == 0 ||
           strcasecmp (suffix, "tib") == 0)
    multiplier = 1024.0L * 1024.0L * 1024.0L * 1024.0L;
  else
    die ("Invalid memory limit suffix in '%s' for %s", value, option);

  bytes = number * multiplier;
  if (bytes < 1.0L || bytes > (long double) ULLONG_MAX)
    die ("Memory limit '%s' for %s is out of range", value, option);

  return xasprintf ("%llu", (unsigned long long) bytes);
}

bool
cgroup_config_is_set (const CgroupConfig *config)
{
  return config->cpu_max != NULL ||
         config->memory_max != NULL ||
         config->parent != NULL;
}

static void
send_status (int         fd,
             char        status,
             const char *message)
{
  char header[2] = { status, 0 };
  uint32_t len = message != NULL ? (uint32_t) strlen (message) : 0;

  if (!write_all (fd, header, 1))
    return;
  if (!write_all (fd, (const char *) &len, sizeof (len)))
    return;
  if (len > 0)
    (void) write_all (fd, message, len);
}

static char *
receive_status (int fd)
{
  char status;
  uint32_t len;
  cleanup_free char *message = NULL;

  if (!read_all (fd, &status, 1))
    die_with_error ("cgroup manager exited unexpectedly");

  if (!read_all (fd, (char *) &len, sizeof (len)))
    die_with_error ("cgroup manager exited unexpectedly");

  if (len > 1024 * 1024)
    die ("Invalid response from cgroup manager");

  message = xmalloc (len + 1);
  if (len > 0 && !read_all (fd, message, len))
    die_with_error ("cgroup manager exited unexpectedly");
  message[len] = '\0';

  if (status == CGROUP_STATUS_ERROR)
    {
      if (message[0] == '\0')
        die ("cgroup manager failed");
      die ("%s", message);
    }

  if (status != CGROUP_STATUS_READY)
    die ("Invalid response from cgroup manager");

  return steal_pointer (&message);
}

static void
cgroup_state_clear (CgroupState *state)
{
  free (state->mount);
  free (state->parent_path);
  free (state->holder_path);
  free (state->manager_path);
  free (state->limit_path);
  state->mount = NULL;
  state->parent_path = NULL;
  state->holder_path = NULL;
  state->manager_path = NULL;
  state->limit_path = NULL;
}

static bool
cgroup_is_empty (const char *path)
{
  cleanup_free char *procs_path = xasprintf ("%s/cgroup.procs", path);
  cleanup_free char *procs = read_text_file (procs_path);

  if (procs == NULL)
    {
      /* If the cgroup disappeared or we can no longer inspect it, there
       * is nothing useful left for the cleanup path to wait for. */
      return true;
    }

  {
    const char *p = procs;
    while (*p != '\0')
      {
        if (isdigit ((unsigned char) *p))
          return false;
        p++;
      }
  }

  return true;
}

static void
wait_for_empty_cgroup (const char *path)
{
  /* The sandbox is allowed to contain helpers that are reparented after
   * their parent exits.  Keep the cgroup around until it is really empty. */
  for (;;)
    {
      if (cgroup_is_empty (path))
        return;

      (void) poll (NULL, 0, 10);
    }
}

static void
remove_cgroup (const char *path)
{
  if (path != NULL && rmdir (path) != 0 && errno != ENOENT)
    warn ("Can't remove cgroup %s: %s", path, strerror (errno));
}

static bool
enable_controllers (CgroupState *state,
                    char        *error,
                    size_t       error_size)
{
  cleanup_free char *controllers = NULL;
  cleanup_free char *subtree = NULL;
  cleanup_free char *controllers_path = NULL;
  cleanup_free char *subtree_path = NULL;
  char enable[64];
  size_t enable_len = 0;

  controllers_path = xasprintf ("%s/cgroup.controllers", state->parent_path);
  subtree_path = xasprintf ("%s/cgroup.subtree_control", state->parent_path);

  controllers = read_text_file (controllers_path);
  if (controllers == NULL)
    {
      snprintf (error, error_size, "Can't read %s: %s",
                controllers_path, strerror (errno));
      return false;
    }

  if (state->config.cpu_max != NULL && !word_in_list (controllers, "cpu"))
    {
      snprintf (error, error_size,
                "The cgroup v2 'cpu' controller is not available at %s",
                state->parent_path);
      return false;
    }

  if (state->config.memory_max != NULL && !word_in_list (controllers, "memory"))
    {
      snprintf (error, error_size,
                "The cgroup v2 'memory' controller is not available at %s",
                state->parent_path);
      return false;
    }

  subtree = read_text_file (subtree_path);
  if (subtree == NULL)
    {
      snprintf (error, error_size, "Can't read %s: %s",
                subtree_path, strerror (errno));
      return false;
    }

  if (state->config.cpu_max != NULL && !word_in_list (subtree, "cpu"))
    {
      enable_len += (size_t) snprintf (enable + enable_len,
                                      sizeof (enable) - enable_len,
                                      "+cpu ");
      state->added_cpu = true;
    }

  if (state->config.memory_max != NULL && !word_in_list (subtree, "memory"))
    {
      enable_len += (size_t) snprintf (enable + enable_len,
                                      sizeof (enable) - enable_len,
                                      "+memory ");
      state->added_memory = true;
    }

  if (enable_len == 0)
    return true;

  if (state->manager_path == NULL)
    {
      snprintf (error, error_size,
                "Internal error: no manager cgroup for controller setup");
      return false;
    }

  if (mkdir (state->manager_path, 0755) != 0)
    {
      snprintf (error, error_size, "Can't create %s: %s",
                state->manager_path, strerror (errno));
      return false;
    }

  if (!write_pid_to_cgroup (state->holder_path, state->launcher_pid))
    {
      snprintf (error, error_size, "Can't move bwrap into %s: %s",
                state->holder_path, strerror (errno));
      return false;
    }

  if (!write_pid_to_cgroup (state->manager_path, getpid ()))
    {
      snprintf (error, error_size, "Can't move cgroup manager into %s: %s",
                state->manager_path, strerror (errno));
      return false;
    }
  state->moved_manager = true;

  enable[enable_len] = '\0';
  if (!write_text_file (subtree_path, enable))
    {
      snprintf (error, error_size,
                "Can't enable cgroup controllers in %s: %s "
                "(the cgroup must be delegated and must not contain other "
                "processes; try running bwrap directly in a scope created with "
                "'systemd-run --user --scope -p Delegate=yes')",
                subtree_path, strerror (errno));
      return false;
    }

  return true;
}

static bool
cgroup_state_setup (CgroupState *state,
                    char        *error,
                    size_t       error_size)
{
  cleanup_free char *controllers = NULL;
  unsigned int attempt;

  state->mount = find_cgroup2_mount ();
  if (state->mount == NULL)
    {
      snprintf (error, error_size,
                "cgroup v2 is not mounted; CPU and memory limits require cgroup v2");
      return false;
    }

  if (state->config.parent != NULL)
    {
      state->parent_path = canonicalize_cgroup_path (state->mount,
                                                     state->config.parent);
      if (state->parent_path == NULL)
        {
          snprintf (error, error_size, "Invalid cgroup parent '%s': %s",
                    state->config.parent, strerror (errno));
          return false;
        }
    }
  else
    {
      state->parent_path = find_current_cgroup (state->mount);
      if (state->parent_path == NULL)
        {
          snprintf (error, error_size,
                    "Can't find the current cgroup v2 path in /proc/self/cgroup");
          return false;
        }
    }

  {
    cleanup_free char *controllers_path =
      xasprintf ("%s/cgroup.controllers", state->parent_path);

    controllers = read_text_file (controllers_path);
    if (controllers == NULL)
      {
        snprintf (error, error_size, "Can't read %s: %s",
                  controllers_path, strerror (errno));
        return false;
      }
  }

  if (state->config.cpu_max != NULL && !word_in_list (controllers, "cpu"))
    {
      snprintf (error, error_size,
                "The cgroup v2 'cpu' controller is not available at %s",
                state->parent_path);
      return false;
    }

  if (state->config.memory_max != NULL && !word_in_list (controllers, "memory"))
    {
      snprintf (error, error_size,
                "The cgroup v2 'memory' controller is not available at %s",
                state->parent_path);
      return false;
    }

  for (attempt = 0; attempt < 1000; attempt++)
    {
      cleanup_free char *base =
        xasprintf ("%s/bwrap-%d-%u",
                   state->parent_path, (int) state->launcher_pid, attempt);
      char *holder = xasprintf ("%s-holder", base);

      if (mkdir (holder, 0755) == 0)
        {
          state->holder_path = holder;
          state->manager_path = xasprintf ("%s-manager", base);
          state->limit_path = xasprintf ("%s-scope", base);
          break;
        }

      free (holder);

      if (errno != EEXIST)
        {
          snprintf (error, error_size, "Can't create cgroup in %s: %s",
                    state->parent_path, strerror (errno));
          return false;
        }
    }

  if (state->holder_path == NULL)
    {
      snprintf (error, error_size, "Can't create a unique cgroup in %s",
                state->parent_path);
      return false;
    }

  if (mkdir (state->limit_path, 0755) != 0)
    {
      snprintf (error, error_size, "Can't create %s: %s",
                state->limit_path, strerror (errno));
      return false;
    }

  if (!enable_controllers (state, error, error_size))
    return false;

  if (!write_pid_to_cgroup (state->limit_path, state->launcher_pid))
    {
      snprintf (error, error_size, "Can't move bwrap into %s: %s",
                state->limit_path, strerror (errno));
      return false;
    }

  return true;
}

static void
cgroup_state_cleanup (CgroupState *state)
{
  if (state->parent_path == NULL)
    return;

  if (state->limit_path != NULL)
    wait_for_empty_cgroup (state->limit_path);

  if (state->holder_path != NULL)
    wait_for_empty_cgroup (state->holder_path);

  if (state->added_cpu || state->added_memory)
    {
      cleanup_free char *subtree_path =
        xasprintf ("%s/cgroup.subtree_control", state->parent_path);
      char disable[64];
      size_t disable_len = 0;

      if (state->added_cpu)
        disable_len += (size_t) snprintf (disable + disable_len,
                                         sizeof (disable) - disable_len,
                                         "-cpu ");
      if (state->added_memory)
        disable_len += (size_t) snprintf (disable + disable_len,
                                         sizeof (disable) - disable_len,
                                         "-memory ");
      disable[disable_len] = '\0';

      if (!write_text_file (subtree_path, disable))
        warn ("Can't restore cgroup subtree control in %s: %s",
              subtree_path, strerror (errno));
    }

  remove_cgroup (state->limit_path);
  remove_cgroup (state->holder_path);

  if (state->moved_manager)
    {
      if (!write_pid_to_cgroup (state->parent_path, getpid ()))
        warn ("Can't move cgroup manager back to %s: %s",
              state->parent_path, strerror (errno));
    }

  remove_cgroup (state->manager_path);
}

static int
read_command (int           fd,
              CgroupCommand *command)
{
  size_t offset = 0;

  while (offset < sizeof (*command))
    {
      ssize_t n = TEMP_FAILURE_RETRY (read (fd,
                                            (char *) command + offset,
                                            sizeof (*command) - offset));

      if (n < 0)
        return -1;
      if (n == 0)
        return 0;

      offset += n;
    }

  return 1;
}

static int
close_extra_fds_cb (void *data,
                    int   fd)
{
  int *keep = data;

  if (fd <= 2 || fd == keep[0] || fd == keep[1])
    return 0;

  close (fd);
  return 0;
}

static int
cgroup_manager_main (int                 command_fd,
                     int                 status_fd,
                     const CgroupConfig *config)
{
  CgroupState state = {0};
  CgroupCommand command;
  char error[512];
  int keep_fds[2] = { command_fd, status_fd };
  int command_result;

  state.config = *config;
  state.launcher_pid = getppid ();

  fdwalk (close_extra_fds_cb, keep_fds);

  if (!cgroup_state_setup (&state, error, sizeof (error)))
    {
      send_status (status_fd, CGROUP_STATUS_ERROR, error);
      cgroup_state_cleanup (&state);
      cgroup_state_clear (&state);
      return 1;
    }

  send_status (status_fd, CGROUP_STATUS_READY, NULL);

  command_result = read_command (command_fd, &command);
  if (command_result <= 0)
    {
      /* The launcher exited before creating the sandbox.  The launcher is
       * still in the limit cgroup, so move it to the holder before waiting. */
      (void) write_pid_to_cgroup (state.holder_path, state.launcher_pid);
      cgroup_state_cleanup (&state);
      cgroup_state_clear (&state);
      return command_result < 0 ? 1 : 0;
    }

  if (command.command == CGROUP_COMMAND_CHILD)
    {
      cleanup_free char *cpu_path = NULL;
      cleanup_free char *memory_path = NULL;
      cleanup_free char *swap_path = NULL;
      cleanup_free char *oom_group_path = NULL;

      if (!write_pid_to_cgroup (state.holder_path, state.launcher_pid))
        {
          snprintf (error, sizeof (error), "Can't move bwrap out of %s: %s",
                    state.limit_path, strerror (errno));
          send_status (status_fd, CGROUP_STATUS_ERROR, error);
          cgroup_state_cleanup (&state);
          cgroup_state_clear (&state);
          return 1;
        }

      if (config->cpu_max != NULL)
        {
          cpu_path = xasprintf ("%s/cpu.max", state.limit_path);
          if (!write_text_file (cpu_path, config->cpu_max))
            {
              snprintf (error, sizeof (error), "Can't set %s: %s",
                        cpu_path, strerror (errno));
              send_status (status_fd, CGROUP_STATUS_ERROR, error);
              cgroup_state_cleanup (&state);
              cgroup_state_clear (&state);
              return 1;
            }
        }

      if (config->memory_max != NULL)
        {
          memory_path = xasprintf ("%s/memory.max", state.limit_path);
          if (!write_text_file (memory_path, config->memory_max))
            {
              snprintf (error, sizeof (error), "Can't set %s: %s",
                        memory_path, strerror (errno));
              send_status (status_fd, CGROUP_STATUS_ERROR, error);
              cgroup_state_cleanup (&state);
              cgroup_state_clear (&state);
              return 1;
            }

          /* A hard memory limit should not silently spill into swap. */
          if (strcmp (config->memory_max, "max") != 0)
            {
              swap_path = xasprintf ("%s/memory.swap.max", state.limit_path);
              (void) write_text_file (swap_path, "0");
            }

          /* Keep the OOM killer scoped to the process that exceeded the
           * limit rather than killing the whole sandbox. */
          oom_group_path = xasprintf ("%s/memory.oom.group", state.limit_path);
          (void) write_text_file (oom_group_path, "0");
        }

      send_status (status_fd, CGROUP_STATUS_READY, NULL);
    }
  else if (command.command == CGROUP_COMMAND_DONE)
    {
      /* Nothing to do here; cleanup below waits for the sandbox to exit. */
    }
  else
    {
      send_status (status_fd, CGROUP_STATUS_ERROR,
                   "Invalid cgroup manager command");
      cgroup_state_cleanup (&state);
      cgroup_state_clear (&state);
      return 1;
    }

  /* Wait for the launcher to finish.  It sends DONE after the sandbox
   * process has exited; if it dies unexpectedly, EOF is enough. */
  if (command.command == CGROUP_COMMAND_CHILD)
    {
      command_result = read_command (command_fd, &command);
      if (command_result > 0 && command.command != CGROUP_COMMAND_DONE)
        warn ("Ignoring unexpected command from bwrap");
    }

  cgroup_state_cleanup (&state);
  cgroup_state_clear (&state);
  return 0;
}

void
cgroup_manager_start (const CgroupConfig *config,
                      CgroupManager      *manager)
{
  int command_pipe[2] = { -1, -1 };
  int status_pipe[2] = { -1, -1 };
  cleanup_free char *unused = NULL;
  pid_t pid;

  manager->pid = -1;
  manager->command_fd = -1;
  manager->status_fd = -1;

  if (pipe2 (command_pipe, O_CLOEXEC) != 0)
    die_with_error ("Can't create cgroup manager pipe");
  if (pipe2 (status_pipe, O_CLOEXEC) != 0)
    die_with_error ("Can't create cgroup manager pipe");

  pid = fork ();
  if (pid < 0)
    die_with_error ("Can't fork cgroup manager");

  if (pid == 0)
    {
      int result;

      close (command_pipe[PIPE_WRITE_END]);
      close (status_pipe[PIPE_READ_END]);
      result = cgroup_manager_main (command_pipe[PIPE_READ_END],
                                    status_pipe[PIPE_WRITE_END], config);
      _exit (result);
    }

  close (command_pipe[PIPE_READ_END]);
  close (status_pipe[PIPE_WRITE_END]);

  manager->pid = pid;
  manager->command_fd = command_pipe[PIPE_WRITE_END];
  manager->status_fd = status_pipe[PIPE_READ_END];

  unused = receive_status (manager->status_fd);
}

void
cgroup_manager_child (CgroupManager *manager,
                      pid_t          child_pid)
{
  CgroupCommand command = { CGROUP_COMMAND_CHILD, (int) child_pid };
  cleanup_free char *unused = NULL;

  if (manager->command_fd < 0)
    return;

  if (!write_all (manager->command_fd, (const char *) &command, sizeof (command)))
    die_with_error ("Can't send PID to cgroup manager");

  unused = receive_status (manager->status_fd);
}

void
cgroup_manager_finish (CgroupManager *manager)
{
  CgroupCommand command = { CGROUP_COMMAND_DONE, 0 };

  if (manager->command_fd < 0)
    return;

  (void) write_all (manager->command_fd, (const char *) &command, sizeof (command));
  close_fd (&manager->command_fd);
  close_fd (&manager->status_fd);
}

void
cgroup_manager_close_in_child (CgroupManager *manager)
{
  close_fd (&manager->command_fd);
  close_fd (&manager->status_fd);
}

/* bubblewrap
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#pragma once

#include <stdbool.h>
#include <sys/types.h>

typedef struct
{
  const char *cpu_max;
  const char *memory_max;
  const char *parent;
} CgroupConfig;

typedef struct
{
  pid_t pid;
  int   command_fd;
  int   status_fd;
} CgroupManager;

bool cgroup_config_is_set (const CgroupConfig *config);

char *cgroup_parse_cpu (const char *option,
                        const char *value);
char *cgroup_parse_memory (const char *option,
                           const char *value,
                           bool        value_is_megabytes);

void cgroup_manager_start (const CgroupConfig *config,
                           CgroupManager      *manager);
void cgroup_manager_child (CgroupManager *manager,
                          pid_t          child_pid);
void cgroup_manager_finish (CgroupManager *manager);

void cgroup_manager_close_in_child (CgroupManager *manager);

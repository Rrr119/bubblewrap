/* bubblewrap
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#pragma once

#include <stdbool.h>

#include <linux/filter.h>

typedef struct _SeccompPolicy SeccompPolicy;

SeccompPolicy *seccomp_policy_new (void);
void seccomp_policy_free (SeccompPolicy *policy);
void seccomp_policy_set_default_action (SeccompPolicy *policy,
                                        const char    *action);
void seccomp_policy_add_rule (SeccompPolicy *policy,
                              const char    *rule);
struct sock_fprog *seccomp_policy_compile (SeccompPolicy *policy);

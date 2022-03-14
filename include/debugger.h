#pragma once

#include "types.h"

i32 exec_inferior(char const* path, char *const* args);
void dbg_inferior(pid_t inferior);

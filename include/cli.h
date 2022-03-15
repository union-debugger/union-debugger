#pragma once

#include "config.h"
#include "types.h"
#include "../ext/linenoise.h"

config_t* parse_args(const int argc, char* const* argv);
ssize_t handle_command(char* cmd, config_t* cfg);
void completions(char const* buf, linenoiseCompletions* lc);

#pragma once

#include "config.h"
#include "types.h"
#include "../ext/linenoise.h"

bool handle_command(char* prompt, config_t* cfg);
void completions(char const* buf, linenoiseCompletions* lc);

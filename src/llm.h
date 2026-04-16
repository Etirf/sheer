#pragma once

#include "cmd.h"
#include <stddef.h>

typedef struct {
    char url[512];    /* full endpoint, e.g. http://localhost:11434/v1/chat/completions */
    char key[256];    /* API key - empty string = no Authorization header */
    char model[128];
} LlmConf;

/*
 * parse --llm option string into LlmConf.
 *
 *   NULL or ""            → env vars (SHEER_API_URL, SHEER_API_KEY, SHEER_LLM_MODEL)
 *   "ollama"              → http://localhost:11434  no key needed
 *   "ollama:8080"         → custom port, still no key
 *   "http://host/v1/..."  → any endpoint, SHEER_API_KEY for auth
 *
 * model_override takes precedence over SHEER_LLM_MODEL.
 * defaults: gpt-4o-mini for openai, llama3.2 for ollama.
 */
int  llm_conf_parse(const char *opt, const char *model_override, LlmConf *out);

/* explain a command - populates Analysis.explanation, .risk, etc. */
void llm_analyze(const char *cmd, const LlmConf *conf, Analysis *out);

/*
 * generate a shell command from a plain-English description.
 * writes the raw command string into cmd_out.
 * context is optional recent shell history (newline-separated), may be NULL.
 */
void llm_gen(const char *description, const char *context,
             const LlmConf *conf, char *cmd_out, size_t outlen);

#include "llm.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ask for strict JSON so our grep-parser doesn't explode. see json_str() below */
static const char SYSTEM_PROMPT[] =
    "You are a shell command explainer. "
    "Given a shell command, respond ONLY with a JSON object - no markdown, "
    "no extra text - in this exact shape: "
    "{\"explanation\":\"...\","
    "\"risk\":\"SAFE|LOW|MEDIUM|HIGH|CRITICAL\","
    "\"warning\":\"...or empty string\","
    "\"safer\":\"...or empty string\"}. "
    "explanation: 1-2 sentences describing what the command does. "
    "risk: one of the five values above. "
    "warning: specific risk detail, empty if SAFE/LOW. "
    "safer: a safer alternative command or flag, empty if none.";

int llm_conf_parse(const char *opt, const char *model_override, LlmConf *out)
{
    const char *env_model = getenv("SHEER_LLM_MODEL");
    const char *model     = model_override ? model_override
                          : env_model      ? env_model
                          : NULL;

    if (!opt || opt[0] == '\0') {
        /* use env vars - user manages their own config */
        const char *url = getenv("SHEER_API_URL");
        const char *key = getenv("SHEER_API_KEY");
        if (!url) url = "https://api.openai.com/v1/chat/completions";
        snprintf(out->url,   sizeof out->url,   "%s", url);
        snprintf(out->key,   sizeof out->key,   "%s", key ? key : "");
        snprintf(out->model, sizeof out->model, "%s", model ? model : "gpt-4o-mini");
        return 0;
    }

    if (strncmp(opt, "ollama", 6) == 0) {
        int port = 11434;
        if (opt[6] == ':' && opt[7] != '\0')
            port = atoi(opt + 7);
        snprintf(out->url, sizeof out->url,
                 "http://localhost:%d/v1/chat/completions", port);
        out->key[0] = '\0'; /* local - no auth */
        snprintf(out->model, sizeof out->model, "%s", model ? model : "llama3.2");
        return 0;
    }

    if (strncmp(opt, "http://", 7) == 0 || strncmp(opt, "https://", 8) == 0) {
        snprintf(out->url, sizeof out->url, "%s", opt);
        const char *key = getenv("SHEER_API_KEY");
        snprintf(out->key,   sizeof out->key,   "%s", key ? key : "");
        snprintf(out->model, sizeof out->model, "%s", model ? model : "gpt-4o-mini");
        return 0;
    }

    return -1; /* unknown provider string */
}

/*
 * this is not a JSON parser. it's a JSON grep. it will break on nested
 * objects, duplicate keys, or values that contain the key name as a substring.
 * in practice the model follows the schema we gave it, so it works.
 * if you see garbage output the model didn't follow instructions. not our fault.
 *
 * TODO: swap this for a real parser if the response schema ever grows. jsmn
 * is ~200 lines and header-only if we go that route.
 */
static bool json_str(const char *json, const char *key,
                     char *out, size_t outlen)
{
    char needle[128];
    snprintf(needle, sizeof needle, "\"%s\"", key);

    const char *p = strstr(json, needle);
    if (!p) return false;
    p += strlen(needle);

    while (*p == ' ' || *p == '\t' || *p == ':' || *p == '\n') p++;
    if (*p != '"') return false;
    p++;

    size_t i = 0;
    while (*p && *p != '"' && i < outlen - 1) {
        if (*p == '\\' && *(p + 1)) {
            switch (*++p) {
            case 'n':  out[i++] = '\n'; break;
            case 't':  out[i++] = '\t'; break;
            case '"':  out[i++] = '"';  break;
            case '\\': out[i++] = '\\'; break;
            default:   out[i++] = *p;   break;
            }
        } else {
            out[i++] = *p;
        }
        p++;
    }
    out[i] = '\0';
    return true;
}

static Risk risk_from_str(const char *s)
{
    if (!s || *s == '\0')      return RISK_LOW;
    if (strstr(s, "CRITICAL")) return RISK_CRITICAL;
    if (strstr(s, "HIGH"))     return RISK_HIGH;
    if (strstr(s, "MEDIUM") ||
        strstr(s, "MODERATE")) return RISK_MEDIUM;
    if (strstr(s, "LOW"))      return RISK_LOW;
    if (strstr(s, "SAFE"))     return RISK_SAFE;
    return RISK_LOW;
}

static void json_escape(const char *src, char *dst, size_t dstlen)
{
    size_t d = 0;
    for (const char *s = src; *s && d < dstlen - 4; s++) {
        switch (*s) {
        case '"':  dst[d++] = '\\'; dst[d++] = '"';  break;
        case '\\': dst[d++] = '\\'; dst[d++] = '\\'; break;
        case '\n': dst[d++] = '\\'; dst[d++] = 'n';  break;
        case '\r': dst[d++] = '\\'; dst[d++] = 'r';  break;
        case '\t': dst[d++] = '\\'; dst[d++] = 't';  break;
        default:   dst[d++] = *s;                     break;
        }
    }
    dst[d] = '\0';
}

void llm_analyze(const char *cmd, const LlmConf *conf, Analysis *out)
{
    if (!conf || conf->url[0] == '\0') {
        snprintf(out->explanation, sizeof out->explanation,
                 "No LLM configured. Use --llm, --llm=ollama, or set SHEER_API_KEY.");
        out->matched = false;
        return;
    }

    char esc_cmd[4096], esc_sys[2048];
    json_escape(cmd,           esc_cmd, sizeof esc_cmd);
    json_escape(SYSTEM_PROMPT, esc_sys, sizeof esc_sys);

    char payload[8192];
    snprintf(payload, sizeof payload,
             "{\"model\":\"%s\","
             "\"messages\":["
               "{\"role\":\"system\",\"content\":\"%s\"},"
               "{\"role\":\"user\",\"content\":\"%s\"}"
             "],"
             "\"max_tokens\":300,"
             "\"temperature\":0}",
             conf->model, esc_sys, esc_cmd);

    /* temp file avoids shell-injection in popen() */
    char tmppath[] = "/tmp/sheer_XXXXXX";
    int fd = mkstemp(tmppath);
    if (fd < 0) goto fail_io;

    {
        FILE *tf = fdopen(fd, "w");
        if (!tf) { close(fd); unlink(tmppath); goto fail_io; }
        fputs(payload, tf);
        fclose(tf);
    }

    /* single-quoted URL and key - no word-splitting */
    char curl_cmd[2048];
    if (conf->key[0] != '\0') {
        snprintf(curl_cmd, sizeof curl_cmd,
                 "curl -s -m 15 -X POST '%s' "
                 "-H 'Content-Type: application/json' "
                 "-H 'Authorization: Bearer %s' "
                 "-d @'%s' 2>/dev/null",
                 conf->url, conf->key, tmppath);
    } else {
        /* local endpoint - omit Authorization header entirely */
        snprintf(curl_cmd, sizeof curl_cmd,
                 "curl -s -m 15 -X POST '%s' "
                 "-H 'Content-Type: application/json' "
                 "-d @'%s' 2>/dev/null",
                 conf->url, tmppath);
    }

    FILE *fp = popen(curl_cmd, "r");
    if (!fp) { unlink(tmppath); goto fail_io; }

    char response[8192] = "";
    size_t total = 0;
    char   rbuf[512];
    while (total < sizeof response - 1 && fgets(rbuf, sizeof rbuf, fp)) {
        size_t n = strlen(rbuf);
        if (total + n >= sizeof response - 1) n = sizeof response - 1 - total;
        memcpy(response + total, rbuf, n);
        total += n;
    }
    response[total] = '\0';
    pclose(fp);
    unlink(tmppath);

    /* OpenAI wraps the reply: choices[0].message.content */
    char content[4096] = "";
    const char *cp = strstr(response, "\"content\":");
    if (cp) json_str(cp, "content", content, sizeof content);
    if (content[0] == '\0')  /* Ollama and others return JSON directly */
        snprintf(content, sizeof content, "%s", response);

    char expl[1024] = "", risk_s[32] = "", warn[512] = "", safer[512] = "";
    json_str(content, "explanation", expl,   sizeof expl);
    json_str(content, "risk",        risk_s, sizeof risk_s);
    json_str(content, "warning",     warn,   sizeof warn);
    json_str(content, "safer",       safer,  sizeof safer);

    if (expl[0] == '\0') goto fail_parse;

    snprintf(out->explanation, sizeof out->explanation, "%s", expl);
    snprintf(out->warning,     sizeof out->warning,     "%s", warn);
    snprintf(out->safer,       sizeof out->safer,       "%s", safer);
    snprintf(out->source,      sizeof out->source,      "llm (%s)", conf->model);
    out->risk    = risk_from_str(risk_s);
    out->matched = true;
    return;

fail_parse:
    snprintf(out->explanation, sizeof out->explanation,
             "LLM responded but output couldn't be parsed. "
             "Check your endpoint and model (%s @ %s).",
             conf->model, conf->url);
    out->matched = false;
    return;

fail_io:
    snprintf(out->explanation, sizeof out->explanation,
             "LLM query failed - ensure curl is on PATH.");
    out->matched = false;
}

void llm_gen(const char *description, const char *context,
             const LlmConf *conf, char *cmd_out, size_t outlen)
{
    cmd_out[0] = '\0';

    if (!conf || conf->url[0] == '\0')
        return;

    /*
     * we give the model history context so it can make smarter suggestions.
     * if you've been working with docker all session, "run postgres" should
     * give you "docker run postgres", not some obscure init system invocation.
     */
    char ctx_block[1024] = "";
    if (context && context[0] != '\0') {
        snprintf(ctx_block, sizeof ctx_block,
                 "Recent shell history for context:\\n%s\\n\\n", context);
    }

    char esc_desc[2048], esc_ctx[2048];
    json_escape(description, esc_desc, sizeof esc_desc);
    json_escape(ctx_block,   esc_ctx,  sizeof esc_ctx);

    /* system prompt for gen mode: output ONLY the command, nothing else */
    const char *sys =
        "You are a shell command generator. "
        "Given a plain-English description, output ONLY the exact shell command "
        "that accomplishes it. One line. No explanation. No markdown. No backticks. "
        "No surrounding text. Just the command.";

    char esc_sys[1024];
    json_escape(sys, esc_sys, sizeof esc_sys);

    char user_msg[4096];
    snprintf(user_msg, sizeof user_msg, "%s%s", ctx_block, description);
    char esc_user[4096];
    json_escape(user_msg, esc_user, sizeof esc_user);

    char payload[8192];
    snprintf(payload, sizeof payload,
             "{\"model\":\"%s\","
             "\"messages\":["
               "{\"role\":\"system\",\"content\":\"%s\"},"
               "{\"role\":\"user\",\"content\":\"%s\"}"
             "],"
             "\"max_tokens\":128,"
             "\"temperature\":0}",
             conf->model, esc_sys, esc_user);

    char tmppath[] = "/tmp/sheer_gen_XXXXXX";
    int fd = mkstemp(tmppath);
    if (fd < 0) return;

    {
        FILE *tf = fdopen(fd, "w");
        if (!tf) { close(fd); unlink(tmppath); return; }
        fputs(payload, tf);
        fclose(tf);
    }

    char curl_cmd[2048];
    if (conf->key[0] != '\0') {
        snprintf(curl_cmd, sizeof curl_cmd,
                 "curl -s -m 15 -X POST '%s' "
                 "-H 'Content-Type: application/json' "
                 "-H 'Authorization: Bearer %s' "
                 "-d @'%s' 2>/dev/null",
                 conf->url, conf->key, tmppath);
    } else {
        snprintf(curl_cmd, sizeof curl_cmd,
                 "curl -s -m 15 -X POST '%s' "
                 "-H 'Content-Type: application/json' "
                 "-d @'%s' 2>/dev/null",
                 conf->url, tmppath);
    }

    FILE *fp = popen(curl_cmd, "r");
    if (!fp) { unlink(tmppath); return; }

    char response[4096] = "";
    size_t total = 0;
    char   rbuf[512];
    while (total < sizeof response - 1 && fgets(rbuf, sizeof rbuf, fp)) {
        size_t n = strlen(rbuf);
        if (total + n >= sizeof response - 1) n = sizeof response - 1 - total;
        memcpy(response + total, rbuf, n);
        total += n;
    }
    response[total] = '\0';
    pclose(fp);
    unlink(tmppath);

    /* OpenAI wraps the reply, Ollama doesn't - handle both */
    char content[2048] = "";
    const char *cp = strstr(response, "\"content\":");
    if (cp) json_str(cp, "content", content, sizeof content);
    if (content[0] == '\0')
        snprintf(content, sizeof content, "%s", response);

    /* strip whitespace and any backtick fencing the model snuck in */
    char *s = content;
    while (*s == ' ' || *s == '\t' || *s == '\n' || *s == '`') s++;
    size_t len = strlen(s);
    while (len > 0 && (s[len-1] == '\n' || s[len-1] == '\r' ||
                       s[len-1] == ' '  || s[len-1] == '`'))
        s[--len] = '\0';

    snprintf(cmd_out, outlen, "%s", s);
}

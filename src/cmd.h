#pragma once

#include "token.h"

/* risk levels. CRITICAL means "you will regret this" */
typedef enum {
    RISK_SAFE     = 0,
    RISK_LOW      = 1,
    RISK_MEDIUM   = 2,
    RISK_HIGH     = 3,
    RISK_CRITICAL = 4,
} Risk;

typedef struct {
    char explanation[1024];
    char warning[512];
    char safer[512];
    char source[32];    /* "local rules" | "llm (model)" */
    Risk risk;
    bool matched;
} Analysis;

static inline Risk risk_max(Risk a, Risk b) { return a > b ? a : b; }

void cmd_analyze(const TokList *tl, Analysis *out);

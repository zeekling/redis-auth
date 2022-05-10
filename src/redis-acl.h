
#ifndef REDISAUTH_H
#include "redismodule.h"

/* Error status return values. */
#define REDISMODULE_OK 0
#define REDISMODULE_ERR 1
#define LOG_LEVL_NOTICE "notice"

/* *
 * Redis Auth command
 * */
int AuthCommand_RedisCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc);

void AuthFilter_CommandFilter(RedisModuleCommandFilter *filter);

#endif // REDISAUTH_H




#include <stdio.h>
#include "redis-acl.h"
#include "redismodule.h"

static RedisModuleCommandFilter *filter;
static int time = 1;
static int MAX_TIME = 1000;

void AuthFilter_CommandFilter(RedisModuleCommandFilter *filter) {
  int pos = 0;
  RedisModule_Log(NULL, LOG_LEVEL_NOTICE, "command filter");
  while (pos < RedisModule_CommandFilterArgsCount(filter)) {
    const RedisModuleString *arg = RedisModule_CommandFilterArgGet(filter, pos);
    size_t arg_len;
    const char *arg_str = RedisModule_StringPtrLen(arg, &arg_len);
    RedisModule_Log(NULL, LOG_LEVEL_NOTICE, "str=%s,len=%ld", arg_str, arg_len);
    if (strcmp(arg_str, "auth") == 0) {
      RedisModule_Log(NULL, LOG_LEVEL_NOTICE, "command is auth");
      RedisModule_CommandFilterArgReplace(filter, pos, RedisModule_CreateString(NULL, "acl.auth", 9));
    }
    // 解密
    pos++;
  }
  RedisModule_Log(NULL, LOG_LEVEL_NOTICE, "filter finished");
}

int AuthCommand_RedisCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
  REDISMODULE_NOT_USED(ctx);
  REDISMODULE_NOT_USED(argc);
  REDISMODULE_NOT_USED(argv);
  RedisModule_Log(ctx, LOG_LEVEL_NOTICE, "acl.auth begin");
  RedisModule_ReplyWithCString(ctx, "ok");
  return REDISMODULE_OK;
}

void cronLoopCallBack(RedisModuleCtx *ctx, RedisModuleEvent *e, uint64_t sub, void *data) {
  REDISMODULE_NOT_USED(e);
  RedisModuleCronLoop *ei = data;
  REDISMODULE_NOT_USED(ei);
  REDISMODULE_NOT_USED(sub);
  if (time < MAX_TIME) {
    time++;
    return;
  }
  RedisModule_Log(ctx, LOG_LEVEL_NOTICE, "cron event");
  time = 0;
}

int RedisModule_OnLoad(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
  REDISMODULE_NOT_USED(argv);
  REDISMODULE_NOT_USED(argc);
  if (RedisModule_Init(ctx, "redis-auth", 1, REDISMODULE_APIVER_1) == REDISMODULE_ERR) {
    RedisModule_Log(ctx, LOG_LEVEL_NOTICE, "init redis-auth failed");
    return REDISMODULE_ERR;
  }

  filter = RedisModule_RegisterCommandFilter(ctx, AuthFilter_CommandFilter, 0);
  if (filter == NULL) {
    RedisModule_Log(ctx, LOG_LEVEL_WARNING, "init filter failed");
    return REDISMODULE_ERR;
  }
  RedisModule_Log(ctx, LOG_LEVEL_NOTICE, "init filter success");

  if (RedisModule_CreateCommand(ctx, "acl.auth", AuthCommand_RedisCommand, 
        "no-auth", 0,0,0) == REDISMODULE_ERR) {
    RedisModule_Log(ctx, LOG_LEVEL_WARNING, "init acl.auth failed");
    return REDISMODULE_ERR;
  }
  RedisModule_Log(ctx, LOG_LEVEL_NOTICE, "init command success");
  RedisModule_SubscribeToServerEvent(ctx, RedisModuleEvent_CronLoop, cronLoopCallBack);

  RedisModule_Log(ctx, LOG_LEVEL_NOTICE, "init redis-auth success!");
  return REDISMODULE_OK;
}


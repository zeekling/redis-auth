#include <pthread.h>
#include <stdio.h>

#include "redis-acl.h"
#include "redismodule.h"

static RedisModuleCommandFilter *filter;
static int times = 1;
static int MAX_TIME = 1000;

void AuthFilter_CommandFilter(RedisModuleCommandFilter *filter) {
  int pos = 0;
  RedisModule_Log(NULL, LOG_LEVEL_NOTICE, "command filter");
  while (pos < RedisModule_CommandFilterArgsCount(filter)) {
    const RedisModuleString *arg = RedisModule_CommandFilterArgGet(filter, pos);
    size_t arg_len;
    const char *arg_str = RedisModule_StringPtrLen(arg, &arg_len);
    // RedisModule_Log(NULL, LOG_LEVEL_NOTICE, "str=%s,len=%ld", arg_str, arg_len);
    // if (strcmp(arg_str, "auth") == 0) {
    //  RedisModule_Log(NULL, LOG_LEVEL_NOTICE, "command is auth");
    //  RedisModule_CommandFilterArgReplace(filter, pos,
    //  RedisModule_CreateString(NULL, "acl.auth", 9));
    //}
    // 解密
    pos++;
  }
  RedisModule_Log(NULL, LOG_LEVEL_NOTICE, "filter finished");
}

int AuthCommand_RedisCommand(RedisModuleCtx *ctx, RedisModuleString **argv,
                             int argc) {
  REDISMODULE_NOT_USED(ctx);
  REDISMODULE_NOT_USED(argc);
  REDISMODULE_NOT_USED(argv);
  RedisModule_Log(ctx, LOG_LEVEL_NOTICE, "acl.auth begin");
  RedisModule_ReplyWithCString(ctx, "ok");
  return REDISMODULE_OK;
}

RedisModuleUser* createUser(RedisModuleCtx *ctx, const char *name) {
  RedisModuleUser *user = RedisModule_CreateModuleUser(name);
  RedisModule_SetModuleUserACL(user, "allcommands");
  RedisModule_SetModuleUserACL(user, "allkeys");
  RedisModule_SetModuleUserACL(user, "on");
  return user;
}

int module_auth_reply(RedisModuleCtx *ctx, RedisModuleString *username,
                      RedisModuleString *password, RedisModuleString **err) {
  void **targ = RedisModule_GetBlockedClientPrivateData(ctx);
  int result = (uintptr_t)targ[0];
  RedisModule_Log(ctx, LOG_LEVEL_NOTICE, "auth reply");
  size_t userlen = 0;
  const char *user = RedisModule_StringPtrLen(username, &userlen);
  if (result == 1) {
    // auth success
    RedisModuleUser *moduleUser = createUser(ctx, user);
    uint64_t client_id;
    int auth_result = RedisModule_AuthenticateClientWithUser(ctx, moduleUser, NULL, NULL, &client_id);
    RedisModule_Log(ctx, LOG_LEVEL_NOTICE, "auth success user=%s, %lu", user, client_id);
    if (auth_result == REDISMODULE_ERR) {
      RedisModule_Log(ctx, LOG_LEVEL_NOTICE, "user not exits user=%s", user);
    }
    return REDISMODULE_AUTH_HANDLED;
  } else if (result == 0) {
    // auth failed
    const char *err_msg = "Auth denied by Misc Module.";
    *err = RedisModule_CreateString(ctx, err_msg, strlen(err_msg));
    return REDISMODULE_AUTH_HANDLED;
  }
  /** skip auth*/
  return REDISMODULE_AUTH_HANDLED;
}

void free_auth_data(RedisModuleCtx *ctx, void *privdata) {
  REDISMODULE_NOT_USED(ctx);
  RedisModule_Free(privdata);
}

void *AuthBlock_ThreadMain(void *arg) {
  void **targ = arg;
  RedisModuleBlockedClient *bc = targ[0];
  RedisModuleCtx *ctx = targ[1];
  RedisModule_Log(ctx, LOG_LEVEL_NOTICE, "begin auth ");
  const char *user = RedisModule_StringPtrLen(targ[2], NULL);
  const char *pwd = RedisModule_StringPtrLen(targ[3], NULL);
  int result = 2;
  if (!strcmp(user, "foo") && !strcmp(pwd, "block_allow")) {
    RedisModule_Log(ctx, LOG_LEVEL_NOTICE, "auth success");
    result = 1;
  } else if (!strcmp(user, "foo") && !strcmp(pwd, "block_deny")) {
    result = 0;
  } else if (!strcmp(user, "foo") && !strcmp(pwd, "block_abort")) {
    RedisModule_BlockedClientMeasureTimeEnd(bc);
    RedisModule_AbortBlock(bc);
    goto cleanup;
  } else {
    result = 0;
  }
  void **replyarg = RedisModule_Alloc(sizeof(void *));
  replyarg[0] = (void *)(uintptr_t)result;
  RedisModule_BlockedClientMeasureTimeEnd(bc);
  RedisModule_UnblockClient(bc, replyarg);
cleanup:
  RedisModule_FreeString(NULL, targ[2]);
  RedisModule_FreeString(NULL, targ[3]);
  RedisModule_Free(targ);
  return NULL;
}

int module_auth(RedisModuleCtx *ctx, RedisModuleString *username,
                RedisModuleString *password, RedisModuleString **err) {
  RedisModuleBlockedClient *bc =
      RedisModule_BlockClientOnAuth(ctx, module_auth_reply, free_auth_data);
  int ctx_flags = RedisModule_GetContextFlags(ctx);
  if (ctx_flags & REDISMODULE_CTX_FLAGS_MULTI ||
      ctx_flags & REDISMODULE_CTX_FLAGS_LUA) {
    RedisModule_UnblockClient(bc, NULL);
    return REDISMODULE_AUTH_HANDLED;
  }
  RedisModule_BlockedClientMeasureTimeStart(bc);
  pthread_t tid;
  void **targ = RedisModule_Alloc(sizeof(void *) * 4);
  targ[0] = bc;
  targ[1] = ctx;
  targ[2] = RedisModule_CreateStringFromString(NULL, username);
  targ[3] = RedisModule_CreateStringFromString(NULL, password);
  /* Create bg thread and pass the blockedclient, username and password to it.
   */
  if (pthread_create(&tid, NULL, AuthBlock_ThreadMain, targ) != 0) {
    RedisModule_AbortBlock(bc);
  }
  return REDISMODULE_AUTH_HANDLED;
}

int auth_cb(RedisModuleCtx *ctx, RedisModuleString *username,
            RedisModuleString *password, RedisModuleString **err) {
  const char *user = RedisModule_StringPtrLen(username, NULL);
  const char *pwd = RedisModule_StringPtrLen(password, NULL);
  if (!strcmp(user, "foo") && !strcmp(pwd, "allow")) {
    RedisModuleUser *user = createUser(ctx, "foo");
    RedisModule_AuthenticateClientWithACLUser(ctx, "foo", 3, NULL, NULL, NULL);
    return REDISMODULE_AUTH_HANDLED;
  } else if (!strcmp(user, "foo") && !strcmp(pwd, "deny")) {
    const char *err_msg = "Auth denied by Misc Module.";
    *err = RedisModule_CreateString(ctx, err_msg, strlen(err_msg));
    return REDISMODULE_AUTH_HANDLED;
  }
  return REDISMODULE_AUTH_NOT_HANDLED;
}

void cronLoopCallBack(RedisModuleCtx *ctx, RedisModuleEvent *e, uint64_t sub,
                      void *data) {
  REDISMODULE_NOT_USED(e);
  RedisModuleCronLoop *ei = data;
  REDISMODULE_NOT_USED(ei);
  REDISMODULE_NOT_USED(sub);
  if (time < MAX_TIME) {
    times++;
    return;
  }
  RedisModule_Log(ctx, LOG_LEVEL_NOTICE, "cron event");
  times = 0;
}

int RedisModule_OnLoad(RedisModuleCtx *ctx, RedisModuleString **argv,
                       int argc) {
  REDISMODULE_NOT_USED(argv);
  REDISMODULE_NOT_USED(argc);
  if (RedisModule_Init(ctx, "redis-auth", 1, REDISMODULE_APIVER_1) ==
      REDISMODULE_ERR) {
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
                                "no-auth", 0, 0, 0) == REDISMODULE_ERR) {
    RedisModule_Log(ctx, LOG_LEVEL_WARNING, "init acl.auth failed");
    return REDISMODULE_ERR;
  }

  RedisModule_RegisterAuthCallback(ctx, module_auth);
  RedisModule_RegisterAuthCallback(ctx, auth_cb);

  RedisModule_Log(ctx, LOG_LEVEL_NOTICE, "init command success");
  // RedisModule_SubscribeToServerEvent(ctx, RedisModuleEvent_CronLoop,
  // cronLoopCallBack);

  RedisModule_Log(ctx, LOG_LEVEL_NOTICE, "init redis-auth success!");
  return REDISMODULE_OK;
}

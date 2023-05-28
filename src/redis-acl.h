
#ifndef REDISAUTH_H
#include "redismodule.h"

/* Error status return values. */
#define REDISMODULE_OK 0
#define REDISMODULE_ERR 1
#define LOG_LEVEL_NOTICE "notice"
#define LOG_LEVEL_WARNING "warning"

#define UNUSED(V) ((void) V) 

struct redisAcl {
    RedisModuleString *username;
    RedisModuleString *password;
} redisAcl;


RedisModuleUser *createUser(RedisModuleCtx *ctx, const char *name);

int authReply(RedisModuleCtx *ctx, RedisModuleString *username, RedisModuleString *password, RedisModuleString **err);

void freeAuthData(RedisModuleCtx *ctx, void *privdata);

void *AuthBlockThreadMain(void *arg);

int moduleBlockAuth(RedisModuleCtx *ctx, RedisModuleString *username, RedisModuleString *password, RedisModuleString **err);

int moduleAuth(RedisModuleCtx *ctx, RedisModuleString *username, RedisModuleString *password, RedisModuleString **err);

void cronLoopCallBack(RedisModuleCtx *ctx, RedisModuleEvent *e, uint64_t sub,  void *data);

int banDefaultUser(RedisModuleCtx *ctx);

#endif // REDISAUTH_H




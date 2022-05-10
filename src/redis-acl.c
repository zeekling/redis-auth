
#include <stdio.h>
#include "redis-acl.h"
#include "redismodule.h"

static RedisModuleCommandFilter *filter;

void AuthFilter_CommandFilter(RedisModuleCommandFilter *filter) {
    int log = 0;
    int pos = 0;
	RedisModule_Log(NULL, LOG_LEVL_NOTICE, "command filter");
	while (pos < RedisModule_CommandFilterArgsCount(filter)) {
		const RedisModuleString *arg = RedisModule_CommandFilterArgGet(filter, pos);
		size_t arg_len;
		const char *arg_str = RedisModule_StringPtrLen(arg, &arg_len);
		RedisModule_Log(NULL, LOG_LEVL_NOTICE, "str=%s,len=%d", arg_str, arg_len);
		// 解密
		pos++;
   }
	RedisModuleUser *user = RedisModule_CreateModuleUser("default");
	if (user == NULL) {
        RedisModule_Log(NULL, LOG_LEVL_NOTICE, "user is null");

	}

}

int AuthCommand_RedisCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {

	return REDISMODULE_OK;
}

void create_users(RedisModuleCtx *ctx) {
	RedisModuleUser *user =  RedisModule_CreateModuleUser("default");
	RedisModule_SetModuleUserACL(user, "allcommands");
    RedisModule_SetModuleUserACL(user, "allkeys");
    RedisModule_SetModuleUserACL(user, "on");
	RedisModule_Log(ctx, LOG_LEVL_NOTICE, "init module user success!");
	RedisModule_FreeModuleUser(user);
}

int RedisModule_OnLoad(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
	REDISMODULE_NOT_USED(argv);
    REDISMODULE_NOT_USED(argc);
	if (RedisModule_Init(ctx, "redis-auth", 1, REDISMODULE_APIVER_1) == REDISMODULE_ERR) {
		RedisModule_Log(ctx, LOG_LEVL_NOTICE, "init redis-auth failed");
		return REDISMODULE_ERR;
	}

	create_users(ctx);


    filter = RedisModule_RegisterCommandFilter(ctx, AuthFilter_CommandFilter, 0);
	if (filter == NULL) {
		return REDISMODULE_ERR;
	}

	RedisModule_Log(ctx, LOG_LEVL_NOTICE, "init redis-auth success!");
	return REDISMODULE_OK;
}


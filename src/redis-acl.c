#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include "redis-acl.h"
#include "redismodule.h"
#include "postgres-client.h"

static int times = 1;
static int MAX_TIME = 1000;
static RedisModuleDict *userDict = NULL;

RedisModuleString *strval = NULL;

RedisModuleUser *createUser(RedisModuleCtx *ctx, const char *name) {
    REDISMODULE_NOT_USED(ctx);
    RedisModuleUser *user = RedisModule_CreateModuleUser(name);
    RedisModule_SetModuleUserACL(user, "allcommands");
    RedisModule_SetModuleUserACL(user, "allkeys");
    RedisModule_SetModuleUserACL(user, "on");
    return user;
}

int authReply(RedisModuleCtx *ctx, RedisModuleString *username,
              RedisModuleString *password, RedisModuleString **err) {
    REDISMODULE_NOT_USED(password);
    void **targ = RedisModule_GetBlockedClientPrivateData(ctx);
    int result = (uintptr_t)targ[0];
    RedisModule_Log(ctx, LOG_LEVEL_NOTICE, "auth reply");
    size_t userlen = 0;
    const char *user = RedisModule_StringPtrLen(username, &userlen);
    if (result == 1) {
        // auth success
        RedisModuleUser *moduleUser = createUser(ctx, user);
        uint64_t client_id;
        int authResult = RedisModule_AuthenticateClientWithUser(
            ctx, moduleUser, NULL, NULL, &client_id);
        RedisModule_Log(ctx, LOG_LEVEL_NOTICE, "auth success user=%s, %lu", user,
                        client_id);
        if (authResult == REDISMODULE_ERR) {
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

void freeAuthData(RedisModuleCtx *ctx, void *privdata) {
    REDISMODULE_NOT_USED(ctx);
    RedisModule_Free(privdata);
}

void *AuthBlockThreadMain(void *arg) {
    void **targ = arg;
    RedisModuleBlockedClient *bc = targ[0];
    RedisModuleCtx *ctx = targ[1];
    RedisModule_Log(ctx, LOG_LEVEL_NOTICE, "begin auth ");
    const char *user = RedisModule_StringPtrLen(targ[2], NULL);
    const char *pwd = RedisModule_StringPtrLen(targ[3], NULL);
    void **replyarg = RedisModule_Alloc(sizeof(void *));
    int result = 2;
    struct redisAcl *acl = (struct redisAcl *)RedisModule_DictGetC(userDict, (void *)user, strlen(user), NULL);
    if (!acl) {
        RedisModule_Log(ctx, LOG_LEVEL_WARNING, "auth failed");
        result = 0;
        goto returnResult;
    }
    const char *passwdInModule = RedisModule_StringPtrLen(acl->password, NULL);
    if (!strcmp(pwd, passwdInModule)) {
        result = 1;
    } else {
        result = 0;
    }
returnResult:
    replyarg[0] = (void *)(uintptr_t)result;
    RedisModule_BlockedClientMeasureTimeEnd(bc);
    RedisModule_UnblockClient(bc, replyarg);
    RedisModule_FreeString(NULL, targ[2]);
    RedisModule_FreeString(NULL, targ[3]);
    RedisModule_Free(targ);
    return NULL;
}

int moduleBlockAuth(RedisModuleCtx *ctx, RedisModuleString *username,
                    RedisModuleString *password, RedisModuleString **err) {
    REDISMODULE_NOT_USED(password);
    REDISMODULE_NOT_USED(err);
    RedisModuleBlockedClient *bc =
        RedisModule_BlockClientOnAuth(ctx, authReply, freeAuthData);
    int ctx_flags = RedisModule_GetContextFlags(ctx);
    if (ctx_flags & REDISMODULE_CTX_FLAGS_MULTI || ctx_flags & REDISMODULE_CTX_FLAGS_LUA) {
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
    if (pthread_create(&tid, NULL, AuthBlockThreadMain, targ) != 0) {
        RedisModule_AbortBlock(bc);
    }
    return REDISMODULE_AUTH_HANDLED;
}

int moduleAuth(RedisModuleCtx *ctx, RedisModuleString *username,
               RedisModuleString *password, RedisModuleString **err) {
    const char *user = RedisModule_StringPtrLen(username, NULL);
    const char *pwd = RedisModule_StringPtrLen(password, NULL);
    struct redisAcl *acl = (struct redisAcl *)RedisModule_DictGetC(userDict, (void *)user, strlen(user), NULL);
    if (!acl) {
        const char *err_msg = "Auth denied by Misc Module.";
        *err = RedisModule_CreateString(ctx, err_msg, strlen(err_msg));
        return REDISMODULE_AUTH_HANDLED;
    }
    const char *userInModule = RedisModule_StringPtrLen(acl->username, NULL);
    const char *userInPass = RedisModule_StringPtrLen(acl->password, NULL);

    if (!strcmp(pwd, userInPass)) {
        RedisModuleUser *moduleUser = createUser(ctx, userInModule);
        uint64_t client_id;
        RedisModule_AuthenticateClientWithUser(ctx, moduleUser, NULL, NULL, &client_id);
        return REDISMODULE_AUTH_HANDLED;
    } else {
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

int initUsers(RedisModuleCtx *ctx, const char *user, const char *passwd) {
    REDISMODULE_NOT_USED(ctx);
    if (userDict == NULL) {
        userDict = RedisModule_CreateDict(ctx);
    }
    struct redisAcl *acl;
    acl = RedisModule_Alloc(sizeof(*acl));
    memset(acl, 0, sizeof(*acl));
    acl->username = RedisModule_CreateString(ctx, user, strlen(user));
    acl->password = RedisModule_CreateString(ctx, passwd, strlen(passwd));
    int result = RedisModule_DictSetC(userDict, (void *)user, strlen(user), acl);
    if (result == REDISMODULE_OK) {
        const char *userModule = RedisModule_StringPtrLen(acl->username, NULL);
        RedisModule_Log(ctx, LOG_LEVEL_NOTICE, "user add success, username=%s", userModule);
    }
    return REDISMODULE_OK;
}

int banDefaultUser(RedisModuleCtx *ctx) {
  RedisModuleCallReply *reply = RedisModule_Call(ctx, "ACL", "ccc", "SETUSER", "default", "off");
  if (reply == NULL) {
    RedisModule_Log(ctx, LOG_LEVEL_WARNING, "Ban default user failed.");
    return REDISMODULE_ERR;
  }
  size_t len;
  const char *replyStr = RedisModule_CallReplyProto(reply, &len);
  RedisModule_Log(ctx, "Ban default user success, reply=%s", replyStr);
  return REDISMODULE_OK;
}

RedisModuleString *getAuthUrlConfigCommand(const char *name, void *privdata) {
    REDISMODULE_NOT_USED(name);
    REDISMODULE_NOT_USED(privdata);
    return strval;
}
int setAuthUrlConfigCommand(const char *name, RedisModuleString *new, void *privdata, RedisModuleString **err) {
    REDISMODULE_NOT_USED(name);
    REDISMODULE_NOT_USED(err);
    REDISMODULE_NOT_USED(privdata);
    size_t len;
    if (!strcasecmp(RedisModule_StringPtrLen(new, &len), "rejectisfreed")) {
        *err = RedisModule_CreateString(NULL, "Cannot set string to 'rejectisfreed'", 36);
        return REDISMODULE_ERR;
    }
    if (strval) RedisModule_FreeString(NULL, strval);
    RedisModule_RetainString(NULL, new);
    strval = new;
    return REDISMODULE_OK;
}

RedisModuleString *getAuthDBConfigCommand(const char *name, void *privdata) {
    REDISMODULE_NOT_USED(name);
    REDISMODULE_NOT_USED(privdata);
    return strval;
}
int setAuthDBConfigCommand(const char *name, RedisModuleString *new, void *privdata, RedisModuleString **err) {
    REDISMODULE_NOT_USED(name);
    REDISMODULE_NOT_USED(err);
    REDISMODULE_NOT_USED(privdata);
    size_t len;
    if (!strcasecmp(RedisModule_StringPtrLen(new, &len), "rejectisfreed")) {
        *err = RedisModule_CreateString(NULL, "Cannot set string to 'rejectisfreed'", 36);
        return REDISMODULE_ERR;
    }
    if (strval) RedisModule_FreeString(NULL, strval);
    RedisModule_RetainString(NULL, new);
    strval = new;
    return REDISMODULE_OK;
}

int registerConfig(RedisModuleCtx *ctx) {
    int result = RedisModule_RegisterStringConfig(ctx, "auth.url", "", REDISMODULE_CONFIG_DEFAULT, getAuthUrlConfigCommand, setAuthUrlConfigCommand, NULL, NULL);
    
    RedisModule_RegisterStringConfig(ctx, "auth.db", "", REDISMODULE_CONFIG_DEFAULT, getAuthDBConfigCommand, setAuthDBConfigCommand, NULL, NULL);
}

int RedisModule_OnLoad(RedisModuleCtx *ctx, RedisModuleString **argv,
                       int argc) {
    REDISMODULE_NOT_USED(argv);
    REDISMODULE_NOT_USED(argc);
    if (RedisModule_Init(ctx, "redis-auth", 1, REDISMODULE_APIVER_1) == REDISMODULE_ERR) {
        RedisModule_Log(ctx, LOG_LEVEL_NOTICE, "init redis-auth failed");
        return REDISMODULE_ERR;
    }

    RedisModule_RegisterAuthCallback(ctx, moduleBlockAuth);
    RedisModule_RegisterAuthCallback(ctx, moduleAuth);
    banDefaultUser(ctx);
    initUsers(ctx, "foo", "block_allow");

    RedisModule_Log(ctx, LOG_LEVEL_NOTICE, "init redis-auth success!");
    return REDISMODULE_OK;
}

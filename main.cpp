/*
 * 夜白过检测 1.0
 * 编译：x86_64-w64-mingw32-g++ -mwindows -static -o 夜白过检测.exe main.cpp resource.o -lwininet -ladvapi32 -lcomctl32
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wininet.h>
#include <aclapi.h>
#include <sddl.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <process.h>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "advapi32.lib")

// ==================== 配置区 ====================
#define CFG_APPID     "61572"
#define CFG_APPKEY    "00INaa4ja01VtNiy"
#define CFG_LOGIN_URL "http://wy.llua.cn/api/?id=kmlogon&app=61572"
#define CFG_NOTICE_URL "http://wy.llua.cn/api/?id=notice&app=61572"

// MinGW 缺少 TRUSTEE_IS_WILDCARD，改用 Everyone SID (S-1-1-0) 实现拒绝所有
#define ACE_FOLDER_PATH     "C:\\Program Files\\AntiCheatExpert"
#define GAME_PROCESS_NAME    "NRC-Win64-Shipping.exe"

#define WINDOW_TITLE "夜白过检测 1.0"
#define GAME_NAME    "洛克王国"

#define WIN_WIDTH  420
#define WIN_HEIGHT 355
// =========================================


// ========== 全局状态 ==========
static HWND g_hLoginWnd   = NULL;
static HWND g_hMainWnd   = NULL;
static HWND g_hStatusText = NULL;
static HWND g_hBtnStart   = NULL;
static HWND g_hBtnLogout = NULL;

static char g_Kami[64]   = {0};
static char g_VipTime[64] = {0};
static int  g_LoginOk    = 0;

static volatile LONG g_Running     = 0;
static volatile LONG g_GameStarted = 0;
static HANDLE g_MonitorThread = NULL;

static char g_LogBuf[8192] = {0};
static CRITICAL_SECTION g_csLog;


// ============================================================================
// 日志
// ============================================================================
static void EnterLog()  { EnterCriticalSection(&g_csLog); }
static void LeaveLog()  { LeaveCriticalSection(&g_csLog); }

static void AppendLog(const char* fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    EnterLog();
    int len = (int)strlen(g_LogBuf);
    if (len > 6000)
        memmove(g_LogBuf, g_LogBuf + 2000, 6000);
    strcat(g_LogBuf, buf);
    strcat(g_LogBuf, "\r\n");
    if (g_hStatusText) {
        SetWindowText(g_hStatusText, g_LogBuf);
        SendMessage(g_hStatusText, EM_SETSEL, -1, -1);
        SendMessage(g_hStatusText, EM_SCROLLCARET, 0, 0);
    }
    LeaveLog();
}

static void ClearLog() {
    EnterLog();
    g_LogBuf[0] = 0;
    if (g_hStatusText) SetWindowText(g_hStatusText, "");
    LeaveLog();
}


// ============================================================================
// MD5（自带实现，不依赖 CryptoAPI，避免跨编译器问题）
// ============================================================================
static void MD5_Init(void* ctx);
static void MD5_Update(void* ctx, const void* data, unsigned long len);
static void MD5_Final(unsigned char* out, void* ctx);
static void MD5Transform(unsigned long state[4], const unsigned char block[64]);

typedef struct {
    unsigned long state[4];
    unsigned long count[2];
    unsigned char buffer[64];
} MD5_CTX;

#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define F(x, y, z)   ((z) ^ ((x) & ((y) ^ (z))))
#define G(x, y, z)   ((y) ^ ((z) & ((x) ^ (y))))
#define H(x, y, z)   ((x) ^ (y) ^ (z))
#define I(x, y, z)   ((y) ^ ((x) | (~(z))))

#define FF(a,b,c,d,x,s,ac) a += F(b,c,d) + x + (unsigned long)(ac); a = ROTL32(a,s) + b;
#define GG(a,b,c,d,x,s,ac) a += G(b,c,d) + x + (unsigned long)(ac); a = ROTL32(a,s) + b;
#define HH(a,b,c,d,x,s,ac) a += H(b,c,d) + x + (unsigned long)(ac); a = ROTL32(a,s) + b;
#define II(a,b,c,d,x,s,ac) a += I(b,c,d) + x + (unsigned long)(ac); a = ROTL32(a,s) + b;

static const unsigned char MD5_PADDING[64] = {
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

static void MD5_Init(MD5_CTX* ctx) {
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xefcdab89;
    ctx->state[2] = 0x98badcfe;
    ctx->state[3] = 0x10325476;
    ctx->count[0] = ctx->count[1] = 0;
}

static void MD5_Update(MD5_CTX* ctx, const void* data, unsigned long len) {
    unsigned long i, index, partLen;
    const unsigned char* input = (const unsigned char*)data;
    index = (unsigned long)((ctx->count[0] >> 3) & 0x3F);
    if ((ctx->count[0] += ((unsigned long)len << 3)) < ((unsigned long)len << 3))
        ctx->count[1]++;
    ctx->count[1] += ((unsigned long)len >> 29);
    partLen = 64 - index;
    if (len >= partLen) {
        memcpy(&ctx->buffer[index], input, partLen);
        MD5Transform(ctx->state, ctx->buffer);
        for (i = partLen; i + 63 < len; i += 64)
            MD5Transform(ctx->state, &input[i]);
        index = 0;
    } else {
        i = 0;
    }
    memcpy(&ctx->buffer[index], &input[i], len - i);
}

static void MD5_Final(unsigned char digest[16], MD5_CTX* ctx) {
    unsigned char bits[8];
    unsigned long index, padLen;
    *(unsigned long*)bits = ctx->count[0];
    *(unsigned long*)(bits + 4) = ctx->count[1];
    index = (unsigned long)((ctx->count[0] >> 3) & 0x3f);
    padLen = (index < 56) ? (56 - index) : (120 - index);
    MD5_Update(ctx, MD5_PADDING, padLen);
    MD5_Update(ctx, bits, 8);
    memcpy(digest, ctx->state, 16);
}

static void MD5Transform(unsigned long state[4], const unsigned char block[64]) {
    unsigned long a = state[0], b = state[1], c = state[2], d = state[3], x[16];
    int i;
    for (i = 0; i < 16; i++)
        x[i] = ((unsigned long)block[i * 4]) |
               ((unsigned long)block[i * 4 + 1] << 8) |
               ((unsigned long)block[i * 4 + 2] << 16) |
               ((unsigned long)block[i * 4 + 3] << 24);

    FF(a, b, c, d, x[0],  7, 0xd76aa478); FF(d, a, b, c, x[1], 12, 0xe8c7b756);
    FF(c, d, a, b, x[2], 17, 0x242070db); FF(b, c, d, a, x[3], 22, 0xc1bdceee);
    FF(a, b, c, d, x[4],  7, 0xf57c0faf); FF(d, a, b, c, x[5], 12, 0x4787c62a);
    FF(c, d, a, b, x[6], 17, 0xa8304613); FF(b, c, d, a, x[7], 22, 0xfd469501);
    FF(a, b, c, d, x[8],  7, 0x698098d8); FF(d, a, b, c, x[9], 12, 0x8b44f7af);
    FF(c, d, a, b, x[10], 17, 0xffff5bb1); FF(b, c, d, a, x[11], 22, 0x895cd7be);
    FF(a, b, c, d, x[12],  7, 0x6b901122); FF(d, a, b, c, x[13], 12, 0xfd987193);
    FF(c, d, a, b, x[14], 17, 0xa679438e); FF(b, c, d, a, x[15], 22, 0x49b40821);

    GG(a, b, c, d, x[1],  5, 0xf61e2562); GG(d, a, b, c, x[6],  9, 0xc040b340);
    GG(c, d, a, b, x[11], 14, 0x265e5a51); GG(b, c, d, a, x[0], 20, 0xe9b6c7aa);
    GG(a, b, c, d, x[5],  5, 0xd62f105d); GG(d, a, b, c, x[10], 9, 0x2441453);
    GG(c, d, a, b, x[15], 14, 0xd8a1e681); GG(b, c, d, a, x[4], 20, 0xe7d3fbc8);
    GG(a, b, c, d, x[9],  5, 0x21e1cde6); GG(d, a, b, c, x[14], 9, 0xc33707d6);
    GG(c, d, a, b, x[3], 14, 0xf4d50d87); GG(b, c, d, a, x[8], 20, 0x455a14ed);
    GG(a, b, c, d, x[13],  5, 0xa9e3e905); GG(d, a, b, c, x[2],  9, 0xfcefa3f8);
    GG(c, d, a, b, x[7], 14, 0x676f02d9); GG(b, c, d, a, x[12], 20, 0x8d2a4c8a);

    HH(a, b, c, d, x[5],  4, 0xfffa3942); HH(d, a, b, c, x[8], 11, 0x8771f681);
    HH(c, d, a, b, x[11], 16, 0x6d9d6122); HH(b, c, d, a, x[14], 23, 0xfde5380c);
    HH(a, b, c, d, x[1],  4, 0xa4beea44); HH(d, a, b, c, x[4], 11, 0x4bdecfa9);
    HH(c, d, a, b, x[7], 16, 0xf6bb4b60); HH(b, c, d, a, x[10], 23, 0xbebfbc70);
    HH(a, b, c, d, x[13],  4, 0x289b7ec6); HH(d, a, b, c, x[0], 11, 0xeaa127fa);
    HH(c, d, a, b, x[3], 16, 0xd4ef3085); HH(b, c, d, a, x[6], 23, 0x4881d05);
    HH(a, b, c, d, x[9],  4, 0xd9d4d039); HH(d, a, b, c, x[12], 11, 0xe6db99e5);
    HH(c, d, a, b, x[15], 16, 0x1fa27cf8); HH(b, c, d, a, x[2], 23, 0xc4ac5665);

    II(a, b, c, d, x[0],  6, 0xf4292244); II(d, a, b, c, x[7], 10, 0x432aff97);
    II(c, d, a, b, x[14], 15, 0xab9423a7); II(b, c, d, a, x[5], 21, 0xfc93a039);
    II(a, b, c, d, x[12],  6, 0x655b59c3); II(d, a, b, c, x[3], 10, 0x8f0ccc92);
    II(c, d, a, b, x[10], 15, 0xffeff47d); II(b, c, d, a, x[1], 21, 0x85845dd1);
    II(a, b, c, d, x[6],  6, 0x6fa87e4f); II(d, a, b, c, x[13], 10, 0xfe2ce6e0);
    II(c, d, a, b, x[4], 15, 0xa3014314); II(b, c, d, a, x[11], 21, 0x4e0811a1);
    II(a, b, c, d, x[2],  6, 0xf7537e82); II(d, a, b, c, x[9], 10, 0xbd3af235);
    II(c, d, a, b, x[16], 15, 0x2ad7d2bb); II(b, c, d, a, x[7], 21, 0xeb86d391);

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
}

static int CalcMD5(const char* input, char* output) {
    MD5_CTX ctx;
    unsigned char digest[16];
    MD5_Init(&ctx);
    MD5_Update(&ctx, input, (unsigned long)strlen(input));
    MD5_Final(digest, &ctx);
    for (int i = 0; i < 16; i++)
        sprintf(output + i * 2, "%02x", digest[i]);
    output[32] = 0;
    return 0;
}


// ============================================================================
// HTTP GET
// ============================================================================
static int HttpGet(const char* url, char* response, int respSize) {
    URL_COMPONENTS uc = {0};
    uc.dwStructSize = sizeof(uc);
    char host[256] = {0}, pathBuf[2048] = {0};

    const char* p = strstr(url, "://");
    const char* hostStart = p ? p + 3 : url;
    const char* pathStart = strchr(hostStart, '/');
    if (pathStart) {
        strncpy(host, hostStart, (int)(pathStart - hostStart));
        strncpy(pathBuf, pathStart, sizeof(pathBuf) - 1);
    } else {
        strncpy(host, hostStart, sizeof(host) - 1);
        strcpy(pathBuf, "/");
    }

    uc.lpszHostName = host;
    uc.dwHostNameLength = (DWORD)strlen(host);
    uc.lpszUrlPath = pathBuf;
    uc.dwUrlPathLength = (DWORD)strlen(pathBuf);

    HINTERNET hInternet = InternetOpen("YeBaiAnticheat/1.0",
        INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) return -1;

    HINTERNET hConnect = InternetOpenUrl(hInternet, url, NULL, 0,
        INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_RELOAD |
        INTERNET_FLAG_NO_COOKIES, 0);
    if (!hConnect) {
        InternetCloseHandle(hInternet);
        return -1;
    }

    char buf[8192];
    DWORD bytesRead = 0;
    int total = 0;

    while (InternetReadFile(hConnect, buf, sizeof(buf) - 1, &bytesRead) && bytesRead > 0) {
        if (total + (int)bytesRead >= respSize - 1)
            bytesRead = (DWORD)(respSize - total - 1);
        memcpy(response + total, buf, bytesRead);
        total += (int)bytesRead;
        response[total] = 0;
        if (total >= respSize - 1) break;
    }

    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
    return 0;
}


// ============================================================================
// JSON 解析（极简）
// ============================================================================
static int ExtractJsonInt(const char* json, const char* key) {
    char pattern[128];
    sprintf(pattern, "\"%s\"", key);
    const char* p = strstr(json, pattern);
    if (!p) return -1;
    p = strchr(p, ':');
    if (!p) return -1;
    p++;
    while (*p && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) p++;
    return atoi(p);
}

static int ExtractJsonStr(const char* json, const char* key, char* out, int outSize) {
    char pattern[128];
    sprintf(pattern, "\"%s\"", key);
    const char* p = strstr(json, pattern);
    if (!p) return -1;
    p = strchr(p, ':');
    if (!p) return -1;
    p++;
    while (*p && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) p++;
    if (*p == 'n' && strncmp(p, "null", 4) == 0) { out[0] = 0; return 0; }
    if (*p == '"') p++;
    const char* end = p;
    while (*end && *end != '"') end++;
    int len = (int)(end - p);
    if (len >= outSize) len = outSize - 1;
    strncpy(out, p, len);
    out[len] = 0;
    return 0;
}

static void TsToString(time_t ts, char* out, int outSize) {
    if (ts == 0) { strcpy(out, "(无)"); return; }
    struct tm* t = localtime(&ts);
    strftime(out, outSize, "%Y-%m-%d %H:%M:%S", t);
}


// ============================================================================
// 卡密验证
// ============================================================================
static int VerifyKami(const char* kami) {
    char ts[32];
    sprintf(ts, "%ld", (long)time(NULL));

    char computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD nameLen = sizeof(computerName);
    GetComputerNameA(computerName, &nameLen);
    char markcode[256];
    sprintf(markcode, "%s-PC", computerName);

    // sign = md5("kami=" + kami + "&markcode=" + markcode + "&t=" + ts + "&" + APPKEY)
    char signSrc[512];
    sprintf(signSrc, "kami=%s&markcode=%s&t=%s&%s", kami, markcode, ts, CFG_APPKEY);
    char sign[64];
    CalcMD5(signSrc, sign);

    char url[4096];
    sprintf(url, "%s&kami=%s&markcode=%s&t=%s&sign=%s",
        CFG_LOGIN_URL, kami, markcode, ts, sign);

    AppendLog("[验证] 正在连接服务器...");

    char resp[8192] = {0};
    if (HttpGet(url, resp, sizeof(resp)) != 0) {
        AppendLog("[验证] 网络请求失败！请检查网络");
        return -1;
    }

    AppendLog("[验证] 响应: %.300s", resp);

    int code = ExtractJsonInt(resp, "code");
    if (code == -1) {
        AppendLog("[验证] 响应格式错误");
        return -1;
    }

    if (code == 200) {
        char vip[64] = {0};
        ExtractJsonStr(resp, "vip", vip, sizeof(vip));
        if (strlen(vip) > 0) {
            strcpy(g_VipTime, vip);
            time_t ts_val = (time_t)atoll(vip);
            char readable[64] = {0};
            TsToString(ts_val, readable, sizeof(readable));
            AppendLog("[验证] 到期时间: %s", readable);
        }
        AppendLog("[验证] 卡密正确，欢迎使用！");
        return 0;
    } else {
        char msg[256] = {0};
        ExtractJsonStr(resp, "msg", msg, sizeof(msg));
        if (strlen(msg) == 0) {
            const char* mp = strstr(resp, "\"msg\"");
            if (mp) {
                const char* pp = strchr(mp, '"');
                if (pp) {
                    pp = strchr(pp + 1, '"');
                    if (pp) {
                        pp++;
                        const char* end = pp;
                        while (*end && *end != '"') end++;
                        int l = (int)(end - pp);
                        if (l < 256) { strncpy(msg, pp, l); msg[l] = 0; }
                    }
                }
            }
        }
        AppendLog("[验证] 失败: %s (code=%d)", msg, code);
        return -1;
    }
}


// ============================================================================
// 公告获取
// ============================================================================
static int FetchNotice(char* out, int outSize) {
    char resp[4096] = {0};
    if (HttpGet(CFG_NOTICE_URL, resp, sizeof(resp)) != 0) {
        strcpy(out, "(公告获取失败)");
        return -1;
    }

    char tmp[2048] = {0};
    if (ExtractJsonStr(resp, "app_gg", tmp, sizeof(tmp)) == 0 && strlen(tmp) > 0) {
        strncat(out, tmp, outSize - 1);
    } else if (ExtractJsonStr(resp, "notice", tmp, sizeof(tmp)) == 0 && strlen(tmp) > 0) {
        strncat(out, tmp, outSize - 1);
    } else {
        const char* msgP = strstr(resp, "\"msg\"");
        if (msgP) {
            const char* p = strchr(msgP, '{');
            if (p) {
                if (ExtractJsonStr(p, "app_gg", tmp, sizeof(tmp)) == 0 && strlen(tmp) > 0) {
                    strncat(out, tmp, outSize - 1); return 0;
                }
                if (ExtractJsonStr(p, "notice", tmp, sizeof(tmp)) == 0 && strlen(tmp) > 0) {
                    strncat(out, tmp, outSize - 1); return 0;
                }
            }
        }
        strcpy(out, "(暂无公告)");
    }
    return 0;
}


// ============================================================================
// 文件操作
// ============================================================================
static int PathExistsA(const char* path) {
    DWORD a = GetFileAttributesA(path);
    return (a != INVALID_FILE_ATTRIBUTES);
}

static int DeleteFolderRecursiveA(const char* path) {
    char search[MAX_PATH];
    sprintf(search, "%s\\*", path);

    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(search, &fd);
    if (h == INVALID_HANDLE_VALUE) {
        RemoveDirectoryA(path);
        return 0;
    }

    do {
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0)
            continue;
        char full[MAX_PATH];
        sprintf(full, "%s\\%s", path, fd.cFileName);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            DeleteFolderRecursiveA(full);
        else
            DeleteFileA(full);
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    RemoveDirectoryA(path);
    return 0;
}


// ============================================================================
// 进程监控
// ============================================================================
static int IsProcessRunning(const char* name) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe = { sizeof(PROCESSENTRY32) };
    BOOL ok = Process32First(hSnap, &pe);
    int found = 0;
    while (ok) {
        if (stricmp(pe.szExeFile, name) == 0) { found = 1; break; }
        ok = Process32Next(hSnap, &pe);
    }
    CloseHandle(hSnap);
    return found;
}


// ============================================================================
// ACE 文件夹权限
// ============================================================================

static int LockACEFolder() {
    AppendLog("[权限] 锁定 ACE 文件夹...");

    if (!PathExistsA(ACE_FOLDER_PATH)) {
        AppendLog("[权限] ACE 文件夹不存在！");
        return -1;
    }

    // 用 SDDL 创建拒绝所有访问的安全描述符
    // D:(Deny 0x1fffff:(NP)WD) = 拒绝所有用户的所有权限，无继承
    const char* sddl = "D:(Deny 0x1fffff:(NP)WD)";

    PSECURITY_DESCRIPTOR pNewSD = NULL;
    ULONG sdSize = 0;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(
            sddl, SDDL_REVISION_1, &pNewSD, &sdSize)) {
        AppendLog("[权限] 创建 SDDL 失败 GLE=%d", GetLastError());
        return -1;
    }

    PACL pNewDacl = NULL;
    BOOL daclPresent = FALSE, daclDefault = FALSE;
    if (!GetSecurityDescriptorDacl(pNewSD, &daclPresent, &pNewDacl, &daclDefault)) {
        AppendLog("[权限] 获取 DACL 失败 GLE=%d", GetLastError());
        LocalFree(pNewSD);
        return -1;
    }

    DWORD dwRes = SetNamedSecurityInfoA((LPSTR)ACE_FOLDER_PATH, SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        NULL, NULL, pNewDacl, NULL);

    LocalFree(pNewSD);

    if (dwRes != ERROR_SUCCESS) {
        AppendLog("[权限] 设置安全信息失败 GLE=%d", dwRes);
        return -1;
    }

    AppendLog("[权限] ACE 文件夹已锁定！");
    return 0;
}

static int UnlockACEFolder() {
    AppendLog("[权限] 解锁 ACE 文件夹...");

    if (!PathExistsA(ACE_FOLDER_PATH)) {
        AppendLog("[权限] ACE 文件夹不存在，跳过");
        return 0;
    }

    // 移除 PROTECTED 标志以恢复继承
    DWORD dwRes = SetNamedSecurityInfoA((LPSTR)ACE_FOLDER_PATH, SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        NULL, NULL, NULL, NULL);

    if (dwRes != ERROR_SUCCESS) {
        AppendLog("[权限] 解锁失败 GLE=%d", dwRes);
        return -1;
    }

    AppendLog("[权限] 解锁成功！");
    return 0;
}
// ============================================================================
// 监控线程
// ============================================================================
static unsigned __stdcall MonitorThreadFunc(void* arg) {
    (void)arg;

    AppendLog("=== 开始过检测流程 ===");
    AppendLog("[1/6] 清理 ACE 文件夹...");
    DeleteFolderRecursiveA(ACE_FOLDER_PATH);
    AppendLog("[1/6] 清理完成");

    AppendLog("[2/6] 等待游戏启动(%s)...", GAME_NAME);

    DWORD startTick = GetTickCount();
    int gameFound = 0;
    while (g_Running) {
        if (IsProcessRunning(GAME_PROCESS_NAME)) {
            gameFound = 1;
            AppendLog("[2/6] 检测到游戏进程！");
            break;
        }
        if (GetTickCount() - startTick > 600000) {
            AppendLog("[2/6] 等待游戏超时");
            InterlockedExchange(&g_Running, 0);
            if (g_hBtnStart) {
                EnableWindow(g_hBtnStart, TRUE);
                SetWindowText(g_hBtnStart, "开启过检测");
            }
            _endthreadex(0);
            return 0;
        }
        Sleep(500);
    }

    if (!g_Running) {
        AppendLog("[2/6] 用户取消");
        _endthreadex(0);
        return 0;
    }

    AppendLog("[3/6] 等待 ACE 文件夹生成(5s)...");
    Sleep(5000);

    AppendLog("[4/6] 锁定 ACE 文件夹权限...");
    LockACEFolder();

    AppendLog("[5/6] 游戏运行中，监控退出...");
    while (g_Running) {
        if (!IsProcessRunning(GAME_PROCESS_NAME)) {
            AppendLog("[5/6] 检测到游戏退出！");
            break;
        }
        Sleep(1000);
    }

    AppendLog("[6/6] 解锁并清理 ACE...");
    UnlockACEFolder();
    DeleteFolderRecursiveA(ACE_FOLDER_PATH);

    AppendLog("=== 过检测完成！===");
    AppendLog("请手动关闭本程序或再次点击开启");

    InterlockedExchange(&g_Running, 0);

    if (g_hBtnStart) {
        EnableWindow(g_hBtnStart, TRUE);
        SetWindowText(g_hBtnStart, "开启过检测");
    }

    _endthreadex(0);
    return 0;
}

static void StartMonitor() {
    if (g_MonitorThread) {
        CloseHandle(g_MonitorThread);
        g_MonitorThread = NULL;
    }
    InterlockedExchange(&g_Running, 1);
    InterlockedExchange(&g_GameStarted, 0);
    ClearLog();
    AppendLog("=== 夜白过检测 1.0 ===");
    AppendLog("请启动游戏: %s", GAME_NAME);

    unsigned int tid = 0;
    g_MonitorThread = (HANDLE)_beginthreadex(NULL, 0, MonitorThreadFunc, NULL, 0, &tid);
    if (!g_MonitorThread) {
        AppendLog("[错误] 启动监控线程失败！");
        InterlockedExchange(&g_Running, 0);
    }
}

static void StopMonitor() {
    if (g_Running) {
        InterlockedExchange(&g_Running, 0);
        AppendLog("[用户] 正在停止...");
    }
}


// ============================================================================
// 登录窗口过程
// ============================================================================
static INT_PTR CALLBACK LoginDlgProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    (void)lParam;
    switch (msg) {
    case WM_INITDIALOG:
        g_hLoginWnd = hwnd;
        SendMessage(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)LoadIcon(NULL, IDI_APPLICATION));
        SendMessage(hwnd, WM_SETICON, ICON_BIG, (LPARAM)LoadIcon(NULL, IDI_APPLICATION));
        return 1;

    case WM_COMMAND:
        if (LOWORD(wParam) == 1002) {  // 登录按钮
            char kami[64] = {0};
            GetWindowText(GetDlgItem(hwnd, 1001), kami, sizeof(kami));
            if (strlen(kami) == 0) {
                MessageBox(hwnd, "请输入卡密", WINDOW_TITLE, MB_OK | MB_ICONWARNING);
                return 0;
            }
            strcpy(g_Kami, kami);
            EnableWindow(GetDlgItem(hwnd, 1002), FALSE);
            AppendLog("正在验证卡密...");

            int ok = VerifyKami(g_Kami);

            if (ok == 0) {
                g_LoginOk = 1;
                if (strlen(g_VipTime) > 0) {
                    time_t ts = (time_t)atoll(g_VipTime);
                    char readable[64] = {0};
                    TsToString(ts, readable, sizeof(readable));
                    char info[256];
                    sprintf(info, "验证成功！到期时间: %s", readable);
                    MessageBox(hwnd, info, WINDOW_TITLE, MB_OK | MB_ICONINFORMATION);
                } else {
                    MessageBox(hwnd, "验证成功！", WINDOW_TITLE, MB_OK | MB_ICONINFORMATION);
                }
                EndDialog(hwnd, IDOK);
            } else {
                MessageBox(hwnd, "卡密验证失败，请检查卡密是否正确", WINDOW_TITLE, MB_OK | MB_ICONERROR);
                EnableWindow(GetDlgItem(hwnd, 1002), TRUE);
            }
            return 0;
        }
        break;

    case WM_CLOSE:
        EndDialog(hwnd, IDCANCEL);
        return 1;
    }
    return 0;
}


// ============================================================================
// 主窗口过程
// ============================================================================
static LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static HFONT hFontTitle = NULL, hFontNormal = NULL;

    switch (msg) {
    case WM_CREATE: {
        hFontTitle = CreateFont(22, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Microsoft YaHei UI");
        hFontNormal = CreateFont(13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Microsoft YaHei UI");

        HWND hTitle = CreateWindow("static", "夜白过检测 1.0",
            WS_CHILD | WS_VISIBLE | SS_CENTER,
            80, 10, 260, 35, hwnd, NULL, NULL, NULL);
        SendMessage(hTitle, WM_SETFONT, (WPARAM)hFontTitle, TRUE);

        HWND hLblNotice = CreateWindow("static", "公告:",
            WS_CHILD | WS_VISIBLE, 15, 52, 40, 20, hwnd, NULL, NULL, NULL);
        SendMessage(hLblNotice, WM_SETFONT, (WPARAM)hFontNormal, TRUE);

        HWND hNotice = CreateWindow("edit", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_READONLY | ES_MULTILINE | ES_AUTOVSCROLL,
            15, 73, WIN_WIDTH - 30, 55, hwnd, (HMENU)3001, NULL, NULL);
        SendMessage(hNotice, WM_SETFONT, (WPARAM)hFontNormal, TRUE);

        g_hStatusText = CreateWindow("edit", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_READONLY | ES_MULTILINE |
            ES_AUTOVSCROLL | WS_VSCROLL,
            15, 135, WIN_WIDTH - 30, 108, hwnd, (HMENU)3002, NULL, NULL);
        SendMessage(g_hStatusText, WM_SETFONT, (WPARAM)hFontNormal, TRUE);

        g_hBtnStart = CreateWindow("button", "开启过检测",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            30, WIN_HEIGHT - 70, 150, 38, hwnd, (HMENU)2001, NULL, NULL);
        SendMessage(g_hBtnStart, WM_SETFONT, (WPARAM)hFontNormal, TRUE);

        g_hBtnLogout = CreateWindow("button", "退出程序",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            WIN_WIDTH - 180, WIN_HEIGHT - 70, 150, 38, hwnd, (HMENU)2002, NULL, NULL);
        SendMessage(g_hBtnLogout, WM_SETFONT, (WPARAM)hFontNormal, TRUE);

        g_hMainWnd = hwnd;

        char notice[2048] = {0};
        FetchNotice(notice, sizeof(notice));
        SetWindowText(hNotice, notice);

        ClearLog();
        AppendLog("=== 夜白过检测 1.0 ===");
        AppendLog("点击「开启过检测」后");
        AppendLog("再启动游戏，自动过检测");
        break;
    }

    case WM_COMMAND:
        if (LOWORD(wParam) == 2001) {
            if (!g_Running) {
                StartMonitor();
                SetWindowText(g_hBtnStart, "停止过检测");
            } else {
                StopMonitor();
                SetWindowText(g_hBtnStart, "开启过检测");
            }
        } else if (LOWORD(wParam) == 2002) {
            if (g_Running) StopMonitor();
            Sleep(300);
            DestroyWindow(hwnd);
        }
        break;

    case WM_CLOSE:
        if (g_Running) { StopMonitor(); Sleep(300); }
        DestroyWindow(hwnd);
        return 0;

    case WM_DESTROY:
        DeleteObject(hFontTitle);
        DeleteObject(hFontNormal);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

static ATOM RegisterMainWindowClass(HINSTANCE hInstance) {
    WNDCLASSEXA wcex = {0};
    wcex.cbSize = sizeof(WNDCLASSEX);
    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = MainWndProc;
    wcex.hInstance = hInstance;
    wcex.hCursor = LoadCursor(NULL, IDC_ARROW);
    wcex.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wcex.lpszClassName = "YeBaiAntiCheatMain";
    return RegisterClassExA(&wcex);
}


// ============================================================================
// 程序入口
// ============================================================================
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    (void)hPrevInstance; (void)lpCmdLine; (void)nCmdShow;

    InitializeCriticalSection(&g_csLog);

    INT_PTR loginRes = DialogBox(hInstance, MAKEINTRESOURCE(1000), NULL, LoginDlgProc);
    if (loginRes != IDOK) {
        DeleteCriticalSection(&g_csLog);
        return 0;
    }

    if (!RegisterMainWindowClass(hInstance)) {
        MessageBox(NULL, "窗口注册失败！", WINDOW_TITLE, MB_OK | MB_ICONERROR);
        DeleteCriticalSection(&g_csLog);
        return 1;
    }

    HWND hwnd = CreateWindow("YeBaiAntiCheatMain", WINDOW_TITLE,
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, WIN_WIDTH, WIN_HEIGHT,
        NULL, NULL, hInstance, NULL);
    if (!hwnd) {
        MessageBox(NULL, "窗口创建失败！", WINDOW_TITLE, MB_OK | MB_ICONERROR);
        DeleteCriticalSection(&g_csLog);
        return 1;
    }

    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    DeleteCriticalSection(&g_csLog);
    return (int)msg.wParam;
}

/*
 * YeBai AntiCheat 1.0
 * Compile: x86_64-w64-mingw32-g++ -mwindows -static -o YebaiAntiCheat.exe main.cpp -lwininet -ladvapi32 -lcomctl32
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

#define CFG_APPKEY  "00INaa4ja01VtNiy"
#define WIN_TITLE   L"YeBai AntiCheat 1.0"
#define WIN_WIDTH   420
#define WIN_HEIGHT  355

#define ACE_FOLDER_PATH    L"C:\\Program Files\\AntiCheatExpert"
#define GAME_PROCESS_NAME  L"NRC-Win64-Shipping.exe"

static HWND g_hLoginWnd   = NULL;
static HWND g_hMainWnd   = NULL;
static HWND g_hStatusText = NULL;
static HWND g_hBtnStart   = NULL;
static HWND g_hBtnLogout = NULL;

static char g_Kami[64]   = {0};
static char g_VipTime[64] = {0};
static int  g_LoginOk    = 0;

static volatile LONG g_Running = 0;
static HANDLE g_MonitorThread = NULL;

static WCHAR g_LogBuf[8192] = {0};
static CRITICAL_SECTION g_csLog;

// ============================================================================
// 日志实现
// ============================================================================
static void AppendLogW(const WCHAR* fmt, ...) {
    WCHAR buf[512];
    va_list ap;
    va_start(ap, fmt);
    vswprintf(buf, 512, fmt, ap);
    va_end(ap);
    EnterCriticalSection(&g_csLog);
    int len = (int)wcslen(g_LogBuf);
    if (len > 6000)
        memmove(g_LogBuf, g_LogBuf + 2000, sizeof(WCHAR) * 6000);
    wcscat(g_LogBuf, buf);
    wcscat(g_LogBuf, L"\r\n");
    if (g_hStatusText) {
        SetWindowTextW(g_hStatusText, g_LogBuf);
        SendMessageW(g_hStatusText, EM_SETSEL, -1, -1);
        SendMessageW(g_hStatusText, EM_SCROLLCARET, 0, 0);
    }
    LeaveCriticalSection(&g_csLog);
}
static void ClearLogW() {
    EnterCriticalSection(&g_csLog);
    g_LogBuf[0] = 0;
    if (g_hStatusText) SetWindowTextW(g_hStatusText, L"");
    LeaveCriticalSection(&g_csLog);
}

// ============================================================================
// MD5
// ============================================================================
typedef struct { unsigned long s[4]; unsigned long c[2]; unsigned char b[64]; } MD5_CTX;
static void MD5_Init(MD5_CTX* c) { c->s[0]=0x67452301; c->s[1]=0xefcdab89; c->s[2]=0x98badcfe; c->s[3]=0x10325476; c->c[0]=c->c[1]=0; }
static void MD5_Update(MD5_CTX* c, const void* d, unsigned long len);
static void MD5_Final(unsigned char* o, MD5_CTX* c);
static void MD5_Tr(unsigned long s[4], const unsigned char b[64]);

static const unsigned char PADDING[64] = {0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

static void MD5_Update(MD5_CTX* c, const void* data, unsigned long len) {
    unsigned long i,index,partLen;
    const unsigned char* input=(const unsigned char*)data;
    index=(unsigned long)((c->c[0]>>3)&0x3F);
    if((c->c[0]+=((unsigned long)len<<3))<((unsigned long)len<<3)) c->c[1]++;
    c->c[1]+=((unsigned long)len>>29);
    partLen=64-index;
    if(len>=partLen){memcpy(&c->b[index],input,partLen);MD5_Tr(c->s,c->b);for(i=partLen;i+63<len;i+=64)MD5_Tr(c->s,&input[i]);index=0;}else i=0;
    memcpy(&c->b[index],&input[i],len-i);
}
static void MD5_Final(unsigned char o[16], MD5_CTX* c) {
    unsigned char bits[8];
    unsigned long index,padLen;
    *(unsigned long*)bits=c->c[0];*(unsigned long*)(bits+4)=c->c[1];
    index=(unsigned long)((c->c[0]>>3)&0x3f);padLen=(index<56)?(56-index):(120-index);
    MD5_Update(c,PADDING,padLen);MD5_Update(c,bits,8);memcpy(o,c->s,16);
}
static void MD5_Tr(unsigned long s[4], const unsigned char b[64]) {
    unsigned long a=s[0],bb=s[1],cc=s[2],d=s[3],x[16];
    int i;
    for(i=0;i<16;i++) x[i]=((unsigned long)b[i*4])|((unsigned long)b[i*4+1]<<8)|((unsigned long)b[i*4+2]<<16)|((unsigned long)b[i*4+3]<<24);
    #define FF(a,b,c,d,x,s,ac) a+=((c)^((b)&((d)^(c))))+x+(unsigned long)(ac);a=((a)<<(s))|((a)>>(32-(s)));a+=b;
    #define GG(a,b,c,d,x,s,ac) a+=((d)^((c)&((b)^(d))))+x+(unsigned long)(ac);a=((a)<<(s))|((a)>>(32-(s)));a+=b;
    #define HH(a,b,c,d,x,s,ac) a+=((b)^(c)^(d))+x+(unsigned long)(ac);a=((a)<<(s))|((a)>>(32-(s)));a+=b;
    #define II(a,b,c,d,x,s,ac) a+=((c)^((b)|(~(d))))+x+(unsigned long)(ac);a=((a)<<(s))|((a)>>(32-(s)));a+=b;
    FF(a,bb,cc,d,x[0],7,0xd76aa478);FF(d,a,bb,cc,x[1],12,0xe8c7b756);FF(cc,d,a,bb,x[2],17,0x242070db);FF(bb,cc,d,a,x[3],22,0xc1bdceee);
    FF(a,bb,cc,d,x[4],7,0xf57c0faf);FF(d,a,bb,cc,x[5],12,0x4787c62a);FF(cc,d,a,bb,x[6],17,0xa8304613);FF(bb,cc,d,a,x[7],22,0xfd469501);
    FF(a,bb,cc,d,x[8],7,0x698098d8);FF(d,a,bb,cc,x[9],12,0x8b44f7af);FF(cc,d,a,bb,x[10],17,0xffff5bb1);FF(bb,cc,d,a,x[11],22,0x895cd7be);
    FF(a,bb,cc,d,x[12],7,0x6b901122);FF(d,a,bb,cc,x[13],12,0xfd987193);FF(cc,d,a,bb,x[14],17,0xa679438e);FF(bb,cc,d,a,x[15],22,0x49b40821);
    GG(a,bb,cc,d,x[1],5,0xf61e2562);GG(d,a,bb,cc,x[6],9,0xc040b340);GG(cc,d,a,bb,x[11],14,0x265e5a51);GG(bb,cc,d,a,x[0],20,0xe9b6c7aa);
    GG(a,bb,cc,d,x[5],5,0xd62f105d);GG(d,a,bb,cc,x[10],9,0x2441453);GG(cc,d,a,bb,x[15],14,0xd8a1e681);GG(bb,cc,d,a,x[4],20,0xe7d3fbc8);
    GG(a,bb,cc,d,x[9],5,0x21e1cde6);GG(d,a,bb,cc,x[14],9,0xc33707d6);GG(cc,d,a,bb,x[3],14,0xf4d50d87);GG(bb,cc,d,a,x[8],20,0x455a14ed);
    GG(a,bb,cc,d,x[13],5,0xa9e3e905);GG(d,a,bb,cc,x[2],9,0xfcefa3f8);GG(cc,d,a,bb,x[7],14,0x676f02d9);GG(bb,cc,d,a,x[12],20,0x8d2a4c8a);
    HH(a,bb,cc,d,x[5],4,0xfffa3942);HH(d,a,bb,cc,x[8],11,0x8771f681);HH(cc,d,a,bb,x[11],16,0x6d9d6122);HH(bb,cc,d,a,x[14],23,0xfde5380c);
    HH(a,bb,cc,d,x[1],4,0xa4beea44);HH(d,a,bb,cc,x[4],11,0x4bdecfa9);HH(cc,d,a,bb,x[7],16,0xf6bb4b60);HH(bb,cc,d,a,x[10],23,0xbebfbc70);
    HH(a,bb,cc,d,x[13],4,0x289b7ec6);HH(d,a,bb,cc,x[0],11,0xeaa127fa);HH(cc,d,a,bb,x[3],16,0xd4ef3085);HH(bb,cc,d,a,x[6],23,0x0481d05);
    HH(a,bb,cc,d,x[9],4,0xd9d4d039);HH(d,a,bb,cc,x[12],11,0xe6db99e5);HH(cc,d,a,bb,x[15],16,0x1fa27cf8);HH(bb,cc,d,a,x[2],23,0xc4ac5665);
    II(a,bb,cc,d,x[0],6,0xf4292244);II(d,a,bb,cc,x[7],10,0x432aff97);II(cc,d,a,bb,x[14],15,0xab9423a7);II(bb,cc,d,a,x[5],21,0xfc93a039);
    II(a,bb,cc,d,x[12],6,0x655b59c3);II(d,a,bb,cc,x[3],10,0x8f0ccc92);II(cc,d,a,bb,x[10],15,0xffeff47d);II(bb,cc,d,a,x[1],21,0x85845dd1);
    II(a,bb,cc,d,x[6],6,0x6fa87e4f);II(d,a,bb,cc,x[13],10,0xfe2ce6e0);II(cc,d,a,bb,x[4],15,0xa3014314);II(bb,cc,d,a,x[11],21,0x4e0811a1);
    II(a,bb,cc,d,x[2],6,0xf7537e82);II(d,a,bb,cc,x[9],10,0xbd3af235);II(cc,d,a,bb,x[16],15,0x2ad7d2bb);II(bb,cc,d,a,x[7],21,0xeb86d391);
    s[0]+=a;s[1]+=bb;s[2]+=cc;s[3]+=d;
}

static int CalcMD5(const char* input, char* output) {
    MD5_CTX ctx; unsigned char d[16];
    MD5_Init(&ctx);
    MD5_Update(&ctx,input,(unsigned long)strlen(input));
    MD5_Final(d,&ctx);
    for(int i=0;i<16;i++) sprintf(output+i*2,"%02x",d[i]);
    output[32]=0; return 0;
}

// ============================================================================
// HTTP GET
// ============================================================================
static int HttpGetA(const char* url, char* response, int respSize) {
    URL_COMPONENTSA uc = {0};
    uc.dwStructSize = sizeof(uc);
    char host[256]={0}, pathBuf[2048]={0};
    const char* p = strstr(url,"://");
    const char* hs = p ? p+3 : url;
    const char* ps = strchr(hs,'/');
    if(ps){ strncpy(host,hs,(int)(ps-hs)); strncpy(pathBuf,ps,sizeof(pathBuf)-1); }
    else { strncpy(host,hs,sizeof(host)-1); strcpy(pathBuf,"/"); }
    uc.lpszHostName=host; uc.dwHostNameLength=(DWORD)strlen(host);
    uc.lpszUrlPath=pathBuf; uc.dwUrlPathLength=(DWORD)strlen(pathBuf);

    HINTERNET hi = InternetOpenA("YeBaiAntiCheat/1.0",INTERNET_OPEN_TYPE_DIRECT,NULL,NULL,0);
    if(!hi) return -1;
    HINTERNET hc = InternetOpenUrlA(hi,url,NULL,0,INTERNET_FLAG_NO_CACHE_WRITE|INTERNET_FLAG_RELOAD|INTERNET_FLAG_NO_COOKIES,0);
    if(!hc){ InternetCloseHandle(hi); return -1; }
    char buf[8192]; DWORD br=0; int total=0;
    while(InternetReadFile(hc,buf,sizeof(buf)-1,&br)&&br>0){
        if(total+(int)br>=respSize-1) br=(DWORD)(respSize-total-1);
        memcpy(response+total,buf,br); total+=(int)br; response[total]=0;
        if(total>=respSize-1) break;
    }
    InternetCloseHandle(hc); InternetCloseHandle(hi); return 0;
}

// ============================================================================
// JSON 解析
// ============================================================================
static int ExtractJsonIntA(const char* json, const char* key) {
    char pat[128]; sprintf(pat,"\"%s\"",key);
    const char* p=strstr(json,pat); if(!p) return -1;
    p=strchr(p,':'); if(!p) return -1; p++;
    while(*p&&(*p==' '||*p=='\t'||*p=='\n'||*p=='\r')) p++;
    return atoi(p);
}
static int ExtractJsonStrA(const char* json, const char* key, char* out, int outSize) {
    char pat[128]; sprintf(pat,"\"%s\"",key);
    const char* p=strstr(json,pat); if(!p) return -1;
    p=strchr(p,':'); if(!p) return -1; p++;
    while(*p&&(*p==' '||*p=='\t'||*p=='\n'||*p=='\r')) p++;
    if(*p=='"') p++;
    const char* end=p; while(*end&&*end!='"') end++;
    int len=(int)(end-p); if(len>=outSize) len=outSize-1;
    strncpy(out,p,len); out[len]=0; return 0;
}

static void TsToString(time_t ts, char* out, int outSize) {
    if(ts==0){strcpy(out,"(none)");return;}
    struct tm* t=localtime(&ts); strftime(out,outSize,"%Y-%m-%d %H:%M:%S",t);
}

// ============================================================================
// 卡密验证
// ============================================================================
static int VerifyKami(const char* kami) {
    char ts[32]; sprintf(ts,"%ld",(long)time(NULL));
    char computerName[MAX_COMPUTERNAME_LENGTH+1]; DWORD nameLen=sizeof(computerName);
    GetComputerNameA(computerName,&nameLen);
    char markcode[256]; sprintf(markcode,"%s-PC",computerName);
    char signSrc[512];
    sprintf(signSrc,"kami=%s&markcode=%s&t=%s&%s",kami,markcode,ts,CFG_APPKEY);
    char sign[64]; CalcMD5(signSrc,sign);
    char url[4096];
    sprintf(url,"http://wy.llua.cn/api/?id=kmlogon&app=61572&kami=%s&markcode=%s&t=%s&sign=%s",kami,markcode,ts,sign);

    AppendLogW(L"[*] Connecting to server...");
    char resp[8192]={0};
    if(HttpGetA(url,resp,sizeof(resp))!=0){ AppendLogW(L"[!] Network error"); return -1; }
    AppendLogW(L"[*] Response: %.200s", resp);

    int code = ExtractJsonIntA(resp,"code");
    if(code==-1){ AppendLogW(L"[!] Bad response"); return -1; }
    if(code==200){
        char vip[64]={0}; ExtractJsonStrA(resp,"vip",vip,sizeof(vip));
        if(strlen(vip)>0){
            strcpy(g_VipTime,vip);
            time_t t=atoll(vip); char rd[64]; TsToString(t,rd,sizeof(rd));
            AppendLogW(L"[*] Expiry: %S", rd);
        }
        AppendLogW(L"[*] Verified OK!");
        return 0;
    } else {
        char msg[256]={0}; ExtractJsonStrA(resp,"msg",msg,sizeof(msg));
        if(strlen(msg)==0){
            const char* mp=strstr(resp,"\"msg\""); if(mp){
                const char* pp=strchr(mp,'"'); if(pp){ pp=strchr(pp+1,'"'); if(pp){
                    pp++; const char* e=pp; while(*e&&*e!='"') e++;
                    int l=(int)(e-pp); if(l<256){strncpy(msg,pp,l);msg[l]=0;}
                }}}
        }
        AppendLogW(L"[!] Failed: %S (code=%d)", msg, code);
        return -1;
    }
}

// ============================================================================
// 公告
// ============================================================================
static int FetchNoticeA(char* out, int outSize) {
    char resp[4096]={0};
    if(HttpGetA("http://wy.llua.cn/api/?id=notice&app=61572",resp,sizeof(resp))!=0){
        strcpy(out,"(fetch failed)"); return -1;
    }
    char tmp[2048]={0};
    if(ExtractJsonStrA(resp,"app_gg",tmp,sizeof(tmp))==0&&strlen(tmp)>0)
        strncat(out,tmp,outSize-1);
    else if(ExtractJsonStrA(resp,"notice",tmp,sizeof(tmp))==0&&strlen(tmp)>0)
        strncat(out,tmp,outSize-1);
    else {
        const char* mp=strstr(resp,"\"msg\""); if(mp){
            const char* pp=strchr(mp,'{'); if(pp){
                if(ExtractJsonStrA(pp,"app_gg",tmp,sizeof(tmp))==0&&strlen(tmp)>0){strncat(out,tmp,outSize-1);return 0;}
                if(ExtractJsonStrA(pp,"notice",tmp,sizeof(tmp))==0&&strlen(tmp)>0){strncat(out,tmp,outSize-1);return 0;}
            }}
        strcpy(out,"(no notice)");
    }
    return 0;
}

// ============================================================================
// 文件操作
// ============================================================================
static int PathExistsW(const WCHAR* p){ return GetFileAttributesW(p)!=INVALID_FILE_ATTRIBUTES; }

static int DeleteFolderRecursiveW(const WCHAR* p) {
    WCHAR search[MAX_PATH];
    wsprintfW(search,L"%s\\*",p);
    WIN32_FIND_DATAW fd;
    HANDLE h=FindFirstFileW(search,&fd);
    if(h==INVALID_HANDLE_VALUE){ RemoveDirectoryW(p); return 0; }
    do{
        if(wcscmp(fd.cFileName,L".")==0||wcscmp(fd.cFileName,L"..")==0) continue;
        WCHAR full[MAX_PATH];
        wsprintfW(full,L"%s\\%s",p,fd.cFileName);
        if(fd.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY) DeleteFolderRecursiveW(full);
        else DeleteFileW(full);
    }while(FindNextFileW(h,&fd));
    FindClose(h); RemoveDirectoryW(p); return 0;
}

// ============================================================================
// 进程
// ============================================================================
static int IsProcessRunning(const WCHAR* name) {
    HANDLE h=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(h==INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe={sizeof(PROCESSENTRY32W)}; BOOL ok=Process32FirstW(h,&pe);
    int found=0; while(ok){ if(wcsicmp(pe.szExeFile,name)==0){found=1;break;} ok=Process32NextW(h,&pe); }
    CloseHandle(h); return found;
}

// ============================================================================
// 权限
// ============================================================================
static int LockACEFolder() {
    AppendLogW(L"[*] Locking ACE folder...");
    if(!PathExistsW(ACE_FOLDER_PATH)){ AppendLogW(L"[!] ACE folder not found!"); return -1; }
    const WCHAR* sddl = L"D:(Deny 0x1fffff:(NP)WD)";
    PSECURITY_DESCRIPTOR pSD=NULL; ULONG sdSize=0;
    if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl,SDDL_REVISION_1,&pSD,&sdSize)){
        AppendLogW(L"[!] SDDL failed GLE=%d",GetLastError()); return -1;
    }
    PACL pDacl=NULL; BOOL dp=FALSE,dd=FALSE;
    if(!GetSecurityDescriptorDacl(pSD,&dp,&pDacl,&dd)){
        AppendLogW(L"[!] GetDacl failed GLE=%d",GetLastError()); LocalFree(pSD); return -1;
    }
    DWORD r=SetNamedSecurityInfoW((LPWSTR)ACE_FOLDER_PATH,SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION,
        NULL,NULL,pDacl,NULL);
    LocalFree(pSD);
    if(r!=ERROR_SUCCESS){ AppendLogW(L"[!] SetSecurity failed GLE=%d",r); return -1; }
    AppendLogW(L"[*] ACE folder locked!");
    return 0;
}

static int UnlockACEFolder() {
    AppendLogW(L"[*] Unlocking ACE folder...");
    if(!PathExistsW(ACE_FOLDER_PATH)){ AppendLogW(L"[*] ACE folder gone, skip"); return 0; }
    DWORD r=SetNamedSecurityInfoW((LPWSTR)ACE_FOLDER_PATH,SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION, NULL,NULL,NULL,NULL);
    if(r!=ERROR_SUCCESS){ AppendLogW(L"[!] Unlock failed GLE=%d",r); return -1; }
    AppendLogW(L"[*] ACE folder unlocked!");
    return 0;
}

// ============================================================================
// 监控线程
// ============================================================================
static unsigned __stdcall MonitorThreadFunc(void* arg){
    (void)arg;
    AppendLogW(L"=== Anti-cheat starting ===");
    AppendLogW(L"[1/6] Cleaning ACE folder...");
    DeleteFolderRecursiveW(ACE_FOLDER_PATH);
    AppendLogW(L"[1/6] Done");

    AppendLogW(L"[2/6] Waiting for game to start...");
    DWORD start=GetTickCount();
    while(g_Running){
        if(IsProcessRunning(GAME_PROCESS_NAME)){ AppendLogW(L"[2/6] Game detected!"); break; }
        if(GetTickCount()-start>600000){ AppendLogW(L"[2/6] Timeout"); InterlockedExchange(&g_Running,0);
            if(g_hBtnStart){ EnableWindow(g_hBtnStart,TRUE); SetWindowTextW(g_hBtnStart,L"Start AntiCheat"); }
            _endthreadex(0); return 0; }
        Sleep(500);
    }
    if(!g_Running){ AppendLogW(L"[2/6] Cancelled"); _endthreadex(0); return 0; }

    AppendLogW(L"[3/6] Waiting ACE folder (5s)..."); Sleep(5000);
    AppendLogW(L"[4/6] Locking ACE folder..."); LockACEFolder();
    AppendLogW(L"[5/6] Game running, monitoring exit...");
    while(g_Running){ if(!IsProcessRunning(GAME_PROCESS_NAME)){ AppendLogW(L"[5/6] Game exited!"); break; } Sleep(1000); }

    AppendLogW(L"[6/6] Unlocking and cleaning...");
    UnlockACEFolder(); DeleteFolderRecursiveW(ACE_FOLDER_PATH);
    AppendLogW(L"=== Anti-cheat done! ===");

    InterlockedExchange(&g_Running,0);
    if(g_hBtnStart){ EnableWindow(g_hBtnStart,TRUE); SetWindowTextW(g_hBtnStart,L"Start AntiCheat"); }
    _endthreadex(0); return 0;
}

static void StartMonitor() {
    if(g_MonitorThread){ CloseHandle(g_MonitorThread); g_MonitorThread=NULL; }
    InterlockedExchange(&g_Running,1);
    ClearLogW();
    AppendLogW(L"=== YeBai AntiCheat 1.0 ===");
    AppendLogW(L"Start the game now...");
    unsigned int tid=0;
    g_MonitorThread=(HANDLE)_beginthreadex(NULL,0,MonitorThreadFunc,NULL,0,&tid);
    if(!g_MonitorThread){ AppendLogW(L"[!] Thread failed!"); InterlockedExchange(&g_Running,0); }
}

static void StopMonitor() {
    if(g_Running){ InterlockedExchange(&g_Running,0); AppendLogW(L"[*] Stopping..."); }
}

// ============================================================================
// 登录窗口
// ============================================================================
static INT_PTR CALLBACK LoginWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam){
    (void)lParam;
    static HWND hEditKami=NULL, hBtnLogin=NULL;
    switch(msg){
    case WM_CREATE: {
        HFONT hF=CreateFontW(14,0,0,0,FW_NORMAL,0,0,0,DEFAULT_CHARSET,0,0,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Microsoft YaHei UI");

        CreateWindowW(L"static",L"Card Verification",
            WS_CHILD|WS_VISIBLE|SS_CENTER, 100,15,120,25, hwnd,NULL,NULL,NULL);
        CreateWindowW(L"static",L"Card Key:",
            WS_CHILD|WS_VISIBLE, 20,55,80,20, hwnd,NULL,NULL,NULL);
        hEditKami = CreateWindowW(L"edit",L"",
            WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL, 20,77,280,24, hwnd,(HMENU)1001,NULL,NULL);
        hBtnLogin = CreateWindowW(L"button",L"Login",
            WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON|WS_TABSTOP, 120,115,80,30, hwnd,(HMENU)1002,NULL,NULL);
        CreateWindowW(L"static",L"YeBai AntiCheat 1.0",
            WS_CHILD|WS_VISIBLE|SS_CENTER, 0,160,320,16, hwnd,NULL,NULL,NULL);

        SendMessageW(GetDlgItem(hwnd,1001),WM_SETFONT,(WPARAM)hF,TRUE);
        SendMessageW(GetDlgItem(hwnd,1002),WM_SETFONT,(WPARAM)hF,TRUE);
        SendMessageW(GetDlgItem(hwnd,1003),WM_SETFONT,(WPARAM)hF,TRUE);
        SendMessageW(hBtnLogin,WM_SETFONT,(WPARAM)hF,TRUE);
        SendMessageW(hEditKami,WM_SETFONT,(WPARAM)hF,TRUE);

        SetFocus(hEditKami);
        g_hLoginWnd=hwnd;
        return 0;
    }
    case WM_COMMAND:
        if(LOWORD(wParam)==1002){
            WCHAR kamiW[64]={0};
            GetWindowTextW(GetDlgItem(hwnd,1001),kamiW,63);
            if(wcslen(kamiW)==0){
                MessageBoxW(hwnd,L"Please enter card key",L"YeBai AntiCheat",MB_OK|MB_ICONWARNING);
                return 0;
            }
            char kamiA[64]={0};
            WideCharToMultiByte(CP_ACP,0,kamiW,-1,kamiA,sizeof(kamiA),NULL,NULL);
            strcpy(g_Kami,kamiA);
            EnableWindow(hBtnLogin,FALSE);

            int ok=VerifyKami(g_Kami);
            if(ok==0){
                g_LoginOk=1;
                if(strlen(g_VipTime)>0){
                    time_t t=atoll(g_VipTime); char rd[64]; TsToString(t,rd,sizeof(rd));
                    WCHAR infoW[256]; wsprintfW(infoW,L"Verified! Expiry: %S",rd);
                    MessageBoxW(hwnd,infoW,L"YeBai AntiCheat",MB_OK|MB_ICONINFORMATION);
                } else {
                    MessageBoxW(hwnd,L"Verified OK!",L"YeBai AntiCheat",MB_OK|MB_ICONINFORMATION);
                }
                EndDialog(hwnd,IDOK);
            } else {
                MessageBoxW(hwnd,L"Card verification failed",L"YeBai AntiCheat",MB_OK|MB_ICONERROR);
                EnableWindow(hBtnLogin,TRUE);
            }
            return 0;
        }
        break;
    case WM_CLOSE: EndDialog(hwnd,IDCANCEL); return 1;
    }
    return 0;
}

// ============================================================================
// 主窗口
// ============================================================================
static LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam){
    static HFONT hFTitle=0,hFNorm=0;
    switch(msg){
    case WM_CREATE:{
        hFTitle=CreateFontW(22,0,0,0,FW_BOLD,0,0,0,DEFAULT_CHARSET,0,0,CLEARTYPE_QUALITY,DEFAULT_PITCH|FF_DONTCARE,L"Microsoft YaHei UI");
        hFNorm=CreateFontW(13,0,0,0,FW_NORMAL,0,0,0,DEFAULT_CHARSET,0,0,CLEARTYPE_QUALITY,DEFAULT_PITCH|FF_DONTCARE,L"Microsoft YaHei UI");

        CreateWindowW(L"static",L"YeBai AntiCheat 1.0",
            WS_CHILD|WS_VISIBLE|SS_CENTER, 70,10,280,35, hwnd,NULL,NULL,NULL);
        CreateWindowW(L"static",L"Notice:",
            WS_CHILD|WS_VISIBLE, 15,52,50,20, hwnd,NULL,NULL,NULL);

        HWND hNotice=CreateWindowW(L"edit",L"",
            WS_CHILD|WS_VISIBLE|WS_BORDER|ES_READONLY|ES_MULTILINE|ES_AUTOVSCROLL,
            15,73,WIN_WIDTH-30,55, hwnd,(HMENU)3001,NULL,NULL);

        g_hStatusText=CreateWindowW(L"edit",L"",
            WS_CHILD|WS_VISIBLE|WS_BORDER|ES_READONLY|ES_MULTILINE|ES_AUTOVSCROLL|WS_VSCROLL,
            15,135,WIN_WIDTH-30,108, hwnd,(HMENU)3002,NULL,NULL);

        g_hBtnStart=CreateWindowW(L"button",L"Start AntiCheat",
            WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON, 30,WIN_HEIGHT-70,150,38, hwnd,(HMENU)2001,NULL,NULL);
        g_hBtnLogout=CreateWindowW(L"button",L"Exit",
            WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON, WIN_WIDTH-180,WIN_HEIGHT-70,150,38, hwnd,(HMENU)2002,NULL,NULL);

        SendMessageW(GetDlgItem(hwnd,3001),WM_SETFONT,(WPARAM)hFTitle,TRUE);
        SendMessageW(GetDlgItem(hwnd,3002),WM_SETFONT,(WPARAM)hFNorm,TRUE);
        SendMessageW(hNotice,WM_SETFONT,(WPARAM)hFNorm,TRUE);
        SendMessageW(g_hStatusText,WM_SETFONT,(WPARAM)hFNorm,TRUE);
        SendMessageW(g_hBtnStart,WM_SETFONT,(WPARAM)hFNorm,TRUE);
        SendMessageW(g_hBtnLogout,WM_SETFONT,(WPARAM)hFNorm,TRUE);

        g_hMainWnd=hwnd;

        char notice[2048]={0}; FetchNoticeA(notice,sizeof(notice));
        WCHAR noticeW[4096]={0};
        MultiByteToWideChar(CP_UTF8,0,notice,-1,noticeW,4095);
        SetWindowTextW(hNotice,noticeW);

        ClearLogW();
        AppendLogW(L"=== YeBai AntiCheat 1.0 ===");
        AppendLogW(L"Click [Start AntiCheat]");
        AppendLogW(L"Then launch the game");
        break;
    }
    case WM_COMMAND:
        if(LOWORD(wParam)==2001){
            if(!g_Running){
                StartMonitor();
                SetWindowTextW(g_hBtnStart,L"Stop AntiCheat");
            } else {
                StopMonitor();
                SetWindowTextW(g_hBtnStart,L"Start AntiCheat");
            }
        } else if(LOWORD(wParam)==2002){
            if(g_Running) StopMonitor();
            Sleep(300);
            DestroyWindow(hwnd);
        }
        break;
    case WM_CLOSE:
        if(g_Running){StopMonitor();Sleep(300);}
        DestroyWindow(hwnd); return 0;
    case WM_DESTROY:
        DeleteObject(hFTitle); DeleteObject(hFNorm);
        PostQuitMessage(0); return 0;
    }
    return DefWindowProc(hwnd,msg,wParam,lParam);
}

static ATOM RegisterMainWindowClass(HINSTANCE hInst){
    WNDCLASSEXW wcex={0};
    wcex.cbSize=sizeof(WNDCLASSEX);
    wcex.style=CS_HREDRAW|CS_VREDRAW;
    wcex.lpfnWndProc=MainWndProc;
    wcex.hInstance=hInst;
    wcex.hCursor=LoadCursor(NULL,IDC_ARROW);
    wcex.hbrBackground=(HBRUSH)(COLOR_BTNFACE+1);
    wcex.lpszClassName=L"YeBaiAntiCheatMain";
    return RegisterClassExW(&wcex);
}

// ============================================================================
// WinMain
// ============================================================================
int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE hPrev, LPWSTR cmdLine, int nShow){
    (void)hPrev; (void)cmdLine; (void)nShow;
    INT_PTR loginRes = DialogBoxW(hInst, NULL, NULL, LoginWndProc);
    if(loginRes != IDOK){ DeleteCriticalSection(&g_csLog); return 0; }

    if(!RegisterMainWindowClass(hInst)){
        MessageBoxW(NULL,L"Window class failed!",L"YeBai AntiCheat",MB_OK|MB_ICONERROR);
        DeleteCriticalSection(&g_csLog); return 1;
    }

    int scrW=GetSystemMetrics(SM_CXSCREEN);
    int scrH=GetSystemMetrics(SM_CYSCREEN);
    HWND hMain=CreateWindowW(L"YeBaiAntiCheatMain", L"YeBai AntiCheat 1.0",
        WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX,
        (scrW-WIN_WIDTH)/2, (scrH-WIN_HEIGHT)/2,
        WIN_WIDTH, WIN_HEIGHT, NULL, NULL, hInst, NULL);
    if(!hMain){
        MessageBoxW(NULL,L"Window create failed!",L"YeBai AntiCheat",MB_OK|MB_ICONERROR);
        DeleteCriticalSection(&g_csLog); return 1;
    }
    ShowWindow(hMain,SW_SHOW); UpdateWindow(hMain);

    MSG m;
    while(GetMessage(&m,NULL,0,0)){ TranslateMessage(&m); DispatchMessage(&m); }
    DeleteCriticalSection(&g_csLog);
    return (int)m.wParam;
}

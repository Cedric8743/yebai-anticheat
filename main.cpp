/*
 * YeBai AntiCheat 1.0 - Debug Build
 * Compile: x86_64-w64-mingw32-g++ -mwindows -municode -static -o YebaiAntiCheat.exe main.cpp -lwininet -ladvapi32 -lcomctl32
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

// ====== 日志文件 ======
static FILE* g_logFile = NULL;
static void Log(const char* fmt, ...) {
    if (!g_logFile) g_logFile = fopen("yebai_log.txt", "a");
    if (g_logFile) {
        SYSTEMTIME st; GetLocalTime(&st);
        fprintf(g_logFile, "[%02d:%02d:%02d] ", st.wHour, st.wMinute, st.wSecond);
        va_list ap; va_start(ap, fmt); vfprintf(g_logFile, fmt, ap); va_end(ap);
        fprintf(g_logFile, "\n"); fflush(g_logFile);
    }
}
static void LogW(const WCHAR* fmt, ...) {
    if (!g_logFile) g_logFile = fopen("yebai_log.txt", "a");
    if (g_logFile) {
        SYSTEMTIME st; GetLocalTime(&st);
        fwprintf(g_logFile, L"[%02d:%02d:%02d] ", st.wHour, st.wMinute, st.wSecond);
        va_list ap; va_start(ap, fmt); vfwprintf(g_logFile, fmt, ap); va_end(ap);
        fwprintf(g_logFile, L"\n"); fflush(g_logFile);
    }
}

// ====== 配置 ======
#define CFG_APPKEY     "00INaa4ja01VtNiy"
#define WIN_TITLE_W    L"YeBai AntiCheat 1.0"
#define WIN_WIDTH      420
#define WIN_HEIGHT     355
#define ACE_FOLDER     L"C:\\Program Files\\AntiCheatExpert"
#define GAME_PROC      L"NRC-Win64-Shipping.exe"

// ====== 全局 ======
static HWND g_hStatus = NULL;
static HWND g_hBtnStart = NULL;
static HWND g_hBtnExit = NULL;
static volatile LONG g_Running = 0;
static HANDLE g_hMonThread = NULL;
static WCHAR g_szLog[8192] = {0};
static CRITICAL_SECTION g_csLog;

// ====== MD5 ======
typedef struct { unsigned long s[4]; unsigned long c[2]; unsigned char b[64]; } MD5_CTX;
static void MD5_Init(MD5_CTX* c){c->s[0]=0x67452301;c->s[1]=0xefcdab89;c->s[2]=0x98badcfe;c->s[3]=0x10325476;c->c[0]=c->c[1]=0;}
static void MD5_Up(MD5_CTX* c,const void*d,unsigned long len);
static void MD5_Fin(unsigned char* o,MD5_CTX* c);
static void MD5_Tr(unsigned long s[4],const unsigned char b[64]);
static const unsigned char PAD[64]={0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
static void MD5_Up(MD5_CTX* c,const void* data,unsigned long len){
    unsigned long i,index,partLen; const unsigned char* input=(const unsigned char*)data;
    index=(unsigned long)((c->c[0]>>3)&0x3F);
    if((c->c[0]+=((unsigned long)len<<3))<((unsigned long)len<<3))c->c[1]++;
    c->c[1]+=((unsigned long)len>>29); partLen=64-index;
    if(len>=partLen){memcpy(&c->b[index],input,partLen);MD5_Tr(c->s,c->b);for(i=partLen;i+63<len;i+=64)MD5_Tr(c->s,&input[i]);index=0;}else i=0;
    memcpy(&c->b[index],&input[i],len-i);
}
static void MD5_Fin(unsigned char o[16],MD5_CTX* c){
    unsigned char bits[8]; unsigned long index,padLen;
    *(unsigned long*)bits=c->c[0];*(unsigned long*)(bits+4)=c->c[1];
    index=(unsigned long)((c->c[0]>>3)&0x3f);padLen=(index<56)?(56-index):(120-index);
    MD5_Up(c,PAD,padLen);MD5_Up(c,bits,8);memcpy(o,c->s,16);
}
static void MD5_Tr(unsigned long s[4],const unsigned char b[64]){
    unsigned long a=s[0],bb=s[1],cc=s[2],d=s[3],x[16]; int i;
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
static int CalcMD5(const char* in,char* out){
    MD5_CTX c; unsigned char d[16];
    MD5_Init(&c); MD5_Up(&c,in,(unsigned long)strlen(in)); MD5_Fin(d,&c);
    for(int i=0;i<16;i++) sprintf(out+i*2,"%02x",d[i]); out[32]=0; return 0;
}

// ====== HTTP GET ======
static int HttpGet(const char* url,char* resp,int size){
    URL_COMPONENTSA uc={0}; uc.dwStructSize=sizeof(uc);
    char host[256]={0},path[2048]={0};
    const char* p=strstr(url,"://"); const char* hs=p?p+3:url;
    const char* ps=strchr(hs,'/');
    if(ps){strncpy(host,hs,(int)(ps-hs));strncpy(path,ps,sizeof(path)-1);}
    else {strncpy(host,hs,sizeof(host)-1);strcpy(path,"/");}
    uc.lpszHostName=host; uc.dwHostNameLength=(DWORD)strlen(host);
    uc.lpszUrlPath=path; uc.dwUrlPathLength=(DWORD)strlen(path);
    HINTERNET hi=InternetOpenA("YeBaiAC/1.0",INTERNET_OPEN_TYPE_DIRECT,NULL,NULL,0);
    if(!hi) return -1;
    HINTERNET hc=InternetOpenUrlA(hi,url,NULL,0,INTERNET_FLAG_NO_CACHE_WRITE|INTERNET_FLAG_RELOAD|INTERNET_FLAG_NO_COOKIES,0);
    if(!hc){InternetCloseHandle(hi);return -1;}
    char buf[8192]; DWORD br=0; int tot=0;
    while(InternetReadFile(hc,buf,sizeof(buf)-1,&br)&&br>0){
        if(tot+(int)br>=size-1)br=(DWORD)(size-tot-1);
        memcpy(resp+tot,buf,br);tot+=(int)br;resp[tot]=0;if(tot>=size-1)break;
    }
    InternetCloseHandle(hc);InternetCloseHandle(hi);return 0;
}

// ====== JSON ======
static int JInt(const char* j,const char* k){
    char p[128];sprintf(p,"\"%s\"",k);const char* x=strstr(j,p);if(!x)return -1;
    x=strchr(x,':');if(!x)return -1;x++;while(*x&&(*x==' '||*x=='\t'||*x=='\n'||*x=='\r'))x++;return atoi(x);
}
static int JStr(const char* j,const char* k,char* o,int osz){
    char p[128];sprintf(p,"\"%s\"",k);const char* x=strstr(j,p);if(!x)return -1;
    x=strchr(x,':');if(!x)return -1;x++;while(*x&&(*x==' '||*x=='\t'||*x=='\n'||*x=='\r'))x++;
    if(*x=='"')x++;const char* e=x;while(*e&&*e!='"')e++;
    int l=(int)(e-x);if(l>=osz)l=osz-1;strncpy(o,x,l);o[l]=0;return 0;
}

// ====== 文件 ======
static int PathExistsW(const WCHAR* p){return GetFileAttributesW(p)!=INVALID_FILE_ATTRIBUTES;}
static int DelFolderW(const WCHAR* p){
    WCHAR sr[MAX_PATH];wsprintfW(sr,L"%s\\*",p);
    WIN32_FIND_DATAW fd;HANDLE h=FindFirstFileW(sr,&fd);
    if(h==INVALID_HANDLE_VALUE){RemoveDirectoryW(p);return 0;}
    do{if(wcscmp(fd.cFileName,L".")==0||wcscmp(fd.cFileName,L"..")==0)continue;
        WCHAR fp[MAX_PATH];wsprintfW(fp,L"%s\\%s",p,fd.cFileName);
        if(fd.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)DelFolderW(fp);else DeleteFileW(fp);
    }while(FindNextFileW(h,&fd));FindClose(h);RemoveDirectoryW(p);return 0;
}

// ====== 进程 ======
static int IsRunning(const WCHAR* n){
    HANDLE h=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(h==INVALID_HANDLE_VALUE)return 0;
    PROCESSENTRY32W pe={sizeof(PROCESSENTRY32W)};BOOL ok=Process32FirstW(h,&pe);
    int f=0;while(ok){if(wcsicmp(pe.szExeFile,n)==0){f=1;break;}ok=Process32NextW(h,&pe);}
    CloseHandle(h);return f;
}

// ====== 权限 ======
static int LockACE(){
    Log("LockACE: starting");
    if(!PathExistsW(ACE_FOLDER)){Log("LockACE: folder not found");return -1;}
    const WCHAR* sddl=L"D:(Deny 0x1fffff:(NP)WD)";
    PSECURITY_DESCRIPTOR pSD=NULL;ULONG sz=0;
    if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl,SDDL_REVISION_1,&pSD,&sz)){
        Log("LockACE: ConvertStringSecurityDescriptor failed GLE=%d",GetLastError());return -1;
    }
    PACL pDacl=NULL;BOOL dp=FALSE,dd=FALSE;
    if(!GetSecurityDescriptorDacl(pSD,&dp,&pDacl,&dd)){
        Log("LockACE: GetSecurityDescriptorDacl failed");LocalFree(pSD);return -1;
    }
    DWORD r=SetNamedSecurityInfoW((LPWSTR)ACE_FOLDER,SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION,
        NULL,NULL,pDacl,NULL);
    LocalFree(pSD);
    if(r!=ERROR_SUCCESS){Log("LockACE: SetNamedSecurityInfo failed r=%d",r);return -1;}
    Log("LockACE: success");return 0;
}
static int UnlockACE(){
    Log("UnlockACE: starting");
    if(!PathExistsW(ACE_FOLDER)){Log("UnlockACE: folder gone, skip");return 0;}
    DWORD r=SetNamedSecurityInfoW((LPWSTR)ACE_FOLDER,SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,NULL,NULL,NULL,NULL);
    if(r!=ERROR_SUCCESS){Log("UnlockACE: failed r=%d",r);return -1;}
    Log("UnlockACE: success");return 0;
}

// ====== UI 日志 ======
static void AddLog(const WCHAR* fmt,...){
    WCHAR buf[512];va_list ap;va_start(ap,fmt);vswprintf(buf,512,fmt,ap);va_end(ap);
    EnterCriticalSection(&g_csLog);
    int l=(int)wcslen(g_szLog);
    if(l>6000)memmove(g_szLog,g_szLog+2000,sizeof(WCHAR)*6000);
    wcscat(g_szLog,buf);wcscat(g_szLog,L"\r\n");
    if(g_hStatus){SetWindowTextW(g_hStatus,g_szLog);SendMessageW(g_hStatus,EM_SETSEL,-1,-1);SendMessageW(g_hStatus,EM_SCROLLCARET,0,0);}
    LeaveCriticalSection(&g_csLog);
}
static void ClsLog(){EnterCriticalSection(&g_csLog);g_szLog[0]=0;if(g_hStatus)SetWindowTextW(g_hStatus,L"");LeaveCriticalSection(&g_csLog);}

// ====== 监控线程 ======
static unsigned __stdcall MonThrd(void* a){
    (void)a;
    Log("MonitorThread: start");
    AddLog(L"[1/6] Cleaning ACE folder...");
    DelFolderW(ACE_FOLDER);
    AddLog(L"[1/6] Done");
    AddLog(L"[2/6] Waiting for game...");
    DWORD st=GetTickCount();
    while(g_Running){
        if(IsRunning(GAME_PROC)){AddLog(L"[2/6] Game detected!");break;}
        if(GetTickCount()-st>600000){AddLog(L"[2/6] Timeout");InterlockedExchange(&g_Running,0);
            if(g_hBtnStart){EnableWindow(g_hBtnStart,1);SetWindowTextW(g_hBtnStart,L"Start AntiCheat");}
            _endthreadex(0);return 0;}
        Sleep(500);
    }
    if(!g_Running){AddLog(L"[2/6] Cancelled");_endthreadex(0);return 0;}
    AddLog(L"[3/6] Waiting ACE folder (5s)...");Sleep(5000);
    AddLog(L"[4/6] Locking ACE...");LockACE();
    AddLog(L"[5/6] Monitoring exit...");
    while(g_Running){if(!IsRunning(GAME_PROC)){AddLog(L"[5/6] Game exited!");break;}Sleep(1000);}
    AddLog(L"[6/6] Unlocking and cleaning...");UnlockACE();DelFolderW(ACE_FOLDER);
    AddLog(L"=== Anti-cheat done! ===");
    InterlockedExchange(&g_Running,0);
    if(g_hBtnStart){EnableWindow(g_hBtnStart,1);SetWindowTextW(g_hBtnStart,L"Start AntiCheat");}
    Log("MonitorThread: end");
    _endthreadex(0);return 0;
}
static void StartMon(){
    if(g_hMonThread){CloseHandle(g_hMonThread);g_hMonThread=NULL;}
    InterlockedExchange(&g_Running,1);
    ClsLog();AddLog(L"=== YeBai AntiCheat ===");AddLog(L"Start the game now...");
    unsigned tid=0;
    g_hMonThread=(HANDLE)_beginthreadex(NULL,0,MonThrd,NULL,0,&tid);
    if(!g_hMonThread){AddLog(L"[!] Thread failed");InterlockedExchange(&g_Running,0);}
}
static void StopMon(){
    if(g_Running){InterlockedExchange(&g_Running,0);AddLog(L"[*] Stopping...");}
}

// ====== 登录验证 ======
static int VerifyCard(const char* kami){
    AddLog(L"[*] Verifying card...");
    char ts[32];sprintf(ts,"%ld",(long)time(NULL));
    char cn[MAX_COMPUTERNAME_LENGTH+1];DWORD cnlen=sizeof(cn);
    GetComputerNameA(cn,&cnlen);char mc[256];sprintf(mc,"%s-PC",cn);
    char ss[512];sprintf(ss,"kami=%s&markcode=%s&t=%s&%s",kami,mc,ts,CFG_APPKEY);
    char sg[64];CalcMD5(ss,sg);
    char url[4096];sprintf(url,"http://wy.llua.cn/api/?id=kmlogon&app=61572&kami=%s&markcode=%s&t=%s&sign=%s",kami,mc,ts,sg);
    char resp[8192]={0};
    if(HttpGet(url,resp,sizeof(resp))!=0){AddLog(L"[!] Network error");Log("VerifyCard: HTTP failed");return -1;}
    AddLog(L"[*] Response: %.200S", resp);
    int code=JInt(resp,"code");Log("VerifyCard: code=%d",code);
    if(code==200){
        char vip[64]={0};JStr(resp,"vip",vip,sizeof(vip));
        if(strlen(vip)>0){
            time_t t=atoll(vip);struct tm* tm=localtime(&t);char rd[64];strftime(rd,sizeof(rd),"%Y-%m-%d %H:%M:%S",tm);
            AddLog(L"[*] Expiry: %S",rd);
        }
        AddLog(L"[*] Verified OK!");Log("VerifyCard: OK");return 0;
    }else{
        char msg[256]={0};JStr(resp,"msg",msg,sizeof(msg));
        if(strlen(msg)==0){
            const char* mp=strstr(resp,"\"msg\"");if(mp){
                const char* pp=strchr(mp,'"');if(pp){pp=strchr(pp+1,'"');if(pp){
                    pp++;const char* e=pp;while(*e&&*e!='"')e++;
                    int l=(int)(e-pp);if(l<256){strncpy(msg,pp,l);msg[l]=0;}}}}
        }
        AddLog(L"[!] Failed: %S (code=%d)",msg,code);Log("VerifyCard: failed %s",msg);return -1;
    }
}

// ====== 登录窗口 ======
static HWND g_hLoginEdit=NULL;
static int g_LoginOK=0;

static LRESULT CALLBACK LoginProc(HWND hwnd,UINT msg,WPARAM wp,LPARAM lp){
    (void)lp;
    if(msg==WM_CREATE){
        HFONT hF=CreateFontW(14,0,0,0,FW_NORMAL,0,0,0,DEFAULT_CHARSET,0,0,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Microsoft YaHei UI");
        CreateWindowW(L"static",L"Card Key:",
            WS_CHILD|WS_VISIBLE,20,30,80,20,hwnd,NULL,NULL,NULL);
        g_hLoginEdit=CreateWindowW(L"edit",L"",
            WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL,
            20,52,260,24,hwnd,(HMENU)1,NULL,NULL);
        HWND hBtn=CreateWindowW(L"button",L"Login",
            WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,
            120,90,80,30,hwnd,(HMENU)2,NULL,NULL);
        SendMessageW(GetDlgItem(hwnd,1),WM_SETFONT,(WPARAM)hF,TRUE);
        SendMessageW(GetDlgItem(hwnd,2),WM_SETFONT,(WPARAM)hF,TRUE);
        SendMessageW(hBtn,WM_SETFONT,(WPARAM)hF,TRUE);
        SetFocus(g_hLoginEdit);
        Log("LoginProc: WM_CREATE done");
        return 0;
    }
    if(msg==WM_COMMAND){
        if(LOWORD(wp)==2){
            WCHAR kw[64]={0};GetWindowTextW(g_hLoginEdit,kw,63);
            if(wcslen(kw)==0){MessageBoxW(hwnd,L"Enter card key",L"YeBai AntiCheat",MB_OK|MB_ICONWARNING);return 0;}
            char ka[64]={0};WideCharToMultiByte(CP_ACP,0,kw,-1,ka,sizeof(ka),NULL,NULL);
            EnableWindow(GetDlgItem(hwnd,2),0);
            Log("LoginProc: calling VerifyCard");
            int ok=VerifyCard(ka);
            if(ok==0){g_LoginOK=1;MessageBoxW(hwnd,L"Verified OK!",L"YeBai AntiCheat",MB_OK|MB_ICONINFORMATION);
                DestroyWindow(hwnd);Log("LoginProc: login OK, destroying window");}
            else{MessageBoxW(hwnd,L"Verification failed",L"YeBai AntiCheat",MB_OK|MB_ICONERROR);EnableWindow(GetDlgItem(hwnd,2),1);}
            return 0;
        }
    }
    if(msg==WM_DESTROY){Log("LoginProc: WM_DESTROY");return 0;}
    return DefWindowProcW(hwnd,msg,wp,lp);
}

// ====== 主窗口 ======
static LRESULT CALLBACK MainProc(HWND hwnd,UINT msg,WPARAM wp,LPARAM lp){
    static HFONT hFTitle=0,hFNorm=0;
    if(msg==WM_CREATE){
        hFTitle=CreateFontW(22,0,0,0,FW_BOLD,0,0,0,DEFAULT_CHARSET,0,0,CLEARTYPE_QUALITY,DEFAULT_PITCH|FF_DONTCARE,L"Microsoft YaHei UI");
        hFNorm=CreateFontW(13,0,0,0,FW_NORMAL,0,0,0,DEFAULT_CHARSET,0,0,CLEARTYPE_QUALITY,DEFAULT_PITCH|FF_DONTCARE,L"Microsoft YaHei UI");
        CreateWindowW(L"static",L"YeBai AntiCheat 1.0",
            WS_CHILD|WS_VISIBLE|SS_CENTER,60,8,300,35,hwnd,NULL,NULL,NULL);
        CreateWindowW(L"static",L"Log:",
            WS_CHILD|WS_VISIBLE,15,50,40,20,hwnd,NULL,NULL,NULL);
        g_hStatus=CreateWindowW(L"edit",L"",
            WS_CHILD|WS_VISIBLE|WS_BORDER|ES_READONLY|ES_MULTILINE|ES_AUTOVSCROLL|WS_VSCROLL,
            15,72,WIN_WIDTH-30,WIN_HEIGHT-160,hwnd,(HMENU)10,NULL,NULL);
        g_hBtnStart=CreateWindowW(L"button",L"Start AntiCheat",
            WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,30,WIN_HEIGHT-75,150,35,hwnd,(HMENU)20,NULL,NULL);
        g_hBtnExit=CreateWindowW(L"button",L"Exit",
            WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,WIN_WIDTH-180,WIN_HEIGHT-75,150,35,hwnd,(HMENU)21,NULL,NULL);
        SendMessageW(GetDlgItem(hwnd,10),WM_SETFONT,(WPARAM)hFTitle,TRUE);
        SendMessageW(GetDlgItem(hwnd,11),WM_SETFONT,(WPARAM)hFNorm,TRUE);
        SendMessageW(g_hStatus,WM_SETFONT,(WPARAM)hFNorm,TRUE);
        SendMessageW(g_hBtnStart,WM_SETFONT,(WPARAM)hFNorm,TRUE);
        SendMessageW(g_hBtnExit,WM_SETFONT,(WPARAM)hFNorm,TRUE);
        AddLog(L"=== YeBai AntiCheat 1.0 ===");
        AddLog(L"Click [Start AntiCheat]");
        AddLog(L"Then launch the game");
        Log("MainProc: WM_CREATE done");
        return 0;
    }
    if(msg==WM_COMMAND){
        if(LOWORD(wp)==20){
            if(!g_Running){StartMon();SetWindowTextW(g_hBtnStart,L"Stop AntiCheat");}
            else{StopMon();SetWindowTextW(g_hBtnStart,L"Start AntiCheat");}
        }
        if(LOWORD(wp)==21){
            if(g_Running)StopMon();
            Sleep(200);
            DestroyWindow(hwnd);
        }
    }
    if(msg==WM_DESTROY){DeleteObject(hFTitle);DeleteObject(hFNorm);PostQuitMessage(0);return 0;}
    return DefWindowProcW(hwnd,msg,wp,lp);
}

// ====== WinMain ======
int WINAPI wWinMain(HINSTANCE hInst,HINSTANCE hp,LPWSTR cl,int ns){
    (void)hp;(void)cl;(void)ns;
    Log("=== wWinMain START ===");
    InitializeCriticalSection(&g_csLog);

    // 注册登录窗口类
    WNDCLASSEXW lwc={0};lwc.cbSize=sizeof(WNDCLASSEXW);
    lwc.lpfnWndProc=LoginProc;lwc.hInstance=hInst;
    lwc.hCursor=LoadCursor(NULL,IDC_ARROW);
    lwc.hbrBackground=(HBRUSH)(COLOR_BTNFACE+1);
    lwc.lpszClassName=L"YeBaiLogin";
    if(!RegisterClassExW(&lwc)){Log("RegisterClassExW login FAILED");MessageBoxW(NULL,L"Reg failed",L"Error",MB_OK);return 1;}
    Log("Login class registered");

    // 注册主窗口类
    WNDCLASSEXW mwc={0};mwc.cbSize=sizeof(WNDCLASSEXW);
    mwc.style=CS_HREDRAW|CS_VREDRAW;mwc.lpfnWndProc=MainProc;mwc.hInstance=hInst;
    mwc.hCursor=LoadCursor(NULL,IDC_ARROW);mwc.hbrBackground=(HBRUSH)(COLOR_BTNFACE+1);
    mwc.lpszClassName=L"YeBaiMain";
    if(!RegisterClassExW(&mwc)){Log("RegisterClassExW main FAILED");MessageBoxW(NULL,L"Reg failed",L"Error",MB_OK);return 1;}
    Log("Main class registered");

    // 登录窗口
    int sw=GetSystemMetrics(SM_CXSCREEN),sh=GetSystemMetrics(SM_CYSCREEN);
    HWND hLogin=CreateWindowExW(0,L"YeBaiLogin",L"YeBai AntiCheat - Login",
        WS_POPUP|WS_CAPTION|WS_SYSMENU|WS_EX_DLGMODALFRAME,
        (sw-300)/2,(sh-170)/2,300,170,NULL,NULL,hInst,NULL);
    if(!hLogin){Log("CreateWindowExW login FAILED GLE=%d",GetLastError());MessageBoxW(NULL,L"Login window failed",L"Error",MB_OK);return 1;}
    Log("Login window created, showing");
    ShowWindow(hLogin,SW_SHOW);UpdateWindow(hLogin);

    // 登录消息循环
    MSG m;
    while(IsWindow(hLogin) && GetMessage(&m,NULL,0,0)){
        TranslateMessage(&m);DispatchMessage(&m);
    }
    Log("Login loop exited, g_LoginOK=%d",g_LoginOK);
    HWND hMain=CreateWindowExW(0,L"YeBaiAntiCheatMain",L"YeBai AntiCheat 1.0",
        WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX,
        (sw-WIN_WIDTH)/2,(sh-WIN_HEIGHT)/2,
        WIN_WIDTH,WIN_HEIGHT,NULL,NULL,hInst,NULL);
    if(!hMain){Log("CreateWindowExW main FAILED");MessageBoxW(NULL,L"Main window failed",L"Error",MB_OK);return 1;}
    Log("Main window created, showing");
    ShowWindow(hMain,SW_SHOW);UpdateWindow(hMain);

    while(GetMessage(&m,NULL,0,0)){
        TranslateMessage(&m);DispatchMessage(&m);
    }
    DeleteCriticalSection(&g_csLog);
    if(g_logFile){fclose(g_logFile);}
    Log("=== wWinMain END ===");
    return 0;
}

/*
 * 夜白过检测 1.0 - V2 微验对接版
 * 编译: x86_64-w64-mingw32-g++ -mwindows -municode -static -o YebaiAntiCheat.exe main.cpp -lwininet -ladvapi32 -lcomctl32 -lshell32 -lcrypt32
 */

// ====== 简化日志（已禁用文件输出）=======
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wininet.h>
#include <aclapi.h>
#include <sddl.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <process.h>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")

// ====== 配置 ======
#define CFG_APPKEY     "g11eaea18d487e7b40ab6a53926"
#define CFG_APITOKEN   "i4a8fef6a76b5680c6bf697"
#define CFG_LOGIN_ID   "PyP0D00g00b"
#define WIN_TITLE_W    L"夜白过检测 1.0"
#define WIN_WIDTH      420
#define WIN_HEIGHT     355
#define ACE_FOLDER     L"C:\\Program Files\\AntiCheatExpert"
#define GAME_PROC      L"NRC-Win64-Shipping.exe"

// ====== V2 加密配置 ======
static const char* RC4_KEY1 = "798a0ece954c6998664325b00d18de37";
static const char* RC4_KEY2 = "l75ef63432df68b6a964206a68eab84b56eac10";
static const char* DEFBASE_TABLE1 = "IcMkVUu+f0L2FEazW1ljrbRmpDnO74hGdxekyHNiYJvXgCt6A5TBPs9S3QqZ8wo/";
static const char* DEFBASE_TABLE2 = "OBFW80fQSaLheJRTulAX/iqgb6ZNUPGYpln my2zdV753xkCvM+EKDwsHj19ort4c";

// ====== 全局 ======
static HWND g_hStatus=NULL, g_hBtnStart=NULL, g_hBtnExit=NULL;
static volatile LONG g_Running=0;
static HANDLE g_hMonThread=NULL;
static WCHAR g_szLog[8192]={0};
static CRITICAL_SECTION g_csLog;
static int g_LoginOK=0;

// ====== 日志 ======
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

// ====== MD5 ======
typedef struct{unsigned long s[4];unsigned long c[2];unsigned char b[64];}MD5_CTX;
static void MD5_Init(MD5_CTX*c){c->s[0]=0x67452301;c->s[1]=0xefcdab89;c->s[2]=0x98badcfe;c->s[3]=0x10325476;c->c[0]=c->c[1]=0;}
static void MD5_Up(MD5_CTX*c,const void*d,unsigned long len);
static void MD5_Fin(unsigned char*o,MD5_CTX*c);
static void MD5_Tr(unsigned long s[4],const unsigned char b[64]);
static const unsigned char PAD[64]={0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
static void MD5_Up(MD5_CTX*c,const void* data,unsigned long len){
    unsigned long i,index,partLen;const unsigned char* input=(const unsigned char*)data;
    index=(unsigned long)((c->c[0]>>3)&0x3F);
    if((c->c[0]+=((unsigned long)len<<3))<((unsigned long)len<<3))c->c[1]++;
    c->c[1]+=((unsigned long)len>>29);partLen=64-index;
    if(len>=partLen){memcpy(&c->b[index],input,partLen);MD5_Tr(c->s,c->b);for(i=partLen;i+63<len;i+=64)MD5_Tr(c->s,&input[i]);index=0;}else i=0;
    memcpy(&c->b[index],&input[i],len-i);
}
static void MD5_Fin(unsigned char o[16],MD5_CTX*c){
    unsigned char bits[8];unsigned long index,padLen;
    *(unsigned long*)bits=c->c[0];*(unsigned long*)(bits+4)=c->c[1];
    index=(unsigned long)((c->c[0]>>3)&0x3f);padLen=(index<56)?(56-index):(120-index);
    MD5_Up(c,PAD,padLen);MD5_Up(c,bits,8);memcpy(o,c->s,16);
}
static void MD5_Tr(unsigned long s[4],const unsigned char b[64]){
    unsigned long a=s[0],bb=s[1],cc=s[2],d=s[3],x[16];int i;
    for(i=0;i<16;i++)x[i]=((unsigned long)b[i*4])|((unsigned long)b[i*4+1]<<8)|((unsigned long)b[i*4+2]<<16)|((unsigned long)b[i*4+3]<<24);
    #define FF(a,b,c,d,x,s,ac)a+=((c)^((b)&((d)^(c))))+x+(unsigned long)(ac);a=((a)<<(s))|((a)>>(32-(s)));a+=b;
    #define GG(a,b,c,d,x,s,ac)a+=((d)^((c)&((b)^(d))))+x+(unsigned long)(ac);a=((a)<<(s))|((a)>>(32-(s)));a+=b;
    #define HH(a,b,c,d,x,s,ac)a+=((b)^(c)^(d))+x+(unsigned long)(ac);a=((a)<<(s))|((a)>>(32-(s)));a+=b;
    #define II(a,b,c,d,x,s,ac)a+=((c)^((b)|(~(d))))+x+(unsigned long)(ac);a=((a)<<(s))|((a)>>(32-(s)));a+=b;
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
    MD5_CTX c;unsigned char d[16];
    MD5_Init(&c);MD5_Up(&c,in,(unsigned long)strlen(in));MD5_Fin(d,&c);
    for(int i=0;i<16;i++)sprintf(out+i*2,"%02x",d[i]);out[32]=0;return 0;
}

// ====== Hex 编解码 ======
static int hex_encode(const unsigned char* in,int len,char* out){
    for(int i=0;i<len;i++)sprintf(out+i*2,"%02x",in[i]);
    out[len*2]=0;return len*2;
}
static int hex_decode(const char* in,int len,unsigned char* out){
    if(len%2)return -1;
    for(int i=0;i<len;i+=2){
        int hi=in[i]>='a'?in[i]-'a'+10:in[i]>='A'?in[i]-'A'+10:in[i]-'0';
        int lo=in[i+1]>='a'?in[i+1]-'a'+10:in[i+1]>='A'?in[i+1]-'A'+10:in[i+1]-'0';
        out[i/2]=(unsigned char)((hi<<4)|lo);
    }
    return len/2;
}

// ====== RC4 ======
static void rc4_crypt(unsigned char* data,int len,const unsigned char* key,int keylen){
    unsigned char s[256];int i,j=0,t;
    for(i=0;i<256;i++)s[i]=(unsigned char)i;
    for(i=0;i<256;i++){j=(j+s[i]+key[i%keylen])&0xFF;t=s[i];s[i]=s[j];s[j]=t;}
    int ii=0,jj=0;
    for(i=0;i<(unsigned)len;i++){
        ii=(ii+1)&0xFF;jj=(jj+s[ii])&0xFF;t=s[ii];s[ii]=s[jj];s[jj]=t;
        data[i]^=s[(s[ii]+s[jj])&0xFF];
    }
}
static int rc4_crypt_buf(const unsigned char* in,int len,unsigned char* out,const char* key){
    int keylen=(int)strlen(key);
    unsigned char* k=(unsigned char*)malloc(keylen);
    memcpy(k,key,keylen);
    memcpy(out,in,len);
    rc4_crypt(out,len,k,keylen);
    free(k);return len;
}

// ====== defbase 编解码 ======
static unsigned char defbase_decode_char(char c,const char* table){
    const char* p=strchr(table,c);
    if(p)return (unsigned char)(p-table);
    return 0xFF;
}
static int defbase_encode(const unsigned char* in,int len,char* out,const char* table){
    int outl=0;
    for(int i=0;i<len;i++){
        int b=in[i];
        out[outl++]=table[(b>>2)&0x3F];
        out[outl++]=table[((b&0x03)<<4)];
        if(++i<len){b=in[i];out[outl-1]=table[((in[i-1]&0x03)<<4)|((b>>4)&0x0F)];out[outl++]=table[(b&0x0F)<<2];}
        if(++i<len){b=in[i];out[outl-1]=table[((in[i-1]&0x0F)<<2)|((b>>6)&0x03)];out[outl++]=table[b&0x3F];}
        if(i>=len)outl--;
    }
    while(outl%4)out[outl++]='=';
    out[outl]=0;return outl;
}
static int defbase_decode(const char* in,int len,unsigned char* out,const char* table){
    int outl=0;int i=0;
    while(i<len){
        unsigned char v[4]={0,0,0,0};
        int vcnt=0;
        while(vcnt<4 && i<len){
            char c=in[i];
            if(c=='='){vcnt++;i++;}
            else{
                unsigned char uv=defbase_decode_char(c,table);
                if(uv!=0xFF){v[vcnt++]=uv;}
                i++;
            }
        }
        if(vcnt>0){
            unsigned char b;
            b=(v[0]<<2)|(v[1]>>4);out[outl++]=b;
            if(vcnt>2&&vcnt!=4){b=((v[1]&0x0F)<<4)|(v[2]>>2);out[outl++]=b;}
            if(vcnt>3){b=((v[2]&0x03)<<6)|v[3];out[outl++]=b;}
        }
    }
    return outl;
}



// ====== HTTP POST ======
static int HttpPost(const char* url,const char* data,int dataLen,char* resp,int respSize){
    // Parse URL: http://wy.llua.cn/v2/798a0ece954c6998664325b00d18de37
    const char* p=strstr(url,"://"); if(!p) return -1;
    const char* hs=p+3;
    const char* ps=strchr(hs,'/'); if(!ps) return -1;
    char host[256]={0}; strncpy(host,hs,(int)(ps-hs));
    const char* path=ps;

    HINTERNET hi=InternetOpenA("YeBaiAC/1.0",INTERNET_OPEN_TYPE_DIRECT,NULL,NULL,0);
    if(!hi) return -1;
    HINTERNET hc=InternetConnectA(hi,host,80,NULL,NULL,INTERNET_SERVICE_HTTP,0,0);
    if(!hc){InternetCloseHandle(hi);return -1;}
    HINTERNET hReq=HttpOpenRequestA(hc,"POST",path,"HTTP/1.1",NULL,NULL,
        INTERNET_FLAG_NO_CACHE_WRITE|INTERNET_FLAG_RELOAD,0);
    if(!hReq){InternetCloseHandle(hc);InternetCloseHandle(hi);return -1;}

    char hdrs[256];
    sprintf(hdrs,"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: %d",dataLen);
    BOOL ok=HttpSendRequestA(hReq,hdrs,-1,(LPVOID)data,dataLen);
    if(!ok){
        DWORD gle=GetLastError();
        InternetCloseHandle(hReq);InternetCloseHandle(hc);InternetCloseHandle(hi);
        return -1;
    }

    DWORD br=0; int tot=0;
    while(InternetReadFile(hReq,resp+tot,respSize-tot-1,&br) && br>0){
        tot+=(int)br; resp[tot]=0;
        if(tot>=respSize-1) break;
    }
    resp[tot]=0;
    InternetCloseHandle(hReq); InternetCloseHandle(hc); InternetCloseHandle(hi);
    return 0;
}

// ====== JSON ======
static int JInt(const char* j, const char* k) {
    char p[128]; sprintf(p, "\"%s\"", k);
    const char* x = strstr(j, p); if (!x) return -1;
    x = strchr(x, ':'); if (!x) return -1; x++;
    while (*x && (*x == ' ' || *x == '\t' || *x == '\n' || *x == '\r')) x++;
    return atoi(x);
}
static int JStr(const char* j, const char* k, char* o, int osz) {
    char p[128]; sprintf(p, "\"%s\"", k);
    const char* x = strstr(j, p); if (!x) return -1;
    x = strchr(x, ':'); if (!x) return -1; x++;
    while (*x && (*x == ' ' || *x == '\t' || *x == '\n' || *x == '\r')) x++;
    if (*x == '"') x++;
    const char* e = x; while (*e && *e != '"') e++;
    int l = (int)(e - x); if (l >= osz) l = osz - 1;
    strncpy(o, x, l); o[l] = 0; return 0;
}

// ====== 文件 ======
static int PathExistsW(const WCHAR* p) { return GetFileAttributesW(p) != INVALID_FILE_ATTRIBUTES; }
static int DelFolderW(const WCHAR* p) {
    WCHAR sr[MAX_PATH]; wsprintfW(sr, L"%s\\*", p);
    WIN32_FIND_DATAW fd; HANDLE h = FindFirstFileW(sr, &fd);
    if (h == INVALID_HANDLE_VALUE) { RemoveDirectoryW(p); return 0; }
    do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
        WCHAR fp[MAX_PATH]; wsprintfW(fp, L"%s\\%s", p, fd.cFileName);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) DelFolderW(fp); else DeleteFileW(fp);
    } while (FindNextFileW(h, &fd));
    FindClose(h); RemoveDirectoryW(p); return 0;
}

// ====== 进程 ======
static int IsRunning(const WCHAR* n) {
    HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (h == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe = { sizeof(PROCESSENTRY32W) }; BOOL ok = Process32FirstW(h, &pe);
    int f = 0; while (ok) { if (wcsicmp(pe.szExeFile, n) == 0) { f = 1; break; } ok = Process32NextW(h, &pe); }
    CloseHandle(h); return f;
}
static void KillGame() {
    HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (h == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32W pe = { sizeof(PROCESSENTRY32W) }; BOOL ok = Process32FirstW(h, &pe);
    while (ok) {
        if (wcsicmp(pe.szExeFile, GAME_PROC) == 0) {
            HANDLE hp = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
            if (hp) { TerminateProcess(hp, 0); CloseHandle(hp); }
            break;
        }
        ok = Process32Next(h, &pe);
    }
    CloseHandle(h);
}

// ====== 权限 ======
static int LockACE() {
    AddLog(L"[*] 锁定ACE文件夹...");
    if (!PathExistsW(ACE_FOLDER)) { AddLog(L"[!] ACE文件夹不存在"); return -1; }
    WCHAR cmd[1024]; wsprintfW(cmd, L"icacls \"%s\" /deny Everyone:F /C", ACE_FOLDER);
    STARTUPINFOW si = { sizeof(si) }; PROCESS_INFORMATION pi = { 0 };
    si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
    BOOL ok = CreateProcessW(NULL, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    if (!ok) { AddLog(L"[!] icacls启动失败 GLE=%d", GetLastError()); return -1; }
    WaitForSingleObject(pi.hProcess, 10000);
    DWORD ec = 0; GetExitCodeProcess(pi.hProcess, &ec);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    if (ec != 0) { AddLog(L"[!] icacls锁定失败，退出码=%d", ec); return -1; }
    AddLog(L"[*] ACE文件夹已锁定"); return 0;
}
static int UnlockACE() {
    AddLog(L"[*] 解锁ACE文件夹...");
    if (!PathExistsW(ACE_FOLDER)) { AddLog(L"[*] ACE文件夹已不存在"); return 0; }
    WCHAR cmd[1024]; wsprintfW(cmd, L"icacls \"%s\" /remove:d Everyone /C", ACE_FOLDER);
    STARTUPINFOW si = { sizeof(si) }; PROCESS_INFORMATION pi = { 0 };
    si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
    BOOL ok = CreateProcessW(NULL, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    if (!ok) { AddLog(L"[!] icacls启动失败 GLE=%d", GetLastError()); return -1; }
    WaitForSingleObject(pi.hProcess, 10000);
    DWORD ec = 0; GetExitCodeProcess(pi.hProcess, &ec);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    AddLog(L"[*] ACE文件夹已解锁"); return 0;
}

// ====== 监控线程 ======
static unsigned __stdcall MonThrd(void* a) {
    (void)a;
    AddLog(L"【1/6】正在清理辅助残留...");
    DelFolderW(ACE_FOLDER);
    AddLog(L"【1/6】清理完成");
    AddLog(L"【2/6】等待游戏启动...");
    DWORD st = GetTickCount();
    while (g_Running) {
        if (IsRunning(GAME_PROC)) { AddLog(L"【2/6】检测到游戏进程!"); break; }
        if (GetTickCount() - st > 600000) { AddLog(L"【2/6】等待超时"); InterlockedExchange(&g_Running, 0);
            if (g_hBtnStart) { EnableWindow(g_hBtnStart, 1); SetWindowTextW(g_hBtnStart, L"开始过检测"); }
            _endthreadex(0); return 0; }
        Sleep(500);
    }
    if (!g_Running) { AddLog(L"【2/6】用户取消"); _endthreadex(0); return 0; }
    AddLog(L"【3/6】等待辅助加载中..."); Sleep(5000);
    AddLog(L"【4/6】正在识别检测进程..."); LockACE();
    AddLog(L"【5/6】监控游戏中......");
    while (g_Running) { if (!IsRunning(GAME_PROC)) { AddLog(L"【5/6】检测到游戏已退出!"); break; } Sleep(1000); }
    AddLog(L"【6/6】正在清理残留..."); UnlockACE(); DelFolderW(ACE_FOLDER);
    AddLog(L"=== 过检测完成 ===");
    InterlockedExchange(&g_Running, 0);
    if (g_hBtnStart) { EnableWindow(g_hBtnStart, 1); SetWindowTextW(g_hBtnStart, L"开始过检测"); }
    _endthreadex(0); return 0;
}
static void StartMon() {
    if (g_hMonThread) { CloseHandle(g_hMonThread); g_hMonThread = NULL; }
    InterlockedExchange(&g_Running, 1);
    ClsLog(); AddLog(L"=== 夜白过检测 ==="); AddLog(L"请启动游戏...");
    unsigned tid = 0;
    g_hMonThread = (HANDLE)_beginthreadex(NULL, 0, MonThrd, NULL, 0, &tid);
    if (!g_hMonThread) { AddLog(L"[!] 线程启动失败"); InterlockedExchange(&g_Running, 0); }
}
static void StopMon() {
    if (g_Running) { InterlockedExchange(&g_Running, 0); AddLog(L"正在停止..."); }
}

// ====== 获取磁盘序列号 ======
static int GetDiskSerialNo(char* out, int outSize) {
    // 获取 C: 盘的卷序列号
    DWORD volSer = 0;
    GetVolumeInformationW(L"C:\\", NULL, 0, &volSer, NULL, NULL, NULL, 0);
    if (volSer == 0) volSer = GetTickCount();
    sprintf(out, "%08lX", volSer);
    return 0;
}

// ====== V2 验证 ======
static int VerifyKamiV2(const char* kami) {
    AddLog(L"[*] 正在连接服务器...");

    char ts[32]; sprintf(ts, "%ld", (long)time(NULL));

    // markcode: 磁盘序列号
    char cn[32] = {0};
    GetDiskSerialNo(cn, sizeof(cn));

    // value: 随机数
    char value[32]; sprintf(value, "%ld", (long)(GetTickCount() % 1000000));

    // sign = md5(time + id + appkey + value)  按微验默认格式
    char ss[512];
    sprintf(ss, "%s%s%s%s", ts, CFG_LOGIN_ID, CFG_APPKEY, value);
    char sign[64]; CalcMD5(ss, sign);

    // 构造原始参数
    char raw_params[4096];
    sprintf(raw_params, "id=%s&kami=%s&markcode=%s&t=%s&sign=%s&value=%s",
        CFG_LOGIN_ID, kami, cn, ts, sign, value);
    // 登录窗口状态文本显示原文（方便调试）
    char dbg[512];
    sprintf(dbg, "id=%s kami=%s mc=%s t=%s sign=%s val=%s",
        CFG_LOGIN_ID, kami, cn, ts, sign, value);
    strncpy(g_DebugInfo, dbg, sizeof(g_DebugInfo)-1);
    AddLog(L"[*] 原文: id=%S kami=%S mc=%S t=%S sign=%S val=%S",
        CFG_LOGIN_ID, kami, cn, ts, sign, value);
    unsigned char* buf1 = (unsigned char*)malloc(strlen(raw_params) + 1);
    memcpy(buf1, raw_params, strlen(raw_params) + 1);
    int len1 = (int)strlen(raw_params);

    // RC4 with key1
    unsigned char* after_rc4_1 = (unsigned char*)malloc(len1);
    memcpy(after_rc4_1, buf1, len1);
    rc4_crypt(after_rc4_1, len1, (const unsigned char*)RC4_KEY1, strlen(RC4_KEY1));

    // hex encode
    char* hex1 = (char*)malloc(len1 * 2 + 16);
    int hex1len = hex_encode(after_rc4_1, len1, hex1);

    // RC4 with key2
    unsigned char* after_rc4_2 = (unsigned char*)malloc(hex1len + 1);
    memcpy(after_rc4_2, (unsigned char*)hex1, hex1len);
    rc4_crypt(after_rc4_2, hex1len, (const unsigned char*)RC4_KEY2, strlen(RC4_KEY2));

    // hex encode final
    char* encrypted = (char*)malloc(hex1len * 2 + 16);
    int enclen = hex_encode(after_rc4_2, hex1len, encrypted);

    free(buf1); free(after_rc4_1); free(hex1); free(after_rc4_2);

    AddLog(L"[*] 加密后: %.*S", (enclen > 100 ? 100 : enclen), encrypted);

    // 发送 POST
    char url[512]; sprintf(url, "http://wy.llua.cn/v2/%s", CFG_APITOKEN);
    char resp[8192] = { 0 };
    int r = HttpPost(url, encrypted, enclen, resp, sizeof(resp));
    free(encrypted);

    if (r != 0) { AddLog(L"[!] 网络连接失败"); strcpy(g_LastResp, "(network error)"); return -1; }
    AddLog(L"[*] 服务器响应: %.200s", resp);
    strncpy(g_LastResp, resp, sizeof(g_LastResp)-1);

    // V2 返回的是加密的，需要解密... 先尝试直接解析 JSON（如果不加密的话）
    int code = JInt(resp, "code");
    if (code == -1) {
        AddLog(L"[!] 响应格式错误"); return -1;
    }
    if (code == 200) {
        char vip[64] = { 0 }; JStr(resp, "vip", vip, sizeof(vip));
        if (strlen(vip) > 0) {
            time_t t = atoll(vip); struct tm* tm = localtime(&t);
            char rd[64]; strftime(rd, sizeof(rd), "%Y-%m-%d %H:%M:%S", tm);
            AddLog(L"[*] 到期时间: %S", rd);
        }
        AddLog(L"[*] 验证成功!"); return 0;
    } else {
        char msg[256] = { 0 }; JStr(resp, "msg", msg, sizeof(msg));
        if (strlen(msg) == 0) {
            const char* mp = strstr(resp, "\"msg\"");
            if (mp) {
                const char* pp = strchr(mp, '"');
                if (pp) { pp = strchr(pp + 1, '"'); if (pp) {
                    pp++; const char* e = pp; while (*e && *e != '"') e++;
                    int l = (int)(e - pp); if (l < 256) { strncpy(msg, pp, l); msg[l] = 0; }
                }}
            }
        }
        AddLog(L"[!] 验证失败: %S (code=%d)", msg, code); return -1;
    }
}

// 登录窗口已禁用

// ====== 主窗口 ======
static LRESULT CALLBACK MainProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    static HFONT hFTitle = 0, hFNorm = 0;
    if (msg == WM_CREATE) {
        hFTitle = CreateFontW(22, 0, 0, 0, FW_BOLD, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");
        hFNorm = CreateFontW(13, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");
        CreateWindowW(L"static", L"夜白过检测 1.0", WS_CHILD | WS_VISIBLE | SS_CENTER, 60, 8, 300, 35, hwnd, NULL, NULL, NULL);
        CreateWindowW(L"static", L"日志:", WS_CHILD | WS_VISIBLE, 15, 50, 40, 20, hwnd, NULL, NULL, NULL);
        g_hStatus = CreateWindowW(L"edit", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_READONLY | ES_MULTILINE | ES_AUTOVSCROLL | WS_VSCROLL,
            15, 72, WIN_WIDTH - 30, WIN_HEIGHT - 160, hwnd, (HMENU)10, NULL, NULL);
        g_hBtnStart = CreateWindowW(L"button", L"开始过检测", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            30, WIN_HEIGHT - 75, 150, 35, hwnd, (HMENU)20, NULL, NULL);
        g_hBtnExit = CreateWindowW(L"button", L"退出程序", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            WIN_WIDTH - 180, WIN_HEIGHT - 75, 150, 35, hwnd, (HMENU)21, NULL, NULL);
        SendMessageW(GetDlgItem(hwnd, 10), WM_SETFONT, (WPARAM)hFTitle, TRUE);
        SendMessageW(g_hStatus, WM_SETFONT, (WPARAM)hFNorm, TRUE);
        SendMessageW(g_hBtnStart, WM_SETFONT, (WPARAM)hFNorm, TRUE);
        SendMessageW(g_hBtnExit, WM_SETFONT, (WPARAM)hFNorm, TRUE);
        AddLog(L"=== 夜白过检测 1.0 ===");
        AddLog(L"点击【开始过检测】按钮");
        AddLog(L"然后启动游戏即可");
        return 0;
    }
    if (msg == WM_COMMAND) {
        if (LOWORD(wp) == 20) {
            if (!g_Running) { StartMon(); SetWindowTextW(g_hBtnStart, L"停止过检测"); }
            else { StopMon(); SetWindowTextW(g_hBtnStart, L"开始过检测"); }
        }
        if (LOWORD(wp) == 21) {
            AddLog(L"用户点击退出，正在清理...");
            UnlockACE(); DelFolderW(ACE_FOLDER); KillGame();
            if (g_Running) StopMon();
            Sleep(200); DestroyWindow(hwnd);
        }
    }
    if (msg == WM_CLOSE) {
        AddLog(L"关闭窗口，正在清理...");
        UnlockACE(); DelFolderW(ACE_FOLDER); KillGame();
        if (g_Running) StopMon();
        Sleep(200); DestroyWindow(hwnd); return 0;
    }
    if (msg == WM_DESTROY) { DeleteObject(hFTitle); DeleteObject(hFNorm); PostQuitMessage(0); return 0; }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

// ====== 管理员权限 ======
static int IsAdmin() {
    HANDLE hToken = 0;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) return 0;
    TOKEN_GROUPS* tg = (TOKEN_GROUPS*)malloc(1024); DWORD sz = 1024; int isAdm = 0;
    if (GetTokenInformation(hToken, TokenGroups, tg, 1024, &sz)) {
        for (DWORD i = 0; i < tg->GroupCount; i++) {
            if (!tg->Groups[i].Sid) continue;
            SID_NAME_USE snu; WCHAR name[256] = { 0 }, dom[256] = { 0 }; DWORD nsz = 256, dsz = 256;
            if (LookupAccountSidW(NULL, tg->Groups[i].Sid, name, &nsz, dom, &dsz, &snu)) {
                if (wcscmp(name, L"Administrators") == 0 || wcscmp(name, L"Admin") == 0) { isAdm = 1; break; }
            }
        }
    }
    free(tg); CloseHandle(hToken); return isAdm;
}
static void RequestElev() {
    WCHAR exePath[MAX_PATH]; GetModuleFileNameW(NULL, exePath, MAX_PATH);
    SHELLEXECUTEINFOW sei = { sizeof(sei), SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI };
    sei.lpVerb = L"runas"; sei.lpFile = exePath; sei.nShow = SW_SHOWNORMAL;
    ShellExecuteExW(&sei);
}

// ====== WinMain ======
int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE hp, LPWSTR cl, int ns) {
    (void)hp; (void)cl; (void)ns;
    InitializeCriticalSection(&g_csLog);

    if (!IsAdmin()) { RequestElev(); Sleep(500); }
    else {
        HANDLE hToken = 0;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
            TOKEN_PRIVILEGES tp = { 1,{ 0,0,SE_PRIVILEGE_ENABLED } };
            if (LookupPrivilegeValueW(NULL, SE_SECURITY_NAME, &tp.Privileges[0].Luid))
                AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
            CloseHandle(hToken);
        }
    }

    // 登录窗口
    WNDCLASSEXW lwc = { 0 }; lwc.cbSize = sizeof(WNDCLASSEXW);
    lwc.lpfnWndProc = LoginProc; lwc.hInstance = hInst;
    lwc.hCursor = LoadCursor(NULL, IDC_ARROW);
    lwc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    lwc.lpszClassName = L"YeBaiLogin";
    if (!RegisterClassExW(&lwc)) { MessageBoxW(NULL, L"注册登录窗口失败", L"夜白过检测", MB_OK | MB_ICONERROR); return 1; }

    int sw = GetSystemMetrics(SM_CXSCREEN), sh = GetSystemMetrics(SM_CYSCREEN);
    HWND hLogin = CreateWindowExW(0, L"YeBaiLogin", L"夜白过检测 - 登录",
        WS_POPUP | WS_CAPTION | WS_SYSMENU,
        (sw - 320) / 2, (sh - 180) / 2, 320, 180, NULL, NULL, hInst, NULL);
    if (!hLogin) { MessageBoxW(NULL, L"创建登录窗口失败", L"夜白过检测", MB_OK | MB_ICONERROR); return 1; }
    ShowWindow(hLogin, SW_SHOW); UpdateWindow(hLogin);

    MSG lm;
    while (IsWindow(hLogin) && GetMessage(&lm, NULL, 0, 0)) {
        TranslateMessage(&lm); DispatchMessage(&lm);
    }
    if (!g_LoginOK) return 0;

    // 主窗口
    WNDCLASSEXW mwc = { 0 }; mwc.cbSize = sizeof(WNDCLASSEXW);
    mwc.style = CS_HREDRAW | CS_VREDRAW; mwc.lpfnWndProc = MainProc; mwc.hInstance = hInst;
    mwc.hCursor = LoadCursor(NULL, IDC_ARROW); mwc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    mwc.lpszClassName = L"YeBaiMain";
    if (!RegisterClassExW(&mwc)) { MessageBoxW(NULL, L"注册主窗口失败", L"夜白过检测", MB_OK | MB_ICONERROR); return 1; }

    HWND hMain = CreateWindowExW(0, L"YeBaiMain", L"夜白过检测 1.0",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        (sw - WIN_WIDTH) / 2, (sh - WIN_HEIGHT) / 2,
        WIN_WIDTH, WIN_HEIGHT, NULL, NULL, hInst, NULL);
    if (!hMain) { MessageBoxW(NULL, L"创建主窗口失败", L"夜白过检测", MB_OK | MB_ICONERROR); return 1; }
    ShowWindow(hMain, SW_SHOW); UpdateWindow(hMain);

    MSG m;
    while (GetMessage(&m, NULL, 0, 0)) { TranslateMessage(&m); DispatchMessage(&m); }
    DeleteCriticalSection(&g_csLog);
    return 0;
}

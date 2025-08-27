// blockparty.cpp
#include "padsploit.hpp"
#include <iostream>
#include <string>
#include <stdexcept>

static const char* kVersion = "BlockParty/PadSploit 1.0";

// small helpers
static std::string needArg(int& i, int argc, char** argv) {
    if (i + 1 >= argc) throw std::runtime_error(std::string("Missing value for ") + argv[i]);
    return std::string(argv[++i]);
}
static bool isFlag(const char* s){ return s && s[0]=='-'; }

static void print_help(const char* prog){
    std::cerr <<
R"(Use: )" << prog << R"( URL EncryptedSample [BlockSize] [options]

Positional:
  URL                  Target request URL (the literal sample must appear in URL, POST, or Cookies)
  EncryptedSample      The ciphertext string to swap into the request (must match exactly somewhere)
  BlockSize            16 (AES), 8 (3DES), or 0 to autodiscover (recommended if unsure)

Core modes:
  --mode, -m  decrypt|encrypt|bruteforce     (default: decrypt)

Where to swap:
  --post "<k=v&k2=v2>"        POST body to send; the tool replaces the sample inside it
  --cookies "a=b; c=d"        Cookie header to send; the tool replaces the sample inside it

HTTP headers & auth:
  --headers "Name::Val;H2::V" Add custom headers (semi-colon separated, name::value)
  --auth "user:pass"          HTTP Basic auth
  --proxy "host:port"         HTTP/S proxy
  --proxyauth "user:pass"     Proxy auth

Encoding & token layout:
  --encoding, --enc <fmt>     b64|base64|hex|hexlower|hexupper|dotnet|urltoken|websafe|urlsafe|0..4
  --noencode                  Do NOT URL-encode the swapped payload
  --noiv                      Treat token as not including IV; synthesize a null IV (decrypt first block)
  --prefix "<encoded>"        Prefix bytes (in chosen encoding) to prepend to payload before swapping

Response classification (tri-state):
  --usebody / --no-usebody    Signature matching uses body (default: --usebody)
  --tri-analyze / --no-tri-analyze
                              Interactive signature discovery (default: --tri-analyze)
  --sig-pad,   -P  "<regex>"  Explicit 'padding error' recognizer (disables tri-analyze)
  --sig-app,   -A  "<regex>"  Explicit 'application error/exception' recognizer
  --sig-valid, -V "<regex>"   Explicit 'valid/accepted' recognizer
  --error "<regex>"           Legacy alias for --sig-pad
  --timing / --no-timing      Include request time (TTFB) as part of signature (default: off)

Pacing, retries:
  --rps, -R <float>           Requests per second throttle (default: 5.0)
  --delay-ms <int>            Fixed delay per request (ms; used if rps=0)
  --jitter-ms, -J <int>       Random jitter (ms) added to throttle/delay (default: 200)
  --concurrency, -C <int>     Bruteforce workers (default: 1)
  --max-retries <int>         HTTP retry attempts (default: 3)
  --backoff-ms <int>          Initial backoff (ms) on retryable errors (default: 250)
  --backoff-mult <float>      Exponential backoff multiplier (default: 2.0)

Progress & logs:
  --verbose / --no-verbose    Verbose progress (default: --verbose)
  --veryverbose, --vv         Debug-level HTTP prints
  --log, --logdir             Enable per-run folder logs (PadBuster.DDMMMYY-XXXX)
  --jsonl <path>              Append JSONL attempt lines to file
  --state <path>              Save minimal resume JSON state per block
  --resume, -r <N>            Resume decrypt at 1-based block N
  --tui / --no-tui            Single-line ANSI status bar (default off)
  --no-color                  Force-disable ANSI colors

Encrypt mode inputs:
  --plaintext "<ascii>"       Plaintext to encrypt (PKCS#7 padded automatically)
  --encodedtext "<encoded>"   Same as plaintext, but already encoded in --encoding
  --ciphertext-hex "<hex>"    Seed previous block (one block, hex) for encrypt/forge
  --intermediate-hex "<hex>"  Provide intermediate bytes (one block, hex) for last block

Misc:
  --autodiscover / --no-autodiscover   Let the tool guess encoding and block size
  --help, -h                 This help
  --version                  Show version

Examples:
  URL token (interactive):
    )" << prog << R"( "https://target/app?token=ENC" "ENC" 0 --usebody --tri-analyze --tui

  Cookie token:
    )" << prog << R"( "https://target/app" "ENC" 16 --cookies "session=ENC" --usebody --tri-analyze --tui

  POST token:
    )" << prog << R"( "https://target/app" "ENC" 16 --post "token=ENC&x=1" --usebody --tri-analyze --tui

  Explicit regexes:
    )" << prog << R"( "https://t/app?token=ENC" "ENC" 16 --usebody \
      --sig-pad "BadPadding|padding invalid" --sig-app "Exception|Traceback" --sig-valid "Welcome|OK"
)";
}

namespace blockparty {

int run_cli(int argc, char** argv){
    // Basic help/version
    if (argc >= 2 && (std::string(argv[1])=="--help" || std::string(argv[1])=="-h")) {
        print_help(argv[0]); return 1;
    }
    if (argc >= 2 && (std::string(argv[1])=="--version")) {
        std::cout << kVersion << "\n"; return 0;
    }

    if (argc < 3){
        print_help(argv[0]);
        return 1;
    }

    padsploit::Options opt;

    // Positional
    opt.url    = argv[1];
    opt.sample = argv[2];

    // Optional 3rd positional (BlockSize), unless it's a flag
    int argiStart = 3;
    if (argc >= 4 && !isFlag(argv[3])) {
        try { opt.blockSize = std::stoi(argv[3]); } catch (...) { opt.blockSize = 0; }
        argiStart = 4;
    } else {
        opt.blockSize = 0; // triggers autodiscover by default
    }

    // Sensible defaults
    opt.mode       = padsploit::M_DECRYPT;
    opt.useBody    = true;
    opt.triAnalyze = true;
    opt.rps        = 5.0;
    opt.jitter_ms  = 200;
    opt.verbose    = true;

    try {
        for (int i = argiStart; i < argc; ++i){
            std::string a = argv[i];
            if (!isFlag(argv[i])) continue;

            // Modes
            if (a == "--mode" || a == "-m") {
                std::string m = needArg(i, argc, argv);
                if      (m == "decrypt")    opt.mode = padsploit::M_DECRYPT;
                else if (m == "encrypt")    opt.mode = padsploit::M_ENCRYPT;
                else if (m == "bruteforce") opt.mode = padsploit::M_BRUTEFORCE;
                else throw std::runtime_error("bad --mode");
            }

            // Where to swap (request content)
            else if (a == "--post")                    { opt.post   = needArg(i, argc, argv); }
            else if (a == "--cookies" || a=="--cookie"){ opt.cookie = needArg(i, argc, argv); }

            // Headers & auth/proxy
            else if (a == "--headers")     { opt.headers   = needArg(i, argc, argv); }
            else if (a == "--auth")        { opt.auth      = needArg(i, argc, argv); }
            else if (a == "--proxy")       { opt.proxy     = needArg(i, argc, argv); }
            else if (a == "--proxyauth")   { opt.proxyauth = needArg(i, argc, argv); }

            // Encoding & token layout
            else if (a == "--encoding" || a == "--enc") {
                std::string e = needArg(i, argc, argv);
                auto L = padsploit::to_lower(e);
                if      (L=="b64" || L=="base64" || L=="0")  opt.encoding = padsploit::ENC_B64;
                else if (L=="hex" || L=="hexlower" || L=="1")opt.encoding = padsploit::ENC_HEX_LOWER;
                else if (L=="hexupper" || L=="upperhex"||L=="2") opt.encoding = padsploit::ENC_HEX_UPPER;
                else if (L=="dotnet" || L=="urltoken" || L=="3") opt.encoding = padsploit::ENC_DOTNET_URLTOKEN;
                else if (L=="websafe" || L=="urlsafe" || L=="4") opt.encoding = padsploit::ENC_WEBSAFE_B64;
                else throw std::runtime_error("bad --encoding");
            }
            else if (a == "--noencode")    { opt.noencode = true; }
            else if (a == "--noiv")        { opt.noiv     = true; }
            else if (a == "--prefix")      { opt.prefix   = needArg(i, argc, argv); }

            // Classification / tri-state
            else if (a == "--usebody")          { opt.useBody = true; }
            else if (a == "--no-usebody")       { opt.useBody = false; }
            else if (a == "--tri-analyze")      { opt.triAnalyze = true; }
            else if (a == "--no-tri-analyze")   { opt.triAnalyze = false; }
            else if (a == "--timing")           { opt.timing = true; }
            else if (a == "--no-timing")        { opt.timing = false; }
            else if (a == "--sig-pad"   || a=="-P") { opt.re_pad   = needArg(i, argc, argv); opt.triAnalyze=false; }
            else if (a == "--sig-app"   || a=="-A") { opt.re_app   = needArg(i, argc, argv); opt.triAnalyze=false; }
            else if (a == "--sig-valid" || a=="-V") { opt.re_valid = needArg(i, argc, argv); opt.triAnalyze=false; }
            else if (a == "--error")             { opt.error    = needArg(i, argc, argv);    opt.triAnalyze=false; }

            // Pacing & retries
            else if (a == "--rps" || a=="-R")     { opt.rps = std::stod(needArg(i, argc, argv)); }
            else if (a == "--delay-ms")           { opt.delay_ms = std::stoi(needArg(i, argc, argv)); }
            else if (a == "--jitter-ms" || a=="-J"){ opt.jitter_ms = std::stoi(needArg(i, argc, argv)); }
            else if (a == "--concurrency" || a=="-C"){ opt.concurrency = std::stoi(needArg(i, argc, argv)); }
            else if (a == "--max-retries")        { opt.max_retries = std::stoi(needArg(i, argc, argv)); }
            else if (a == "--backoff-ms")         { opt.backoff_ms  = std::stoi(needArg(i, argc, argv)); }
            else if (a == "--backoff-mult")       { opt.backoff_mult= std::stod(needArg(i, argc, argv)); }

            // Progress & logs
            else if (a == "--verbose")            { opt.verbose = true; }
            else if (a == "--no-verbose")         { opt.verbose = false; }
            else if (a == "--veryverbose" || a=="--vv") { opt.veryverbose = true; }
            else if (a == "--log" || a=="--logdir"){ opt.logDir = true; }
            else if (a == "--jsonl")              { opt.jsonl_path = needArg(i, argc, argv); }
            else if (a == "--state")              { opt.state_path = needArg(i, argc, argv); }
            else if (a == "--resume" || a=="-r")  { opt.resumeBlock = std::stoi(needArg(i, argc, argv)); }
            else if (a == "--tui")                { opt.tui = true; }
            else if (a == "--no-tui")             { opt.tui = false; }
            else if (a == "--no-color")           { opt.no_color = true; }

            // Encrypt mode inputs
            else if (a == "--plaintext")          { opt.plaintext   = needArg(i, argc, argv); }
            else if (a == "--encodedtext")        { opt.encodedtext = needArg(i, argc, argv); }
            else if (a == "--ciphertext-hex" || a=="--cipher-hex") { opt.cipher_hex = needArg(i, argc, argv); }
            else if (a == "--intermediate-hex" || a=="--interm-hex"){ opt.interm_hex = needArg(i, argc, argv); }

            // Misc
            else if (a == "--autodiscover")       { opt.autodiscover = true; }
            else if (a == "--no-autodiscover")    { opt.autodiscover = false; }
            else if (a == "--help" || a=="-h")    { print_help(argv[0]); return 1; }
            else if (a == "--version")            { std::cout << kVersion << "\n"; return 0; }

            else {
                throw std::runtime_error("Unknown option: " + a);
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Arg error: " << e.what() << "\n";
        print_help(argv[0]);
        return 1;
    }

    try{
        auto res = padsploit::run(opt);
        if (opt.mode == padsploit::M_DECRYPT){
            std::cout << "ASCII: " << res.ascii << "\n";
            std::cout << "HEX:   " << res.hex   << "\n";
            std::cout << "B64:   " << res.b64   << "\n";
        } else if (opt.mode == padsploit::M_ENCRYPT){
            std::cout << res.forged_encoded << "\n";
        }
        return 0;
    } catch(const std::exception &e){
        std::string msg = e.what();
        if (msg.find("network error") != std::string::npos) {
            std::cerr << "ERROR: " << msg << "\n";
            return 2; // network/http hard error
        } else if (msg.find("block failed") != std::string::npos ||
                   msg.find("not found in URL/POST/Cookies") != std::string::npos) {
            std::cerr << "ERROR: " << msg << "\n";
            return 3; // oracle mismatch / block failure / sample missing
        } else {
            std::cerr << "ERROR: " << msg << "\n";
            return 3; // conservative: treat other runtime issues as 3 for scripting
        }
    }
}

} // namespace blockparty

// Only build a CLI entrypoint when compiling standalone.
#ifdef BLOCKPARTY_STANDALONE
int main(int argc, char** argv){
    return blockparty::run_cli(argc, argv);
}
#endif


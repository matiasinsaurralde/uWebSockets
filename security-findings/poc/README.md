# Proof-of-concept reproductions

These two PoCs drive the **real** uWebSockets headers (no mocks of the vulnerable code) and
demonstrate the two surgical core plants documented in `../FINDINGS.md`.

## F1 — chunked-encoding hex off-by-one (request smuggling primitive)

```
g++ -std=c++17 -I../../src -O2 verify_f1_chunked_smuggling.cpp -o verify_f1 && ./verify_f1
```

Expected output (the non-hex bytes `g`/`G`/`@` are wrongly accepted as chunk-size digit 16):

```
g + 16 'A'                 emitted=16 err=0 finEmpty=1 remainingUnparsed=0
1g + 32 'B'                emitted=32 err=0 finEmpty=1 remainingUnparsed=0
f + 15 'C' (valid)         emitted=15 err=0 finEmpty=1 remainingUnparsed=0
h + junk (must err)        emitted=0 err=1 finEmpty=0 remainingUnparsed=27
```

## F3 — WebSocket fragmentation opcode off-by-one (frame injection)

```
g++ -std=c++17 -I../../src -I../../uSockets/src -O2 verify_f3_ws_frame_injection.cpp -o verify_f3 && ./verify_f3
```

Expected output (a mid-fragmentation TEXT frame is correctly rejected, but an injected BINARY
frame is accepted and its payload `BBBB` is concatenated into the message):

```
inject TEXT(1)  mid-frag  (ctrl)   closed=1 reason="Received invalid WebSocket frame" assembled="AAAA" lastOpcode=1 finalDelivered=0
inject BINARY(2) mid-frag (bug)    closed=0 reason="" assembled="AAAABBBBCCCC" lastOpcode=2 finalDelivered=1
```

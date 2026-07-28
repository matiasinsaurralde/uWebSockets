#include <cstdio>
#include <cstring>
#include <vector>
#include <string>
#include "WebSocketProtocol.h"
using namespace uWS;

// Minimal Impl to drive the server-side frame parser.
struct TestImpl;
static bool g_closed = false;
static std::string g_closeReason;
static std::vector<std::pair<int,std::string>> g_messages; // (opcode, payload) — but this parser emits fragments; we track handleFragment calls
static std::string g_assembled; static int g_lastOpcode=-1; static bool g_finalDelivered=false;

struct TestImpl : WebSocketProtocol<uWS::SERVER, TestImpl> {
    static bool setCompressed(WebSocketState<uWS::SERVER>*, void*) { return false; }
    static bool refusePayloadLength(uint64_t len, WebSocketState<uWS::SERVER>*, void*) { return len > 16*1024*1024; }
    static void forceClose(WebSocketState<uWS::SERVER>*, void*, std::string_view reason={}) {
        g_closed = true; g_closeReason = std::string(reason);
    }
    // returns true on breakage
    static bool handleFragment(char* data, size_t length, unsigned int remainingBytes, int opCode, bool fin, WebSocketState<uWS::SERVER>*, void*) {
        g_assembled.append(data, length);
        g_lastOpcode = opCode;
        if (!remainingBytes && fin) { g_finalDelivered = true; }
        return false;
    }
};

// Build a masked server frame: opcode, fin, 4-byte payload masked with mask 01 02 03 04
static void appendFrame(std::string& buf, unsigned char opcode, bool fin, const char* payload4){
    unsigned char b0 = (fin?0x80:0x00) | (opcode & 0x0f);
    unsigned char mask[4] = {0x01,0x02,0x03,0x04};
    buf.push_back((char)b0);
    buf.push_back((char)(0x80 | 4)); // masked, len 4
    for(int i=0;i<4;i++) buf.push_back((char)mask[i]);
    for(int i=0;i<4;i++) buf.push_back((char)(payload4[i]^mask[i]));
}

static void runCase(const char* label, unsigned char midOpcode){
    g_closed=false; g_closeReason.clear(); g_assembled.clear(); g_lastOpcode=-1; g_finalDelivered=false;
    std::string frames;
    appendFrame(frames, 1 /*TEXT*/, false, "AAAA");     // start fragmented TEXT
    appendFrame(frames, midOpcode, false, "BBBB");       // inject a data frame mid-fragmentation
    appendFrame(frames, 0 /*CONT*/, true,  "CCCC");      // finish
    // post-pad buffer with 32 bytes (recv padding contract)
    std::vector<char> padded(frames.size()+64, 0);
    memcpy(padded.data(), frames.data(), frames.size());
    WebSocketState<uWS::SERVER> state;
    TestImpl::consume(padded.data(), (unsigned int)frames.size(), &state, nullptr);
    printf("%-34s closed=%d reason=\"%s\" assembled=\"%s\" lastOpcode=%d finalDelivered=%d\n",
        label, (int)g_closed, g_closeReason.c_str(), g_assembled.c_str(), g_lastOpcode, (int)g_finalDelivered);
}

int main(){
    runCase("inject TEXT(1) mid-frag  (ctrl)", 1); // should be REJECTED (closed=1)
    runCase("inject BINARY(2) mid-frag (bug)", 2); // BUG: should be rejected, but is accepted
    return 0;
}

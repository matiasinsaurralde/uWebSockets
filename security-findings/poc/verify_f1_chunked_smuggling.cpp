#include <cstdio>
#include <string>
#include <string_view>
#include "ChunkedEncoding.h"
using namespace uWS;
// Drive the REAL parser: return total emitted body bytes, and whether it errored.
static void run(const char* label, std::string body){
    // body is the raw chunked stream (after headers)
    std::string_view data(body);
    uint64_t state = STATE_IS_CHUNKED; // start in chunked mode like HttpParser does
    size_t emitted = 0; bool err=false, fin=false;
    for (auto chunk : uWS::ChunkIterator(&data, &state)) {
        emitted += chunk.length();
        if (chunk.length()==0) fin=true;
    }
    if (isParsingInvalidChunkedEncoding(state)) err=true;
    printf("%-26s emitted=%zu err=%d finEmpty=%d remainingUnparsed=%zu\n", label, emitted, (int)err, (int)fin, data.length());
}
int main(){
    // 'g' should be rejected by a correct hex parser; here it means size 16
    run("g + 16 'A'", std::string("g\r\n")+std::string(16,'A')+"\r\n0\r\n\r\n");
    run("1g + 32 'B'", std::string("1g\r\n")+std::string(32,'B')+"\r\n0\r\n\r\n");
    run("f + 15 'C' (valid)", std::string("f\r\n")+std::string(15,'C')+"\r\n0\r\n\r\n");
    run("h + junk (must err)", std::string("h\r\n")+std::string(17,'D')+"\r\n0\r\n\r\n");
    return 0;
}

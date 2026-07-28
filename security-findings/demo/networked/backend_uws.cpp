// Real uWebSockets HTTP back-end for the request-smuggling demo.
// Catch-all handler reports (to stderr + in the response body) exactly what
// request line + headers uWebSockets PARSED, so cross-request/user leakage is observable.
#include "App.h"
#include <string>
#include <memory>
#include <cstdio>

static int counter = 0;

int main() {
    uWS::App().any("/*", [](auto *res, auto *req) {
        int id = ++counter;
        auto d = std::make_shared<std::string>();
        // Copy out of the request buffer while it is valid.
        *d  = "req#" + std::to_string(id)
            + " method=" + std::string(req->getMethod())
            + " url=" + std::string(req->getUrl())
            + " cookie=\"" + std::string(req->getHeader("cookie")) + "\""
            + " x-smuggled=\"" + std::string(req->getHeader("x-smuggled")) + "\"";
        fprintf(stderr, "[BACKEND] PARSED  %s\n", d->c_str());
        fflush(stderr);
        res->onData([res, d](std::string_view /*chunk*/, bool isFin) {
            if (isFin) {
                res->end("BACKEND-SAW " + *d + "\n");
            }
        });
        res->onAborted([](){});
    }).listen(9001, [](auto *ls) {
        if (ls) fprintf(stderr, "[BACKEND] uWebSockets listening on 127.0.0.1:9001\n");
        else    fprintf(stderr, "[BACKEND] FAILED to listen on 9001\n");
        fflush(stderr);
    }).run();
    return 0;
}

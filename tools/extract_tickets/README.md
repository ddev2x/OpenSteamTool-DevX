# DLL interface

Build from an x64 Visual Studio developer prompt at the repository root:

    cmake -S tools -B build-tickets -A x64
    cmake --build build-tickets --config Release --target extract_tickets

Include extract_tickets.h and link extract_tickets.lib.

    TicketsResult* r = ExtractTickets(1361510);
    if (r) {
        // Copy/use r->appticket, r->eticket, r->status and r->error.
        FreeTickets(r);
    }

Ticket strings are lowercase hex, or NULL if unavailable.
Status: 0 = both tickets, 1 = partial, 2 = failure.
NULL return indicates internal/allocation failure. Free each result once.
No ticket files or console output are generated.
Steam must be running and logged in. Polling waits up to 15 seconds.
Do not call from DllMain. Calls within this DLL are serialized.
Steam context is process-wide: use a fresh process when changing AppID.
Native access violations are not caught; this change does not establish
or fix the cause of the previous Python extension crash.

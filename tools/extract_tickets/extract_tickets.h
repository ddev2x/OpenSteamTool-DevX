#pragma once
#include <stdint.h>
#ifdef EXTRACT_TICKETS_BUILD
#define TICKETS_API __declspec(dllexport)
#else
#define TICKETS_API __declspec(dllimport)
#endif
#ifdef __cplusplus
#define TICKETS_NOEXCEPT noexcept
extern "C" {
#else
#define TICKETS_NOEXCEPT
#endif
/* status: 0 = both tickets, 1 = partial, 2 = failure.
   Strings belong to the DLL and are valid until FreeTickets.
   Missing tickets are NULL. Tickets are lowercase hex strings.
   Do not modify internal. NULL result means internal/allocation failure. */
typedef struct TicketsResult {
    uint32_t appid;
    int32_t status;
    const char* appticket;
    const char* eticket;
    const char* error;
    void* internal;
} TicketsResult;
TICKETS_API TicketsResult* __cdecl ExtractTickets(uint32_t appid) TICKETS_NOEXCEPT;
TICKETS_API void __cdecl FreeTickets(TicketsResult* result) TICKETS_NOEXCEPT;
/* Same-thread diagnostic, including after ctypes catches a native fault.
   After a native fault terminate the host process; do not retry extraction. */
TICKETS_API const char* __cdecl GetTicketsLastStage(void) TICKETS_NOEXCEPT;
#ifdef __cplusplus
}
#endif

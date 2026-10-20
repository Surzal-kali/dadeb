#include <stdio.h>
#include <string.h>

typedef struct {
    char event_type[32];
    int session_id;
    char data[1024];
    size_t data_len;
} FrameworkEvent;

// This is the function Python calls via ctypes
void send_event(const FrameworkEvent *event) {
    // For now, let's just print to stdout so you can see it working in the logs
    printf("[C-SIDES] Event Received: %s | Session: %d | Data: %s\n", 
           event->event_type, 
           event->session_id, 
           event->data);
}
//to compile the code, use the following command:
// gcc -shared -o frameit.so -fPIC frameit.c
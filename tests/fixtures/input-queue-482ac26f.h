#define WINIOS_RING_SIZE 256
#define WINIOS_EV_MOUSE 0
#define WINIOS_EV_KEY   1
#define WINIOS_EV_TEXT  2
#define KEYEVENTF_KEYUP 0x0002
typedef struct {
    unsigned int type;       /* WINIOS_EV_MOUSE / WINIOS_EV_KEY */
    int x, y;                /* mouse: coords; key: x = virtual-key code */
    unsigned int flags;      /* mouse: MOUSEEVENTF_*; key: KEYEVENTF_* */
    unsigned int data;       /* mouse: mouseData (wheel delta) */
} winios_input_event_t;

static struct {
    winios_input_event_t buf[WINIOS_RING_SIZE];
    unsigned int head;       /* producer cursor (Swift side) */
    unsigned int tail;       /* consumer cursor (Wine drain) */
    pthread_mutex_t lock;
} g_input_q = { .lock = PTHREAD_MUTEX_INITIALIZER };

static void winios_q_push_ev(unsigned int type, int x, int y, unsigned int flags, unsigned int data) {
    pthread_mutex_lock(&g_input_q.lock);
    unsigned int next = (g_input_q.head + 1) % WINIOS_RING_SIZE;
    if (next != g_input_q.tail) {
        g_input_q.buf[g_input_q.head] = (winios_input_event_t){type, x, y, flags, data};
        g_input_q.head = next;
    }
    /* If buffer is full we drop the oldest event by simply not advancing —
     * better than blocking the UI thread on a Wine event drain. */
    pthread_mutex_unlock(&g_input_q.lock);
}

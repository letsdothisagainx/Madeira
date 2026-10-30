/* The embedded server shares signal dispositions with ntdll/FEX and UIKit.
 * Never replace SIGSEGV, even before ntdll has installed its handlers. A native
 * server/startup fault must retain the OS default crash disposition; later,
 * ntdll owns guest dispatch and declines foreign faults to the OS.
 * Keep the remaining upstream server signal setup unchanged.
 */
#include <signal.h>

#ifdef WINE_IOS
static int wineserver_ios_sigaction( int sig, const struct sigaction *action,
                                    struct sigaction *old_action )
{
    if (sig == SIGSEGV && action) return sigaction( sig, NULL, old_action );
    return sigaction( sig, action, old_action );
}
#define sigaction(sig, action, old_action) wineserver_ios_sigaction(sig, action, old_action)
#endif

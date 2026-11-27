# ``lib`` is the C event-gate handle from thebrain (framework event forward).
# It is None on trees without the gitignored frameit.so build artifact
# (fresh checkouts, CI runners) — consumers must tolerate both;
# thebrain._send_event_to_c() is the guarded forward path.
from listeners.thebrain import FrameworkEvent, lib, start_brain
from listeners.listening import TCPListener
from listeners.thebrain import EVENT_HANDLERS




__all__ = ['FrameworkEvent', 'lib', 'start_brain', 'EVENT_HANDLERS', 'TCPListener', 'FrameworkEvent']
"""
Simply the same as aiosmtpd.controller
by Barry Warsaw <barry@python.org>
"""

import asyncio
import threading

from aiopop3.server import POP3ServerProtocol


class Controller:
    def __init__(self, handler, loop=None, hostname=None, port=8110):
        self.handler = handler
        self.server = None
        self.hostname = '::1' if hostname is None else hostname
        self.port = port
        self.loop = asyncio.new_event_loop() if loop is None else loop
        self.thread = None
        # For exiting the loop.
        self._rsock, self._wsock = self.loop._socketpair()

    def _reader(self):
        self.loop.remove_reader(self._rsock)
        self.loop.stop()
        for task in asyncio.Task.all_tasks(self.loop):
            task.cancel()
        self._rsock.close()
        self._wsock.close()

    def factory(self):
        """Allow subclasses to customize the handler/server creation."""
        return POP3ServerProtocol(self.handler)

    def _run(self, ready_event):
        asyncio.set_event_loop(self.loop)
        self.loop.add_reader(self._rsock, self._reader)
        server = self.loop.run_until_complete(
            self.loop.create_server(
                self.factory, host=self.hostname, port=self.port))
        self.loop.call_soon(ready_event.set)
        self.loop.run_forever()
        server.close()
        self.loop.run_until_complete(server.wait_closed())
        self.loop.close()

    def start(self):
        assert self.thread is None, 'SMTP daemon already running'
        ready_event = threading.Event()
        self.thread = threading.Thread(target=self._run, args=(ready_event,))
        self.thread.daemon = True
        self.thread.start()
        # Wait a while until the server is responding.
        ready_event.wait()

    def stop(self):
        assert self.thread is not None, 'SMTP daemon not running'
        self._wsock.send(b'x')
        self.thread.join()

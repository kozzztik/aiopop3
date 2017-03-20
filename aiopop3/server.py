"""A POP3 server class.

Author: Konstantin Volkov <kozzztik@mail.ru>
Based on aiosmtpd

Implements:

RFC 1939 Post Office Protocol - Version 3
https://tools.ietf.org/html/rfc1939

RFC 2449 POP3 Extension Mechanism
https://tools.ietf.org/html/rfc2449

RFC 2595 Using TLS with IMAP, POP3 and ACAP
https://tools.ietf.org/html/rfc2595

RFC 3206 The SYS and AUTH POP Response Codes
https://tools.ietf.org/html/rfc3206

RFC 1734 POP3 AUTHentication command
https://tools.ietf.org/html/rfc1734

RFC 2222 Simple Authentication and Security Layer (SASL)
https://tools.ietf.org/html/rfc2222

RFC 5034 The Post Office Protocol (POP3) Simple Authentication and Security
Layer (SASL) Authentication Mechanism
https://tools.ietf.org/html/rfc5034

RFC 4616 The PLAIN Simple Authentication and Security Layer (SASL) Mechanism
https://tools.ietf.org/html/rfc4616

"""

import os
import re
import time
import base64
import socket
import asyncio
import logging
import hashlib

from .base_handler import BaseHandler
from .exceptions import (
    POP3Exception,
    BaseCodedException,
    AuthFailed,
)

try:
    import ssl
    from asyncio import sslproto
except ImportError:
    _has_ssl = False
else:
    _has_ssl = sslproto and hasattr(ssl, 'MemoryBIO')


__version__ = '0.1'
__ident__ = 'Python-aiopop3-{}'.format(__version__)

log = logging.getLogger('server.pop3')


def _quote_periods(bindata):
    return re.sub(br'(?m)^\.', b'..', bindata)


class POP3ServerProtocol(asyncio.StreamReaderProtocol):
    command_size_limit = 255  # RFC 2449 p.4

    def __init__(self, handler,
                 *,
                 hostname=None,
                 tls_context=None,
                 require_starttls=False,
                 timeout=600,
                 loop=None):
        self.loop = loop if loop else asyncio.get_event_loop()
        reader = asyncio.StreamReader(
            loop=self.loop, limit=self.command_size_limit)
        super().__init__(reader, loop=self.loop)
        assert isinstance(handler, BaseHandler)
        self.handler = handler  # type: BaseHandler
        hostname = hostname or socket.getfqdn()
        self.tls_context = tls_context
        if tls_context:
            self.tls_context.check_hostname = False
            self.tls_context.verify_mode = ssl.CERT_NONE
        self.require_starttls = tls_context and require_starttls
        self._tls_handshake_failed = False
        self._tls_protocol = None
        self.transport = None
        self._handler_coroutine = None
        self._mail_box = None
        self._messages = None
        self._message_ids = None
        self._deleted_messages = []
        self._read_messages = []
        self._auth_passed = False
        self._user_name = None  # for USER/PASS auth
        self._timeout = timeout
        self._greeting = '<{}.{}@{}>'.format(
            os.getpid(), time.monotonic(), hostname)
        self.__ident__ = __ident__
        self.auth_mechanizms = ['PLAIN']
        self.peer = None
        self._over_ssl = False

    def connection_made(self, transport):
        is_instance = (_has_ssl and
                       isinstance(transport, sslproto._SSLProtocolTransport))
        if self.transport is not None and is_instance:   # pragma: nossl
            # It is STARTTLS connection over normal connection.
            self._stream_reader._transport = transport
            self._stream_writer._transport = transport
            self.transport = transport
            # Why _extra is protected attribute?
            extra = self._tls_protocol._extra
            auth = self.handler.handle_tls_handshake(
                extra['ssl_object'],
                extra['peercert'],
                extra['cipher'])
            self._tls_handshake_failed = not auth
            self._over_ssl = True
            self._user_name = None
        else:
            super().connection_made(transport)
            # TODO context for auth
            self.peer = transport.get_extra_info('peername')
            self.transport = transport
            log.info('Peer: %s', repr(self.peer))
            # Process the client's requests.
            self._stream_writer = asyncio.StreamWriter(
                transport, self, self._stream_reader, self._loop)
            self._handler_coroutine = self.loop.create_task(
                self._handle_client())

    @asyncio.coroutine
    def push(self, msg):
        response = bytes(msg + '\r\n', 'utf-8')
        self._stream_writer.write(response)
        log.debug(msg)
        yield from self._stream_writer.drain()

    @asyncio.coroutine
    def _read_line(self):
        line = yield from asyncio.wait_for(
            self._stream_reader.readline(),
            self._timeout,
            loop=self.loop)
        if not line:
            raise asyncio.IncompleteReadError(line, None)
        return line.decode('utf-8').rstrip('\r\n')

    @asyncio.coroutine
    def _handle_client(self):
        log.info('handling connection')
        yield from self.push(
            '+OK POP3 server ready {}'.format(self._greeting))
        while not self._stream_reader.at_eof():
            # XXX Put the line limit stuff into the StreamReader?
            try:
                line = yield from self._read_line()
            except TimeoutError:
                log.info('Close session by timeout')
                self.close()
                return
            try:
                log.info('Data: %r', line)
                if not line:
                    yield from self.push('-ERR bad syntax')
                    continue
                i = line.find(' ')
                if i < 0:
                    command = line.upper()
                    arg = None
                else:
                    command = line[:i].upper()
                    arg = line[i+1:].strip()
                if (self._tls_handshake_failed
                        and command not in ['CAPA', 'QUIT']):  # pragma: nossl
                    yield from self.push(
                        '-ERR Command refused due to lack of security')
                    continue
                if (self.require_starttls
                        and (not self._tls_protocol)
                        and (command not in ['STLS', 'CAPA', 'QUIT'])):
                    # RFC2595 part 2.2
                    yield from self.push(
                        '-ERR Must issue a STLS command first')
                    continue
                method = getattr(self, 'pop_' + command, None)
                if not method:
                    yield from self.push(
                        '-ERR command "%s" not recognized' % command)
                    continue
                yield from method(arg)
            except BaseCodedException as error:
                yield from self.push('-ERR [{}] {}'.format(
                    error.code, error.message))
            except POP3Exception as error:
                yield from self.push('-ERR {}'.format(error.message))
            except Exception as error:
                yield from self.push('-ERR [SYS/TEMP] ({}) {}'.format(
                    error.__class__.__name__, str(error)))
                log.exception('POP3 session exception')
                yield from self.handler.handle_exception(error)

    @asyncio.coroutine
    def close(self):
        # XXX this close is probably not quite right.
        if self._stream_writer:
            self._stream_writer.close()

    @asyncio.coroutine
    def commit_transaction(self):
        if self._mail_box and self._auth_passed:
            nums = self._deleted_messages
            if self._mail_box.retention_period == 0:
                for i in self._read_messages:
                    if i not in nums:
                        nums.append(i)
            msgs = [self._messages[i] for i in self._deleted_messages]
            yield from self._mail_box.delete_messages(msgs)
            yield from self._mail_box.commit()
            self._deleted_messages = []
            self._read_messages = []
            self._messages = None

    @asyncio.coroutine
    def _load_messages(self):
        if not self._auth_passed:
            raise POP3Exception('Authorization required')
        if self._messages is not None:
            return
        self._messages = yield from self._mail_box.get_messages()
        assert isinstance(self._messages, list)
        self._message_ids = {}
        for i, message in enumerate(self._messages):
            self._message_ids[str(message.message_id)] = i

    def _get_message_by_num(self, arg):
        try:
            arg = int(arg)
        except ValueError:
            raise POP3Exception('Syntax: Message number must be integer')
        if arg > len(self._messages) or arg < 1:
            raise POP3Exception('No such message')
        if arg in self._deleted_messages:
            raise POP3Exception('Message deleted')
        return arg - 1, self._messages[arg - 1]

    @asyncio.coroutine
    def capa_hook(self):
        """Allow subclasses to extend CAPA responses.

        This hook is called just before the final, non-continuing "."
        response.  Subclasses can add additional to declare new capabilities
        """
        pass

    @asyncio.coroutine
    def pop_CAPA(self, arg):
        yield from self.push('+OK Capability list follows')
        if self.tls_context and not self._tls_protocol:
            yield from self.push('STLS')
        auth = not self._auth_passed
        if self._tls_protocol and self._tls_handshake_failed:
            auth = False
        if self.require_starttls and not self._tls_protocol:
            auth = False
        if auth:
            yield from self.push('USER')
            if self.auth_mechanizms:
                yield from self.push('SASL {}'.format(
                    ' '.join(self.auth_mechanizms)))
        if self._auth_passed:
            yield from self.push('TOP')
            yield from self.push('UIDL')
            retention_period = self._mail_box.retention_period
            if retention_period is None:
                retention_period = 'NEVER'
            yield from self.push('EXPIRE {}'.format(retention_period))
            yield from self.push('LOGIN-DELAY {}'.format(
                self._mail_box.login_delay))
        else:
            yield from self.push('EXPIRE {} USER'.format(
                self.handler.retention_period))
            yield from self.push('LOGIN-DELAY {}'.format(
                self.handler.login_delay))
        # TODO Not really capable in sending responses, but must work
        yield from self.push('RESP-CODES')
        yield from self.push('AUTH-RESP-CODE')
        yield from self.push('PIPELINING')
        if self.__ident__:
            yield from self.push('IMPLEMENTATION {}'.format(self.__ident__))
        yield from self.capa_hook()
        yield from self.push('.')

    @asyncio.coroutine
    def pop_APOP(self, arg):
        if not arg or ' ' not in arg:
            raise POP3Exception('Syntax: APOP <user_name> <password_hash>')
        if self._auth_passed:
            raise POP3Exception('Already authenticated')
        user_name, user_hash = arg.split(' ', maxsplit=1)
        mail_box = yield from self.handler.handle_user(user_name)
        if not mail_box:
            raise AuthFailed()
        try:
            password = yield from mail_box.get_password()  # type: str
            digest = bytes(self._greeting + password, encoding='utf-8')
            digest_str = hashlib.md5(digest).hexdigest()
            if user_hash != digest_str:
                raise AuthFailed()
        except Exception:
            yield from mail_box.rollback()
            raise
        self._mail_box = mail_box
        self._auth_passed = True
        yield from self.push('+OK maildrop locked and ready')

    @asyncio.coroutine
    def pop_USER(self, arg):
        if not arg:
            raise POP3Exception('Syntax: USER <name>')
        self._user_name = arg
        yield from self.push('+OK name is a valid mailbox')

    @asyncio.coroutine
    def pop_PASS(self, arg):
        if not arg:
            raise POP3Exception('Syntax: PASS <password>')
        if self._user_name is None:
            raise POP3Exception('USER command first')
        if self._auth_passed:
            raise POP3Exception('Already authenticated')
        mail_box = yield from self.handler.handle_user(self._user_name)
        if not mail_box:
            raise AuthFailed()
        try:
            yield from mail_box.check_password(arg)
        except Exception:
            yield from mail_box.rollback()
            raise
        self._mail_box = mail_box
        self._auth_passed = True
        yield from self.push('+OK maildrop locked and ready')

    @asyncio.coroutine
    def pop_DELE(self, arg):
        if not self._auth_passed:
            raise POP3Exception('Authorization required')
        if not arg:
            raise POP3Exception('Syntax: DELE <message_id>')
        yield from self._load_messages()
        arg, _ = self._get_message_by_num(arg)
        self._deleted_messages.append(arg)
        yield from self.push('+OK message deleted')

    def _get_stat(self):
        count = 0
        size = 0
        for i, message in enumerate(self._messages):
            if i not in self._deleted_messages:
                count += 1
                size += message.size
        return count, size

    @asyncio.coroutine
    def pop_LIST(self, arg):
        yield from self._load_messages()
        if arg:
            arg, message = self._get_message_by_num(arg)
            yield from self.push('+OK {} ({} octets)'.format(
                arg + 1, message.size))
        else:
            count, size = self._get_stat()
            yield from self.push(
                '+OK {} messages ({} octets)'.format(count, size))
            for i, message in enumerate(self._messages):
                if i not in self._deleted_messages:
                    yield from self.push('{} {}'.format(i + 1, message.size))
            yield from self.push('.')

    @asyncio.coroutine
    def pop_NOOP(self, arg):
        if arg:
            raise POP3Exception('Syntax: NOOP')
        yield from self.push('+OK')

    @asyncio.coroutine
    def pop_RSET(self, arg):
        if not self._auth_passed:
            raise POP3Exception('Authorization required')
        yield from self._mail_box.rollback()
        self._deleted_messages = []
        yield from self.push('+OK')

    @asyncio.coroutine
    def pop_STAT(self, arg):
        if arg:
            raise POP3Exception('Syntax: STAT')
        yield from self._load_messages()
        count, size = self._get_stat()
        yield from self.push('+OK {} {}'.format(count, size))

    @asyncio.coroutine
    def pop_TOP(self, arg):
        if not arg or ' ' not in arg:
            raise POP3Exception('Syntax: TOP <message_id> <lines_count>')
        num, lines_count = arg.split(' ', maxsplit=1)
        try:
            lines_count = int(lines_count)
        except ValueError:
            raise POP3Exception('Syntax: Lines count must be integer')
        yield from self._load_messages()
        arg, message = self._get_message_by_num(num)
        data = yield from message.get_data()
        in_headers = True
        i = 0
        for line in data.splitlines(keepends=True):
            # Dump the RFC 2822 headers first.
            if in_headers:
                if not line:
                    in_headers = False
            else:
                i += 1
                if i > lines_count:
                    break
            self._stream_writer.write(_quote_periods(line))
            yield from self._stream_writer.drain()
        self._stream_writer.write(b'\r\n.\r\n')
        log.info('Message %s (%s) %s first lines send',
                 arg, message.message_id, lines_count)
        yield from self._stream_writer.drain()

    @asyncio.coroutine
    def pop_RETR(self, arg):
        yield from self._load_messages()
        arg, message = self._get_message_by_num(arg)
        yield from self.push('+OK {} octets'.format(message.size))
        data = yield from message.get_data()
        self._stream_writer.write(_quote_periods(data))
        self._stream_writer.write(b'\r\n.\r\n')
        log.info('Message %s (%s) is send', arg, message.message_id)
        yield from self._stream_writer.drain()
        if arg not in self._read_messages:
            self._read_messages.append(arg)

    @asyncio.coroutine
    def pop_QUIT(self, arg):
        if arg:
            raise POP3Exception('Syntax: QUIT')
        yield from self.commit_transaction()
        yield from self.push('+OK Bye')
        # To prevent rollback on close
        self._auth_passed = False
        self._handler_coroutine.cancel()
        self.transport.close()

    @asyncio.coroutine
    def pop_STLS(self, arg):  # pragma: nossl
        log.info('STARTTLS')
        if arg:
            raise POP3Exception('Syntax: STARTTLS')
        if not (self.tls_context and _has_ssl):
            raise POP3Exception('TLS not available')
        if self._auth_passed:
            # RFC 2595 4
            raise POP3Exception(
                'Command is only valid in non-authenticated state')
        yield from self.push('+OK Begin TLS negotiation')
        # Create SSL layer.
        self._tls_protocol = sslproto.SSLProtocol(
            self.loop,
            self,
            self.tls_context,
            None,
            server_side=True)
        # Reconfigure transport layer.
        socket_transport = self.transport
        socket_transport._protocol = self._tls_protocol
        # Reconfigure protocol layer. Cant understand why app transport is
        # protected property, if it MUST be used externally.
        self.transport = self._tls_protocol._app_transport
        # Start handshake.
        self._tls_protocol.connection_made(socket_transport)

    @asyncio.coroutine
    def pop_UIDL(self, arg):
        yield from self._load_messages()
        if arg:
            arg, message = self._get_message_by_num(arg)
            yield from self.push('+OK {} {}'.format(arg, message.message_id))
        else:
            yield from self.push('+OK')
            for i, message in enumerate(self._messages):
                yield from self.push('{} {}'.format(i, message.message_id))
            yield from self.push('.')

    @asyncio.coroutine
    def pop_AUTH(self, arg):
        if not arg:
            raise POP3Exception('Unrecognized authentication type')
        if ' ' in arg:
            name, initial = arg.split(' ', maxsplit=1)
        else:
            name = arg.upper()
            initial = None
        if name not in self.auth_mechanizms:
            raise POP3Exception('Unrecognized authentication type')
        if self._auth_passed:
            raise POP3Exception('Already authenticated')
        method = getattr(self, 'auth_' + name, None)
        if not method:
            raise POP3Exception('[SYS/PERM] Authentication type not supported')
        mail_box = yield from method(initial)
        if not mail_box:
            raise AuthFailed()
        self._auth_passed = True
        self._mail_box = mail_box
        yield from self.push('+OK {} authentication successful'.format(name))

    @asyncio.coroutine
    def auth_PLAIN(self, arg):
        if not arg:
            yield from self.push('+')
            arg = yield from self._read_line()
        arg = base64.b64decode(arg)
        params = arg.split(b'\x00')
        _, authcid, passwd = [p.decode('utf-8') for p in params]
        mail_box = yield from self.handler.handle_user(authcid)
        if not mail_box:
            return
        try:
            yield from mail_box.check_password(passwd)
        except Exception:
            yield from mail_box.rollback()
            raise
        return mail_box

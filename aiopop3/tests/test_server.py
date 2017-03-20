import asyncio
import unittest

from poplib import POP3 as OldPOP3, error_proto

from aiopop3.controller import Controller
from aiopop3.handlers import MemoryHandler


class POP3(OldPOP3):
    def __enter__(self):
        return self

    def __exit__(self, *args):
        try:
            self.quit()
        finally:
            self.close()


class TestPOP3(unittest.TestCase):
    def setUp(self):
        loop = asyncio.get_event_loop()
        self.handler = MemoryHandler(loop)
        self.user_name = 'admin'
        self.password = 'password'
        self.user = self.handler.add_user(self.user_name, self.password)
        self.user.add_email('email1\r\n\r\nfirst text')
        self.user.add_email('email1\r\n\r\nsecond text')
        controller = Controller(self.handler)
        controller.start()
        self.addCleanup(controller.stop)
        self.address = (controller.hostname, controller.port)

    def test_capa(self):
        with POP3(*self.address) as client:
            caps = client.capa()
            self.assertIn('SASL', caps)
            self.assertIn('IMPLEMENTATION', caps)
            self.assertIn('RESP-CODES', caps)
            self.assertIn('PIPELINING', caps)
            self.assertIn('LOGIN-DELAY', caps)
            self.assertIn('AUTH-RESP-CODE', caps)
            self.assertIn('EXPIRE', caps)
            self.assertIn('USER', caps)
            self.assertNotIn('TOP', caps)
            self.assertNotIn('UIDL', caps)
            self.assertListEqual(caps['SASL'], ['PLAIN'])

    def test_apop(self):
        with POP3(*self.address) as client:
            response = client.apop(self.user_name, self.password)
            self.assertEqual(response, b'+OK maildrop locked and ready')
            with self.assertRaises(error_proto) as e:
                client.apop(self.user_name, self.password)
            msg = e.exception.args[0]
            self.assertEqual(msg, b'-ERR Already authenticated')

    def test_apop_no_arg(self):
        with POP3(*self.address) as client:
            client._putcmd('APOP')
            response, _ = client._getline()
            self.assertEqual(
                response, b'-ERR Syntax: APOP <user_name> <password_hash>')

    def test_apop_one_arg(self):
        with POP3(*self.address) as client:
            client._putcmd('APOP admin')
            response, _ = client._getline()
            self.assertEqual(
                response, b'-ERR Syntax: APOP <user_name> <password_hash>')

    def test_apop_unknown_user(self):
        with POP3(*self.address) as client:
            with self.assertRaises(error_proto) as e:
                client.apop('foobar', self.password)
            msg = e.exception.args[0]
            self.assertEqual(msg, b'-ERR [AUTH] Invalid password')

    def test_apop_invalid_password(self):
        with POP3(*self.address) as client:
            with self.assertRaises(error_proto) as e:
                client.apop(self.user_name, 'foobar')
            msg = e.exception.args[0]
            self.assertEqual(msg, b'-ERR [AUTH] Invalid password')

    def test_capa_after_auth(self):
        with POP3(*self.address) as client:
            client.apop(self.user_name, self.password)
            caps = client.capa()
            self.assertNotIn('SASL', caps)
            self.assertIn('IMPLEMENTATION', caps)
            self.assertIn('RESP-CODES', caps)
            self.assertIn('PIPELINING', caps)
            self.assertIn('LOGIN-DELAY', caps)
            self.assertIn('AUTH-RESP-CODE', caps)
            self.assertIn('EXPIRE', caps)
            self.assertNotIn('USER', caps)
            self.assertIn('TOP', caps)
            self.assertIn('UIDL', caps)

    def test_user(self):
        with POP3(*self.address) as client:
            response = client.user('foobar')
            self.assertEqual(response, b'+OK name is a valid mailbox')

    def test_pass_no_arg(self):
        with POP3(*self.address) as client:
            with self.assertRaises(error_proto) as e:
                client._shortcmd('PASS')
            msg = e.exception.args[0]
            self.assertEqual(msg, b'-ERR Syntax: PASS <password>')

    def test_pass_no_user(self):
        with POP3(*self.address) as client:
            with self.assertRaises(error_proto) as e:
                client.pass_(self.password)
            msg = e.exception.args[0]
            self.assertEqual(msg, b'-ERR USER command first')

    def test_pass(self):
        with POP3(*self.address) as client:
            client.user(self.user_name)
            msg = client.pass_(self.password)
            self.assertEqual(msg, b'+OK maildrop locked and ready')
            with self.assertRaises(error_proto) as e:
                client.pass_(self.password)
            msg = e.exception.args[0]
            self.assertEqual(msg, b'-ERR Already authenticated')

    def test_pass_unknown_user(self):
        with POP3(*self.address) as client:
            client.user('foobar')
            with self.assertRaises(error_proto) as e:
                client.pass_(self.password)
            msg = e.exception.args[0]
            self.assertEqual(msg, b'-ERR [AUTH] Invalid password')

    def test_pass_invalid_password(self):
        with POP3(*self.address) as client:
            client.user(self.user_name)
            with self.assertRaises(error_proto) as e:
                client.pass_('foobar')
            msg = e.exception.args[0]
            self.assertEqual(msg, b'-ERR [AUTH] Invalid password')

    def test_list_all(self):
        with POP3(*self.address) as client:
            client.apop(self.user_name, self.password)
            resp, msgs, _ = client.list()
            self.assertEqual(resp, b'+OK 2 messages (41 octets)')
            self.assertListEqual(msgs, [b'1 20', b'2 21'])

    def test_list_message(self):
        with POP3(*self.address) as client:
            client.apop(self.user_name, self.password)
            response = client.list(1)
            self.assertEqual(response, b'+OK 1 (20 octets)')

    def test_list_syntax(self):
        with POP3(*self.address) as client:
            client.apop(self.user_name, self.password)
            with self.assertRaises(error_proto) as e:
                client.list('foobar')
            msg = e.exception.args[0]
            self.assertEqual(
                msg, b'-ERR Syntax: Message number must be integer')

    def test_list_unknown_message(self):
        with POP3(*self.address) as client:
            client.apop(self.user_name, self.password)
            with self.assertRaises(error_proto) as e:
                client.list(3)
            msg = e.exception.args[0]
            self.assertEqual(msg, b'-ERR No such message')

    def test_list_no_auth(self):
        with POP3(*self.address) as client:
            with self.assertRaises(error_proto) as e:
                client.list(0)
            msg = e.exception.args[0]
            self.assertEqual(msg, b'-ERR Authorization required')

    def test_list_dublicate(self):
        with POP3(*self.address) as client:
            client.apop(self.user_name, self.password)
            client.list()
            resp, msgs, _ = client.list()
            self.assertEqual(resp, b'+OK 2 messages (41 octets)')
            self.assertListEqual(msgs, [b'1 20', b'2 21'])

    def test_dele_no_auth(self):
        with POP3(*self.address) as client:
            with self.assertRaises(error_proto) as e:
                client.dele(0)
            msg = e.exception.args[0]
            self.assertEqual(msg, b'-ERR Authorization required')

    def test_dele_no_arg(self):
        with POP3(*self.address) as client:
            client.apop(self.user_name, self.password)
            with self.assertRaises(error_proto) as e:
                client._shortcmd('DELE')
            msg = e.exception.args[0]
            self.assertEqual(msg, b'-ERR Syntax: DELE <message_id>')

    def test_dele(self):
        with POP3(*self.address) as client:
            client.apop(self.user_name, self.password)
            resp = client.dele(1)
            self.assertEqual(resp, b'+OK message deleted')
            resp, msgs, _ = client.list()
            self.assertEqual(resp, b'+OK 1 messages (21 octets)')
            self.assertListEqual(msgs, [b'2 21'])
            self.assertEqual(len(self.user.mail_box), 2)
        self.assertEqual(len(self.user.mail_box), 1)

    def test_noop(self):
        with POP3(*self.address) as client:
            response = client.noop()
            self.assertEqual(response, b'+OK')

    def test_rset(self):
        with POP3(*self.address) as client:
            client.apop(self.user_name, self.password)
            resp = client.dele(1)
            self.assertEqual(resp, b'+OK message deleted')
            resp = client.list()[0]
            self.assertEqual(resp, b'+OK 1 messages (21 octets)')
            resp = client.rset()
            self.assertEqual(resp, b'+OK')
            resp = client.list()[0]
            self.assertEqual(resp, b'+OK 2 messages (41 octets)')
        self.assertEqual(len(self.user.mail_box), 2)

    def test_rset_no_auth(self):
        with POP3(*self.address) as client:
            with self.assertRaises(error_proto) as e:
                client.rset()
            msg = e.exception.args[0]
            self.assertEqual(msg, b'-ERR Authorization required')

    def test_stat_no_auth(self):
        with POP3(*self.address) as client:
            with self.assertRaises(error_proto) as e:
                client.stat()
            msg = e.exception.args[0]
            self.assertEqual(msg, b'-ERR Authorization required')

    def test_stat_syntax(self):
        with POP3(*self.address) as client:
            with self.assertRaises(error_proto) as e:
                client._shortcmd('STAT 1')
            msg = e.exception.args[0]
            self.assertEqual(msg, b'-ERR Syntax: STAT')

    def test_stat(self):
        with POP3(*self.address) as client:
            client.apop(self.user_name, self.password)
            count, size = client.stat()
            self.assertEqual(count, 2)
            self.assertEqual(size, 41)

    def test_top_syntax(self):
        with POP3(*self.address) as client:
            with self.assertRaises(error_proto) as e:
                client._shortcmd('TOP')
            msg = e.exception.args[0]
            self.assertEqual(msg,
                             b'-ERR Syntax: TOP <message_id> <lines_count>')

    def test_top_str_lines(self):
        with POP3(*self.address) as client:
            with self.assertRaises(error_proto) as e:
                client._shortcmd('TOP 1 foo')
            msg = e.exception.args[0]
            self.assertEqual(msg,
                             b'-ERR Syntax: Lines count must be integer')

    def test_top_no_auth(self):
        with POP3(*self.address) as client:
            with self.assertRaises(error_proto) as e:
                client.top(1, 1)
            msg = e.exception.args[0]
            self.assertEqual(msg, b'-ERR Authorization required')

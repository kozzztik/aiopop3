import asyncio

from .exceptions import AuthNotSupported


class POP3Message:
    def __init__(self, message_id, size):
        self.message_id = message_id
        self.size = size

    @asyncio.coroutine
    def get_data(self):
        return b''


class MailBox:
    def __init__(self, user_name, loop):
        self.user_name = user_name
        self.loop = loop

    @asyncio.coroutine
    def acquire_lock(self):
        """
        Get lock over maildrop. If mailbox doesn`t exist return None. If lock
        acqired return self. In other cases raise exception.
        :return:
        """
        return self

    @asyncio.coroutine
    def commit(self):
        """ Release lock and commit transaction """
        pass

    @asyncio.coroutine
    def rollback(self):
        """ Release lock and rollback transaction """
        pass

    @property
    def retention_period(self):
        """
        Return retention period by RFC 2449 p 6.7 in days
        None means mail never deleted by server, 0 - deleted after RETR
        Note that 0 will trigger protocol to delete readed messages as if they
        were deleted by user, so you don`t need to care about it.
        :return int:
        """
        return None

    @property
    def login_delay(self):
        """
        Delay between successfull login attempts depended on user by
        RFC 2449 p 6.5
        :return int:
        """
        return 0

    @asyncio.coroutine
    def get_password(self):
        """
        Returns user password for APOP auth. You must implement either this or
        check passord method
        :return str: user password
        """
        raise AuthNotSupported()

    @asyncio.coroutine
    def check_password(self, password):
        """
        Returns user password for USER/PASS auth. You must implement either
        this or get password method.
        :return bool: True if check passed
        """
        raise AuthNotSupported()

    @asyncio.coroutine
    def get_messages(self):
        """
        Get all messages from mailbox. If there are to many messages to store
        their information in memory it is up to you to limit them by RFC 1939
        "8. Scaling and Operational Considerations"
        :return list: list of messages
        """
        raise NotImplementedError()

    @asyncio.coroutine
    def delete_messages(self, messages):
        """
        Deletes messages from mailbox
        :param list messages: List of POP3 messages to delete
        :return:
        """
        raise NotImplementedError()


class BaseHandler:
    mail_box_class = MailBox

    def __init__(self, loop):
        self.loop = loop
        # This is default parameters declared in CAPA in authentication state
        self.retention_period = 0
        self.login_delay = 0

    def handle_tls_handshake(self, ssl_object, peercert, cipher):
        """
        Handle SMTP STARTTLS certificates handshake
        :param ssl_object:
        :param peercert:
        :param cipher:
        :return bool: True if successful, False if failed.
        """
        return True

    @asyncio.coroutine
    def handle_exception(self, error):
        """
        Handle exceptions during SMTP session
        :param Exception error: Unhandled exception
        :return:
        """
        pass

    @asyncio.coroutine
    def handle_user(self, user_name):
        """
        Get mailbox with lock. If it doesn`t exist return None.
        :param str user_name: Client provided user name
        :return MailBox: mail box object to handle user.
        """
        box = self.mail_box_class(user_name, self.loop)
        box = yield from box.acquire_lock()
        return box

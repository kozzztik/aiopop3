import asyncio


class POP3Exception(Exception):
    """
    Some handlers methods are not able to return response string and handle
    error by method return value. Raise this exception to indicate error and
    provide response code and message.
    """
    def __init__(self, message):
        super(POP3Exception, self).__init__(message)
        self.message = message


class POP3AuthNotSupported(POP3Exception):
    def __init__(self):
        super(POP3AuthNotSupported, self).__init__('Auth method not supported')


class POP3AuthFailed(POP3Exception):
    """
    As said in RFC 1939 "13. Security Considerations" return invalid password
    in all auth failed cases such as "no user mailbox"
    """
    def __init__(self):
        super(POP3AuthFailed, self).__init__('Invalid password')


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
    def remove_readed(self):
        """
        Return true if needed to remove readed messages as said in RFC 1939
        "8. Scaling and Operational Considerations"
        :return bool:
        """
        return False

    @asyncio.coroutine
    def get_password(self):
        """
        Returns user password for APOP auth. You must implement either this or
        check passord method
        :return str: user password
        """
        raise POP3AuthNotSupported()

    @asyncio.coroutine
    def check_password(self, password):
        """
        Returns user password for USER/PASS auth. You must implement either
        this or get password method.
        :return bool: True if check passed
        """
        raise POP3AuthNotSupported()

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

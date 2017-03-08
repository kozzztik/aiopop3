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
    def mail_box_exist(self):
        return bool(self.user_name)

    @asyncio.coroutine
    def get_password(self):
        return ''

    @asyncio.coroutine
    def commit(self):
        pass

    @asyncio.coroutine
    def rollback(self):
        pass

    @asyncio.coroutine
    def get_message(self, message_id):
        return None

    @asyncio.coroutine
    def get_all_messages(self):
        return []

    @asyncio.coroutine
    def message_exists(self, message_id):
        return bool(message_id)

    @asyncio.coroutine
    def delete_message(self, message_id):
        pass


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
        Handle start of authorization
        :param str user_name: Client provided user name
        :return MailBox: mail box object to handle user.
        """
        return self.mail_box_class(user_name, self.loop)

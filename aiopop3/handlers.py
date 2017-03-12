import uuid
import asyncio

from .base_handler import POP3Message, BaseHandler, MailBox
from .exceptions import AuthInUseException, AuthFailed


class SimpleMessage(POP3Message):
    def __init__(self, data):
        if not isinstance(data, bytes):
            data = bytes(data, 'utf8')
        super(SimpleMessage, self).__init__(uuid.uuid4(), len(data))
        self.data = data

    @asyncio.coroutine
    def get_data(self):
        return self.data


class MemoryUser:
    def __init__(self, name, password):
        self.name = name
        self.password = password
        self.mail_box = []
        self.locked = False

    def add_email(self, data):
        self.mail_box.append(SimpleMessage(data))


class MemoryMailBox(MailBox):
    def __init__(self, user, loop):
        self.user = user
        super(MemoryMailBox, self).__init__(user.name, loop)

    @asyncio.coroutine
    def acquire_lock(self):
        if self.user.locked:
            raise AuthInUseException
        self.user.locked = True
        return self

    @asyncio.coroutine
    def commit(self):
        self.user.locked = False

    @asyncio.coroutine
    def rollback(self):
        self.user.locked = False

    @asyncio.coroutine
    def check_password(self, password):
        if self.user.password != password:
            raise AuthFailed

    @asyncio.coroutine
    def get_password(self):
        return self.user.password

    @asyncio.coroutine
    def get_messages(self):
        return self.user.mail_box

    @asyncio.coroutine
    def delete_messages(self, del_messages):
        for m in del_messages:
            self.user.mail_box.remove(m)


class MemoryHandler(BaseHandler):
    mail_box_class = MemoryMailBox

    def __init__(self, loop):
        super(MemoryHandler, self).__init__(loop)
        self.users = {}

    def add_user(self, name, password):
        user = MemoryUser(name, password)
        self.users[name] = user
        return user

    @asyncio.coroutine
    def handle_user(self, user_name):
        if user_name not in self.users:
            return None
        box = self.mail_box_class(self.users[user_name], self.loop)
        box = yield from box.acquire_lock()
        return box

class POP3Exception(Exception):
    """
    Some handlers methods are not able to return response string and handle
    error by method return value. Raise this exception to indicate error and
    provide response message.
    """
    def __init__(self, message):
        super(POP3Exception, self).__init__(message)
        self.message = message


class BaseCodedException(POP3Exception):
    """ Raise ancestor of this class to indicate error with response code """
    code = None
    message = None

    def __init__(self, message=None):
        message = message or self.message
        assert message is not None
        super(BaseCodedException, self).__init__(message)


class TempException(BaseCodedException):
    """
    Temporary system exception due to RFC 3206 p. 4
    indicates a problem which is likely to be temporary in nature, and
    therefore there is no need to alarm the user, unless the failure
    persists.  Examples might include a central resource which is currently
    locked or otherwise temporarily unavailable, insufficient free disk or
    memory, etc.
    """
    code = 'SYS/TEMP'


class PermException(BaseCodedException):
    """
    Permanent system exception due to RFC 3206 p. 4
    Indicates problems which are unlikely to be resolved
    without intervention.  It is appropriate to alert the user and
    suggest that the organization's support or assistance personnel be
    contacted.  Examples include corrupted mailboxes, system
    configuration errors, etc.
    """
    code = 'SYS/PERM'


class AuthNotSupported(BaseCodedException):
    """ Login method not supported """
    code = 'SYS/PERM'
    message = 'Auth method not supported'


class AuthFailed(BaseCodedException):
    """
    As said in RFC 1939 "13. Security Considerations" return invalid password
    in all auth failed cases such as "no user mailbox"
    """
    code = 'AUTH'
    message = 'Invalid password'


class AuthLoginDelay(BaseCodedException):
    """
    RFC 2449 p 8.1.1 Exception when client connects not respectively to login
    delay period
    """
    code = 'LOGIN-DELAY'
    message = 'Login delay not expired'


class AuthInUseException(BaseCodedException):
    """
    RFC 2449 p 8.1.2 Exception when client connects and other session is active
    """
    code = 'IN-USE'
    message = 'Another POP session is running'

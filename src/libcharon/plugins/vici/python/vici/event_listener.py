from functools import wraps


class EventListener(object):
    def __init__(self, session=None):
        """Create an event listener instance, which provides decorator methods
        to make listening for events and the disconnection of the vici session
        more convenient.

        The session is optional here, but one must be set via
        :func:`~set_session()` before calling :func:`~listen()`.

        :param session: optional vici session to use
        :type session: :class:`~vici.session.Session` or None
        """
        self.event_map = {}
        self.disconnect_list = []
        self.session = session

    def set_session(self, session):
        """Set the session that's used to listen for events. Only has an effect
        when set before calling :func:`~listen()`.

        :param session: vici session to use
        :type session: :class:`~vici.session.Session`
        """
        self.session = session

    def on_events(self, events):
        """Decorator to mark a function as a listener for specific events.

        The decorated function is expected to receive the name of the event and
        the data as arguments.

        :param events: events to register and call decorated function for
        :type events: list
        :return: decorator function
        :rtype: any
        """
        def decorator(func):
            self.event_map.update({event: func for event in events})

            @wraps(func)
            def wrapper(*args, **kwargs):
                return func(*args, **kwargs)
            return wrapper
        return decorator

    def on_disconnected(self):
        """Decorator to mark a function as a listener for when the daemon
        disconnects the vici session. This listener instance is passed to the
        decorated function.

        :return: decorator function
        :rtype: any
        """
        def decorator(func):
            self.disconnect_list.append(func)

            @wraps(func)
            def wrapper(*args, **kwargs):
                return func(*args, **kwargs)
            return wrapper
        return decorator

    def listen(self):
        """Dispatch events registered via decorators of this instance.

        This method does not return unless the daemon disconnects or an
        exception occurs.

        An active session has to be set before calling this. After getting
        disconnected, a new session may be set via :func:`~set_session()`
        before calling this again.
        """
        try:
            if self.session is None:
                return
            for label, event in self.session.listen(self.event_map.keys()):
                name = label.decode()
                if name in self.event_map:
                    self.event_map[name](name, event)
        except IOError as e:
            for func in self.disconnect_list:
                func(self)

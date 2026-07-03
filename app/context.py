from contextvars import ContextVar

current_user: ContextVar[dict] = ContextVar("current_user", default=None)

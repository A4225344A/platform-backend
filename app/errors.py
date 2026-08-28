class AppError(Exception):
    pass


class Conflict(AppError):
    pass


class Unauthorized(AppError):
    pass

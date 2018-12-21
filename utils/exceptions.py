class GitRepoException(Exception):
    pass


class NotFoundException(GitRepoException):
    pass


class ApiRateLimitExceededException(GitRepoException):
    pass

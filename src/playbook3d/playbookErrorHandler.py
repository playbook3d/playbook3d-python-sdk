class InvalidAPITokenRequest(Exception):
    """
    API Token request is invalid
    """
    pass

class InvalidAPITokenResponse(Exception):
    """
    API Token response is invalid
    """
    pass

class APIKeyNotAvailable(Exception):
    """
    API Key is not found
    """
    pass

class AuthenticatedRequestError(Exception):
    """
    Authenticated request error
    """
    def __init__(self, status_code: int):
        self.status_code = status_code
        super().__init__(f"Authenticated request failed with status code: {status_code}")
    pass

class UserRequestError(Exception):
    """
    User request error
    """
    pass

class WorkflowRequestError(Exception):
    """"
    Workflow request error
    """
    pass

class TeamRequestError(Exception):
    """
    Team request error
    """
    pass

class RunRequestError(Exception):
    """"
    Run request error
    """
    pass

class RunResultRequestError(Exception):
    """"
    Run result error
    """
    pass

class CancelRunRequestError(Exception):
    """"
    Canceling run result error
    """
    pass

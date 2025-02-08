import os
import requests
import jwt.utils
import json


from playbookErrorHandler import *
from playbookUser import PlaybookUser
from playbookWorkflow import PlaybookWorkflow
from playbookTeam import PlaybookTeam
from playbookRun import PlaybookRun
from playbookPrivateModel import PlaybookPrivateModel

from requests import exceptions, Response
from typing import List, Literal, Optional
from dotenv import load_dotenv

load_dotenv()

class PlaybookClient :
    """
    This class implements functionality to use the Playbook API.
    """
    api_key: str = None
    current_user: PlaybookUser = None

    def __init__(self) -> None:
        self.base_url = os.environ.get("BASE_URL")
        self.accounts_url = os.environ.get("BASE_ACCOUNTS_URL")

    def set_api_key(self, api_key: str) -> None:
        """
        Sets the current user API key for the playbook client.
        :param api_key: UUID
        """
        self.api_key = api_key

    def set_current_user(self, user: PlaybookUser) -> None:
        """
        Sets the current user for the playbook client.
        :param user: PlaybookUser
        """
        self.current_user = user

    def __get_user_jwt__(self) -> str:
        """
        Internal method used to get a user's token
        :return: User's JWT
        """
        base_url = os.environ.get("BASE_ACCOUNTS_URL")
        try:
            if self.api_key is None:
                raise APIKeyNotAvailable("API key not set")
            token_request = requests.get(url=f"{base_url}/token-wrapper/get-tokens/{self.api_key}")
            return token_request.json()["access_token"]
        except exceptions.HTTPError as err:
            raise InvalidAPITokenRequest(err)

    def get_authenticated_request(self, request: str, method: Literal["GET", "POST", "PUT", "DELETE"], **kwargs) -> Response | None:
        """
        Sends an authenticated GET request for playbook API usage
        :param request: url for request
        :param method: HTTP method -> GET, POST, PUT, DELETE
        :return: Authenticated Response
        """

        if method not in ["GET", "POST", "PUT", "DELETE"]:
            raise ValueError("Invalid HTTP Method")

        token = self.__get_user_jwt__()
        if token is not None:
            headers = kwargs.pop("headers", {})
            headers["Authorization"] = f"Bearer {token}"
            headers["x-api-key"] = os.environ.get("API_KEY")
            request_func = getattr(requests, method.lower())
            authenticated_request = request_func(request, headers=headers, **kwargs)
            if authenticated_request.status_code != 200:
                raise AuthenticatedRequestError(authenticated_request.status_code)
            return authenticated_request
        else:
            raise InvalidAPITokenRequest()

    @staticmethod
    def __parse_jwt_data__(token: str) -> Optional[dict]:
        try:
            payload_segment = token.split(".")[1]
            payload_bytes = payload_segment.encode("ascii")
            payload_json = jwt.utils.base64url_decode(payload_bytes)
            payload = json.loads(payload_json)
            return payload
        except(IndexError, UnicodeDecodeError, ValueError) as e:
            print(e)
            raise ValueError

    def get_user_data(self) -> Optional[PlaybookUser]:
        """
        Returns current user data
        :return: PlaybookUser
        """

        current_user_token = self.__get_user_jwt__()
        if current_user_token is None:
            raise InvalidAPITokenRequest()
        decoded_jwt = self.__parse_jwt_data__(current_user_token)
        current_user_token = decoded_jwt["username"]
        user_request = self.get_authenticated_request(f"{self.accounts_url}/users/cognito/{current_user_token}/info", method="GET")
        if user_request.status_code != 200:
            raise UserRequestError(user_request.status_code)
        response = user_request.json()
        current_user = PlaybookUser.from_json(response)
        return current_user


    def get_user_workflows(self) -> Optional[List[PlaybookWorkflow]]:
        """
        Returns available workflows based on current user
        :return: List of [PlaybookWorkflow]
        """

        workflows_request = self.get_authenticated_request(f"{self.accounts_url}/workflows", method="GET")
        if workflows_request.status_code != 200:
            raise WorkflowRequestError(workflows_request.status_code)
        workflow_response = workflows_request.json()
        available_workflows = []
        for workflow in workflow_response:
            internal_workflow = PlaybookWorkflow.from_json(workflow)
            available_workflows.append(internal_workflow)
        return available_workflows

    def get_user_teams(self) -> Optional[List[PlaybookTeam]]:
        """
        Returns available teams for current user
        :return: list of [PlaybookTeam]
        """

        team_request = self.get_authenticated_request(f'{self.accounts_url}/teams', method="GET")
        if team_request.status_code != 200:
            raise TeamRequestError(team_request.status_code)
        response = team_request.json()
        available_teams = []
        for team in response:
            current_team = PlaybookTeam.from_json(team)
            available_teams.append(current_team)
        return available_teams

    def get_user_runs(self) -> Optional[List[PlaybookRun]]:
        """
        Returns available runs for current user
        :return: list of [PlaybookRun]
        """

        runs_request = self.get_authenticated_request(f"{self.accounts_url}/runs", method="GET")
        if runs_request.status_code != 200:
            raise RunRequestError(runs_request.status_code)
        response = runs_request.json()
        available_runs = []
        for run in response:
            current_run = PlaybookRun.from_json(run)
            available_runs.append(current_run)
        return available_runs

    def create_workflow(self,
            name: str,
            public: bool,
            team_id: str,
            is_external: bool,
            public_url: Optional[str] = None,
            canvas_type: Optional[int] = None,
            workflow_url: Optional[str] = None,
            workflow_api_url: Optional[str] = None,
            s3_file_id: Optional[str] = None,
            last_form_data: Optional[str] = None,
    ) -> PlaybookWorkflow | None:
        """
        Creates a new workflow for selected user's team
        :param name: Workflow name
        :param public: is workflow public or not
        :param team_id: Team ID
        :param is_external: is workflow external or not
        :param public_url: OPTIONAL Public URL
        :param canvas_type: OPTIONAL Canvas Type
        :param workflow_url: OPTIONAL Workflow URL
        :param workflow_api_url: OPTIONAL Workflow API URL
        :param s3_file_id: OPTIONAL File ID
        :param last_form_data: OPTIONAL Last Form Data
        :return: Created PlaybookWorkflow
        """

    def create_team(self, team_name: str) -> PlaybookTeam | None:
        """
        Creates a new Team for selected user
        :param team_name: New team name
        :return: Created PlaybookTeam
        """
        data = { "name": team_name }
        new_team_request = self.get_authenticated_request(f"{self.accounts_url}/teams", method="POST", json=data)
        if new_team_request.status_code == 200:
            new_team_response = new_team_request.json()
            return PlaybookTeam.from_json(new_team_response)

    def update_workflow(self, workflow_id: str, new_workflow_data: dict) -> PlaybookTeam | None:
        """
        Creates a new Team for selected user
        :param workflow_id: ID for workflow to update
        :param new_workflow_data: New workflow data
        :return: Updated PlaybookWorkflow
        """

    def update_team(self, team_id: str, new_team_data: dict) -> PlaybookTeam | None:
        """
        Creates a new Team for selected user
        :param team_id: ID for workflow to update
        :param new_team_data: New workflow data
        :return: Updated PlaybookWorkflow
        """

    def update_user(self, user_id: str, new_user_data: dict) -> PlaybookTeam | None:
        """
        Creates a new Team for selected user
        :param user_id: ID for workflow to update
        :param new_user_data: New workflow data
        :return: Updated PlaybookWorkflow
        """

    def delete_workflow(self, workflow_id: str) -> PlaybookWorkflow | None:
        """
        Deletes selected workflow
        :param workflow_id: ID for selected workflow
        :return: Deleted PlaybookWorkflow
        """

    def delete_team(self, team_id: str) -> PlaybookTeam | None:
        """
        Deletes selected team
        :param team_id: ID for selected team
        :return: Deleted PlaybookTeam
        """

    def run_workflow(self, workflow: PlaybookWorkflow) -> Response | None:
        """
        Runs a workflow on cloud GPU
        :param workflow: PlaybookWorkflow
        :return: run_id
        """

        team = workflow.team_id
        workflow_id = workflow.workflow_id

        run_id = self.get_authenticated_request(f"{self.base_url}/get_run_id", method='GET').json()['run_id']

        run_data: dict = {
            "id": workflow_id,
            "origin": 0,
            "inputs": {}
        }
        try:
            run_request = self.get_authenticated_request(f"{self.base_url}/run_workflow/{team}/{run_id}", method="POST", json=run_data)
            return run_request
        except exceptions.HTTPError as err:
            raise RunRequestError(err)

    def get_run_result(self, run: PlaybookRun) -> str | None:
        """
        Runs a workflow on cloud GPU
        :param run: Playbook run
        :return: Result URL
        """

        run_id = run.run_id

        try:
            result_request = self.get_authenticated_request(f"{self.accounts_url}/runs/{run_id}/result", method="GET")
            return result_request.json()['result']
        except exceptions.HTTPError as err:
            raise RunResultRequestError(err)

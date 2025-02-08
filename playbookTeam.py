import json
from typing import Optional, List

from playbookUser import PlaybookUser
from playbookWorkflow import PlaybookWorkflow


class PlaybookTeam:
    """
    This class represents a playbook team.
    """

    def __init__(self,
                 team_id: str,
                 name: str,
                 owner_id: str,
                 last_login: str,
                 gpu_usage_total: float,
                 gpu_usage_billing_period: float,
                 modal_app_ids: str,
                 subscription_tier_id: str,
                 has_active_subscription: bool,
                 team_credits: int,
                 api_key: Optional[str] = None,
                 members: Optional[List[PlaybookUser]] = None,
                 private_models: Optional[List["PlaybookPrivateModel"]] = None,
                 workflows: Optional[List[PlaybookWorkflow]] = None,
                 ):
        self.team_id = team_id
        self.name = name
        self.owner_id = owner_id
        self.last_login = last_login
        self.gpu_usage_total = gpu_usage_total
        self.gpu_usage_billing_period = gpu_usage_billing_period
        self.modal_app_ids = modal_app_ids
        self.subscription_tier_id = subscription_tier_id
        self.has_active_subscription = has_active_subscription
        self.team_credits = team_credits
        self.api_key = api_key
        self.members = members if members is not None else []
        self.private_models = private_models if private_models is not None else []
        self.workflows = workflows if workflows is not None else []


    @classmethod
    def from_json(cls, json_data: dict) -> "PlaybookTeam | None":
        """
        Creates a PlaybookTeam object from JSON data.
        :param json_data: JSON data to decode
        :return: A PlaybookTeam object
        """
        if json_data is None:
            return None

        members_data = json_data.get('members', [])
        members = [PlaybookUser.from_json(members_data) for members_data in members_data if isinstance(members_data, dict)]

        private_models_data = json_data.get('private_models', [])
        from playbookPrivateModel import PlaybookPrivateModel
        private_models = [PlaybookPrivateModel.from_json(private_models_data) for private_models_data in private_models_data if isinstance(private_models_data, dict)]

        workflows_data = json_data.get('workflows', [])
        workflows = [PlaybookWorkflow.from_json(workflows_data) for workflows_data in workflows_data if isinstance(workflows_data, dict)]

        return cls(
            team_id=json_data.get("id"),
            name=json_data.get("name"),
            owner_id=json_data.get("owner_id"),
            last_login=json_data.get("last_login"),
            gpu_usage_total=json_data.get("gpu_usage_total"),
            gpu_usage_billing_period=json_data.get("gpu_usage_billing_period"),
            modal_app_ids=json_data.get("modal_app_ids"),
            subscription_tier_id=json_data.get("subscription_tier_id"),
            has_active_subscription=json_data.get("has_active_subscription"),
            team_credits=json_data.get("credits"),
            api_key=json_data.get("api_key"),
            members = members,
            private_models = private_models,
            workflows = workflows
        )

    def to_json(self) -> str:
        """
        Serializes PlaybookTeam object to JSON string.
        :return: JSON data
        """

        return json.dumps({
            "id": self.team_id,
            "name": self.name,
            "owner_id": self.owner_id,
            "last_login": self.last_login,
            "gpu_usage_total": self.gpu_usage_total,
            "gpu_usage_billing_period": self.gpu_usage_billing_period,
            "modal_app_ids": self.modal_app_ids,
            "subscription_tier_id": self.subscription_tier_id,
            "has_active_subscription": self.has_active_subscription,
            "credits": self.team_credits,
            "api_key": self.api_key,
            "members": [members.to_json() for members in self.members],
            "private_models": [private_models.to_json() for private_models in self.private_models],
            "workflows": [workflows.to_json() for workflows in self.workflows],
        })

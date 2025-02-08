import json

from playbookTeam import PlaybookTeam
from playbookUser import PlaybookUser
from playbookWorkflow import PlaybookWorkflow


class PlaybookRun:
    """
    This class represents a playbook run.
    """

    def __init__(
            self,
            run_id: str,
            platform: str,
            status: str,
            progress: float,
            duration: float,
            webhook_url: str,
            run_result: str,
            team: PlaybookTeam,
            owner: PlaybookUser,
            workflow: PlaybookWorkflow
            ):
        self.run_id = run_id
        self.platform = platform
        self.status = status
        self.progress = progress
        self.duration = duration
        self.webhook_url = webhook_url
        self.run_result = run_result
        self.team = team
        self.owner = owner
        self.workflow = workflow

    @classmethod
    def from_json(cls, json_data: dict)-> "PlaybookRun | None":
        """
               Creates a PlaybookWorkflow object from a JSON payload.
               :param json_data: JSON data to decode
               :return: a PlaybookWorkflow object
               """

        if json_data is None:
            return None

        return cls(
            run_id=json_data.get("id"),
            platform=json_data.get("platform"),
            status=json_data.get("status"),
            progress=json_data.get("progress"),
            duration=json_data.get("duration"),
            webhook_url=json_data.get("webhookUrl"),
            run_result=json_data.get("runResult"),
            team=PlaybookTeam.from_json(json_data.get("team")),
            owner=PlaybookUser.from_json(json_data.get("owner")),
            workflow=PlaybookWorkflow.from_json(json_data.get("workflow"))
        )

    def to_json(self) -> str:
        return json.dumps({
            "id": self.run_id,
            "platform": self.platform,
            "status": self.status,
            "progress": self.progress,
            "duration": self.duration,
            "webhook_url": self.webhook_url,
            "run_result": self.run_result,
            "team": self.team.to_json(),
            "owner": self.owner.to_json(),
            "workflow": self.workflow.to_json(),
        })




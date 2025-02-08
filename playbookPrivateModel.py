import json

from playbookTeam import PlaybookTeam


class PlaybookPrivateModel:
    def __init__(
            self,
            private_model_id: str,
            name: str,
            file_path: str,
            base_model: str,
            model_type: str,
            cover: str,
            team: PlaybookTeam,
        ):
        self.private_model_id = private_model_id
        self.name = name
        self.file_path = file_path
        self.base_model = base_model
        self.model_type = model_type
        self.cover = cover
        self.team = team

    @classmethod
    def from_json(cls, json_data: dict) -> "PlaybookPrivateModel | None":

        if json_data is None:
            return None

        return cls(
            private_model_id=json_data.get("id"),
            name=json_data.get("name"),
            file_path=json_data.get("file_path"),
            base_model=json_data.get("base_model"),
            model_type=json_data.get("model_type"),
            cover=json_data.get("cover"),
            team=PlaybookTeam.from_json(json_data.get("team"))
        )

    def to_json(self) -> str:
        return json.dumps({
            "id": self.private_model_id,
            "name": self.name,
            "file_path": self.file_path,
            "base_model": self.base_model,
            "model_type": self.model_type,
            "cover": self.cover,
            "team": self.team.to_json()
        })
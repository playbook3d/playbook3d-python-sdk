import unittest
from playbookUser import PlaybookUser
from playbookTeam import PlaybookTeam
from playbookWorkflow import PlaybookWorkflow
from playbookRun import PlaybookRun
from playbookNetworkClient import PlaybookClient

class TestPlaybookSDK(unittest.TestCase):
    def setUp(self):
        self.playbook_client = PlaybookClient()
        self.playbook_client.set_api_key("")

    def test_create_team(self):
        team_data = {
    "id": "123456",
    "name": "Personal Team",
    "owner_id": None,
    "api_key": None,
    "last_login": None,
    "custom_monthly_rate": None,
    "custom_free_credit": None,
    "gpu_usage_total": None,
    "gpu_usage_billing_period": None,
    "model_urls": None,
    "modal_app_id": None,
    "created_at": "2024-11-26T21:51:22.896Z",
    "updated_at": "2024-11-26T21:51:22.896Z"
}
        new_team = PlaybookTeam.from_json(team_data)
        self.assertIsInstance(new_team, PlaybookTeam)
        self.assertEqual(new_team.name, "Personal Team")
        self.assertEqual(new_team.team_id, "123456")

    def test_get_teams(self):
        available_teams = self.playbook_client.get_user_teams()
        self.assertIsInstance(available_teams[0], PlaybookTeam)
        self.assertEqual(available_teams[0].name, "Personal Team")

    def test_create_user(self):
        user_data = {"id": "123456",
    "cognito_id": "google_123456",
    "name": None,
    "email": "user@playbook3d.com",
    "status": "Active",
    "tier_id": "123456",
    "user_type": "admin",
    "api_key": None,
    "last_login": None,
    "gpu_usage_total": "0.00",
    "gpu_usage_billing_period": "0.00"
    }
        new_user = PlaybookUser.from_json(user_data)
        self.assertIsInstance(new_user, PlaybookUser)
        self.assertEqual(new_user.user_type, "admin")
        self.assertEqual(new_user.email, "user@playbook3d.com")

    def test_get_users(self):
        current_user = self.playbook_client.get_user_data()
        print(current_user)
        self.assertIsInstance(current_user, PlaybookUser)
        self.assertEqual(current_user.status, "Active")

    def test_create_workflow(self):
        workflow_data = {"id": "12345",
    "name": "Demo #1",
    "owner_id": "12345",
    "team_id": "12345",
    "last_edited": None,
    "workflow_url": None,
    "workflow_api_url": None,
    "is_external": False,
    "s3_file_id": "12345",
    "canvas_type": None,
    "public_url": None,
    "public": None,
    "created_at": "2024-11-30T01:11:50.295Z",
    "updated_at": "2024-12-07T23:26:45.240Z",
    "last_form_data": None,
    "cover": "cover",
    "modal_app_ids": None,
    "editing_user_id": None,
    "editing_user": None}
        new_workflow = PlaybookWorkflow.from_json(workflow_data)
        self.assertIsInstance(new_workflow, PlaybookWorkflow)
        self.assertEqual(new_workflow.name, "Demo #1")
        self.assertEqual(new_workflow.owner_id, "12345")

    def test_get_workflows(self):
        available_workflows = self.playbook_client.get_user_workflows()
        self.assertIsInstance(available_workflows[0], PlaybookWorkflow)

    #def test_run_workflow(self):
    #    available_workflows = self.playbook_client.get_user_workflows()
    #    self.assertIsInstance(available_workflows[0], PlaybookWorkflow)
    #    request = self.playbook_client.run_workflow(available_workflows[1])
    #    self.assertEqual(request.status_code, 200)
    #    request.raise_for_status()

    def test_get_runs(self):
        available_runs = self.playbook_client.get_user_runs()
        self.assertIsInstance(available_runs[0], PlaybookRun)

    def test_get_run_result(self):
        available_runs = self.playbook_client.get_user_runs()
        request = self.playbook_client.get_run_result(available_runs[0])
        self.assertIsInstance(request, str)

    def tearDown(self):
        pass

    if __name__ == '__main__':
        unittest.main()
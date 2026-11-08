
from skills.base_skill import BaseAgentSkill
class UnapprovedSkill(BaseAgentSkill):
    def execute(self, params):
        return {'status': 'EXECUTED'}

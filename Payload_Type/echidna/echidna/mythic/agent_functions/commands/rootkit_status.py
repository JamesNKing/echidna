from mythic_container.MythicCommandBase import *
import json
from mythic_container.MythicRPC import *


class RootkitStatusArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []
    
    async def parse_arguments(self):
        # No arguments needed for status check
        pass


class RootkitStatusCommand(CommandBase):
    cmd = "rootkit_status"
    needs_admin = False
    help_cmd = "rootkit_status"
    description = "Check the status of the rootkit kernel module"
    version = 1
    supported_ui_features = []
    author = "Anonymous"
    argument_class = RootkitStatusArguments
    attackmapping = ["T1082"]  # System Information Discovery
    attributes = CommandAttributes(
        suggested_command=True,
        dependencies=["rootkit_module"]
    )

    async def create_go_tasking(
            self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
            CommandName="rootkit_status"
        )
        
        response.DisplayParams = "Checking rootkit module status"
        return response
    
    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
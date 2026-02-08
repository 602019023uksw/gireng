import os
from pydantic import BaseModel, Field


class Settings(BaseModel):
    ghidra_docker_image: str = Field(default="ireng-runner", alias="GHIDRA_DOCKER_IMAGE")
    ghidra_project_root: str = Field(default="/data/projects", alias="GHIDRA_PROJECT_ROOT")
    ghidra_shared_root: str = Field(default="/data/shared", alias="GHIDRA_SHARED_ROOT")
    ghidra_headless_script_path: str = Field(default="/usr/share/ghidra/support/pyghidraRun", alias="GHIDRA_HEADLESS_SCRIPT_PATH")
    ghidra_volume_container: str = Field(default="ghidra_headless", alias="GHIDRA_VOLUME_CONTAINER")
    ghidra_scripts_root: str = Field(default="/data/shared/scripts", alias="GHIDRA_SCRIPTS_ROOT")
    ghidra_scripts_source: str = Field(default="/app/ghidra_scripts", alias="GHIDRA_SCRIPTS_SOURCE")
    ghidra_projects_volume: str = Field(default="ghidra_projects", alias="GHIDRA_PROJECTS_VOLUME")
    ghidra_shared_volume: str = Field(default="ghidra_shared", alias="GHIDRA_SHARED_VOLUME")
    ghidra_install_path: str = Field(default="/usr/share/ghidra", alias="GHIDRA_INSTALL_PATH")
    docker_cli_path: str = Field(default="/usr/bin/docker", alias="DOCKER_CLI_PATH")
    llm_model_name: str = Field(default="glm-4.7", alias="LLM_MODEL_NAME")
    llm_provider: str = Field(default="anthropic", alias="LLM_PROVIDER")
    max_decompilation_time: int = Field(default=30, alias="MAX_DECOMPILATION_TIME")
    default_analysis_timeout: int = Field(default=120, alias="DEFAULT_ANALYSIS_TIMEOUT")
    max_upload_bytes: int = Field(default=200 * 1024 * 1024, alias="MAX_UPLOAD_BYTES")  # 200 MB
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")

    class Config:
        populate_by_name = True


settings = Settings(**os.environ)

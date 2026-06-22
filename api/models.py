from typing import Optional
from pydantic import BaseModel


class ProviderConfigRequest(BaseModel):
    model_id: str
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    azure_api_base: Optional[str] = None
    azure_api_version: Optional[str] = None


class ScopeConfigRequest(BaseModel):
    user_context: str
    target: str
    os_platform: str = "windows"
    elevation_available: bool = False
    hostname: str = ""
    notes: str = ""


class TargetRequest(BaseModel):
    target_id: str = ""
    name: str = ""
    os_platform: str = "windows"
    privilege: str = "standard_user"   # admin | standard_user
    connection: str = "local"          # local | remote
    domain_joined: bool = False
    # Remote (WinRM) — only used when connection == "remote"
    host: str = "localhost"
    winrm_username: str = ""
    winrm_password: str = ""
    winrm_transport: str = "ntlm"      # ntlm | kerberos | credssp | negotiate | basic
    winrm_port: int = 5985
    winrm_ssl: bool = False
    notes: str = ""


class TestSelectionRequest(BaseModel):
    technique_id: str
    test_index: int = 0
    arg_overrides: dict = {}


class StartJobRequest(BaseModel):
    selections: list[TestSelectionRequest]
    targets: list[TargetRequest] = []
    # Legacy single-target shim — older callers send `scope` instead of `targets`.
    scope: Optional[ScopeConfigRequest] = None


class AnalyzeRequest(BaseModel):
    job_id: str
    provider: ProviderConfigRequest


class JobStatusResponse(BaseModel):
    job_id: str
    status: str
    total: int
    completed: int
    succeeded: int
    failed: int
    skipped: int
    start_time: Optional[str]
    end_time: Optional[str]
    error: Optional[str]


# Legacy agent session models kept for backward compat
class StartSessionRequest(BaseModel):
    target: str
    objective: str
    provider: ProviderConfigRequest
    max_iterations: Optional[int] = None
    atomics_path: Optional[str] = None


# --- Nmap scan + vulnerability analysis ---------------------------------
class ScanRequest(BaseModel):
    target: str
    profile: str = "ad-top-1000"
    extra_args: list[str] = []


class ScanAnalyzeRequest(BaseModel):
    scan_id: str
    provider: ProviderConfigRequest


class TerminalCommandRequest(BaseModel):
    command: str


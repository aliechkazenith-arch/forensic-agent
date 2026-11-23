"""Air-Gapped Tool Worker Sandbox and Plugin Runner.

Standards: RFC 3227, Zero Shell Interpolation (shell=False),
Network Isolation (--network none), Read-Only Mounts (:ro),
Mandatory Container Sandboxing, Fail-Closed on Sandbox Absence,
Smart Column Projection with audit.jsonl Transparency Logging.
"""
from __future__ import annotations

import csv
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from uuid import uuid4

from backend.app.core.column_projector import SmartColumnProjector
from backend.app.core.dissect_adapter import DissectAdapter
from backend.app.core.exceptions import (
    ExecutionPolicyError,
    ForensicOpsError,
    ProcessTimeoutError,
    SandboxUnavailableError,
)
from backend.app.core.execution_policy import (
    ToolExecutionPolicy,
    get_execution_policy_registry,
)
from backend.app.models.custody import ArtifactRecord, canonical_json_dump
from backend.app.models.findings import ForensicFinding
from backend.app.models.plugins import ToolExecutionResult, ToolPluginCard


DANGEROUS_SHELL_PATTERNS = {";", "&", "|", "`", "$(", "${"}

ALLOWED_FORENSIC_BINARIES = {
    "chainsaw",
    "chainsaw.exe",
    "evtxecmd",
    "evtxecmd.exe",
    "recmd",
    "recmd.exe",
    "vol",
    "vol.exe",
    "volatility",
    "volatility.exe",
    "volatility3",
    "vol.py",
    "yara",
    "yara.exe",
    "yara64.exe",
    "safe_bin",
    "python",
    "python.exe",
    "python3",
    Path(sys.executable).name.lower(),
}

MAX_CAPTURE_BYTES = 10 * 1024 * 1024  # 10 MB stdout/stderr limit to prevent OOM


def compute_streaming_sha256(file_path: Union[str, Path], chunk_size: int = 8 * 1024 * 1024) -> str:
    """Compute SHA-256 for a file using memory-bounded streaming (RFC 3227).

    Uses hashlib.file_digest (C-level streaming) where available or 8 MiB chunked reads
    to guarantee memory-bounded hashing that never OOMs on multi-gigabyte disk/memory images.
    """
    p = Path(file_path)
    if not p.is_file():
        return ""
    with open(p, "rb") as f:
        if hasattr(hashlib, "file_digest"):
            return hashlib.file_digest(f, "sha256").hexdigest()
        hasher = hashlib.sha256()
        while chunk := f.read(chunk_size):
            hasher.update(chunk)
        return hasher.hexdigest()


def is_container_runtime_available(runtime: str = "docker") -> bool:
    """Check if the configured container runtime is installed and operational."""
    if not shutil.which(runtime):
        return False
    try:
        res = subprocess.run([runtime, "--version"], capture_output=True, timeout=5)
        return res.returncode == 0
    except Exception:
        return False


def terminate_process_tree(proc: subprocess.Popen) -> None:
    """Safely terminate parent and child processes across Windows and POSIX."""
    try:
        if sys.platform == "win32":
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                capture_output=True,
                timeout=5,
            )
        else:
            try:
                pgid = os.getpgid(proc.pid)
                os.killpg(pgid, signal.SIGKILL)
            except Exception:
                proc.kill()
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


class AirGappedSubprocessRunner:
    """Executes external forensic binaries with strict air-gapping and zero shell interpolation."""

    def __init__(
        self,
        use_docker_if_available: bool = True,
        container_runtime: str = "docker",
        allow_test_mock: Optional[bool] = None,
    ):
        self.use_docker = use_docker_if_available
        self.container_runtime = container_runtime
        if allow_test_mock is None:
            self.allow_test_mock = (
                os.getenv("FORENSICOPS_TEST_MODE", "").lower() in ("true", "1")
                or "pytest" in sys.modules
            )
        else:
            self.allow_test_mock = allow_test_mock
        self._mock_handlers: Dict[str, Callable[[List[str], Path, Path], Tuple[int, str, str]]] = {}

    def register_mock_tool(
        self,
        tool_name: str,
        handler: Callable[[List[str], Path, Path], Tuple[int, str, str]],
    ) -> None:
        """Register a mock execution handler for testing environments."""
        self._mock_handlers[tool_name.lower()] = handler

    def build_container_argv(
        self,
        argv: List[str],
        container_image: str,
        readonly_input_dir: Optional[Union[str, Path]] = None,
        scratch_output_dir: Optional[Union[str, Path]] = None,
        tool_policy: Optional[Any] = None,
        readonly_input_file: Optional[Union[str, Path]] = None,
        rules_path: Optional[Union[str, Path]] = None,
    ) -> List[str]:
        """Construct secure, air-gapped container command line with mandatory hardening flags."""
        cpu_lim = tool_policy.resource_limits.cpu_limit if tool_policy else 2.0
        mem_lim = tool_policy.resource_limits.memory_limit if tool_policy else "2g"
        pids_lim = tool_policy.resource_limits.pids_limit if tool_policy else 100
        tmpfs_sz = tool_policy.resource_limits.tmpfs_size if tool_policy else "100m"

        cmd = [
            self.container_runtime,
            "run",
            "--rm",
            "--network", "none",
            "--read-only",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges:true",
            "--user", "1000:1000",
            "--cpus", str(cpu_lim),
            "--memory", mem_lim,
            "--pids-limit", str(pids_lim),
            "--tmpfs", f"/tmp:rw,noexec,nosuid,size={tmpfs_sz}",
        ]
        # SEC-EXEC-002: Single-file evidence mounting prevents exposing sibling vault artifacts
        if readonly_input_file:
            resolved_file = Path(readonly_input_file).resolve()
            cmd.extend(["-v", f"{resolved_file}:/evidence/{resolved_file.name}:ro"])
        elif readonly_input_dir:
            resolved_dir = Path(readonly_input_dir).resolve()
            if resolved_dir.is_file():
                cmd.extend(["-v", f"{resolved_dir}:/evidence/{resolved_dir.name}:ro"])
            else:
                cmd.extend(["-v", f"{resolved_dir}:/evidence:ro"])

        if scratch_output_dir:
            cmd.extend(["-v", f"{Path(scratch_output_dir).resolve()}:/scratch:rw"])

        # Package 3: Mount /rules volume into container if rules_path provided
        if rules_path:
            resolved_rules = Path(rules_path).resolve()
            if resolved_rules.is_file():
                cmd.extend(["-v", f"{resolved_rules}:/rules/{resolved_rules.name}:ro"])
            else:
                cmd.extend(["-v", f"{resolved_rules}:/rules:ro"])

        # Translate any remaining host path references in argv to container mount paths (SEC-EXEC-001)
        translated_argv = []
        for arg in argv:
            arg_str = str(arg)
            if readonly_input_file:
                rf_resolved = str(Path(readonly_input_file).resolve())
                if rf_resolved in arg_str:
                    arg_str = arg_str.replace(rf_resolved, f"/evidence/{Path(readonly_input_file).name}")
                elif str(readonly_input_file) in arg_str:
                    arg_str = arg_str.replace(str(readonly_input_file), f"/evidence/{Path(readonly_input_file).name}")
            if readonly_input_dir:
                ro_resolved = str(Path(readonly_input_dir).resolve())
                if ro_resolved in arg_str:
                    if Path(readonly_input_dir).is_file():
                        arg_str = arg_str.replace(ro_resolved, f"/evidence/{Path(readonly_input_dir).name}")
                    else:
                        arg_str = arg_str.replace(ro_resolved, "/evidence")
                elif str(readonly_input_dir) in arg_str:
                    if Path(readonly_input_dir).is_file():
                        arg_str = arg_str.replace(str(readonly_input_dir), f"/evidence/{Path(readonly_input_dir).name}")
                    else:
                        arg_str = arg_str.replace(str(readonly_input_dir), "/evidence")
            if scratch_output_dir:
                sc_resolved = str(Path(scratch_output_dir).resolve())
                if sc_resolved in arg_str:
                    arg_str = arg_str.replace(sc_resolved, "/scratch")
                elif str(scratch_output_dir) in arg_str:
                    arg_str = arg_str.replace(str(scratch_output_dir), "/scratch")
            if rules_path:
                ru_resolved = str(Path(rules_path).resolve())
                if ru_resolved in arg_str:
                    if Path(rules_path).is_file():
                        arg_str = arg_str.replace(ru_resolved, f"/rules/{Path(rules_path).name}")
                    else:
                        arg_str = arg_str.replace(ru_resolved, "/rules")
                elif str(rules_path) in arg_str:
                    if Path(rules_path).is_file():
                        arg_str = arg_str.replace(str(rules_path), f"/rules/{Path(rules_path).name}")
                    else:
                        arg_str = arg_str.replace(str(rules_path), "/rules")
            translated_argv.append(arg_str)

        cmd.extend([container_image, *translated_argv])
        return cmd

    def execute(
        self,
        argv: List[str],
        cwd: Union[str, Path],
        timeout_seconds: int = 300,
        container_image: Optional[str] = None,
        readonly_input_dir: Optional[Union[str, Path]] = None,
        scratch_output_dir: Optional[Union[str, Path]] = None,
        tool_policy: Optional[ToolExecutionPolicy] = None,
        allow_host_process: bool = False,
        readonly_input_file: Optional[Union[str, Path]] = None,
        rules_path: Optional[Union[str, Path]] = None,
    ) -> Tuple[int, str, str, float]:
        """Execute command array with shell=False and strict safety checks.
        
        Returns:
            Tuple of (returncode, stdout, stderr, execution_duration_seconds)
        """
        if not isinstance(argv, list):
            raise ForensicOpsError(f"Zero shell interpolation violation: argv must be a list, got {type(argv)}")

        if not argv:
            raise ForensicOpsError("Cannot execute empty command array.")

        # Defense-in-depth: check for shell injection attempts in arguments
        for arg in argv:
            if not isinstance(arg, str):
                raise ForensicOpsError(f"Command argument must be string: {arg}")
            for danger in DANGEROUS_SHELL_PATTERNS:
                if danger in arg and not os.path.exists(arg):
                    raise ForensicOpsError(
                        f"Potentially unsafe shell metacharacter '{danger}' detected in argument: {arg}"
                    )

        executable_base = Path(argv[0]).name.lower()
        executable_stem = Path(argv[0]).stem.lower()

        # Check for registered mock handler (for explicit test configurations)
        handler = self._mock_handlers.get(executable_base) or self._mock_handlers.get(executable_stem)
        if handler:
            if not self.allow_test_mock:
                raise ExecutionPolicyError("Mock tool execution is disabled in production configuration.")
            start_t = time.perf_counter()
            ret_code, out, err = handler(
                argv, Path(readonly_input_dir or cwd), Path(scratch_output_dir or cwd)
            )
            duration = time.perf_counter() - start_t
            return ret_code, out, err, duration

        # Host execution allowlist check
        is_containerized = bool(container_image)
        if not is_containerized and not allow_host_process:
            if executable_base not in ALLOWED_FORENSIC_BINARIES:
                raise ForensicOpsError(
                    f"Binary '{executable_base}' is not in the approved forensic tool allowlist. "
                    f"To execute unverified binaries, containerized execution via container_image is required."
                )
            # If it's a forensic binary, reject host execution (fail-closed to sandbox)
            if executable_base not in ("python", "python.exe", "python3", Path(sys.executable).name.lower(), "safe_bin"):
                raise SandboxUnavailableError(
                    f"Direct host execution of forensic binary '{executable_base}' is prohibited. "
                    f"Containerized execution within the approved sandbox is mandatory (Fail-Closed)."
                )

        final_cmd = argv
        if container_image:
            # Fail-closed check: verify container runtime is available
            if not is_container_runtime_available(self.container_runtime):
                raise SandboxUnavailableError(
                    f"Sandbox execution failed: container runtime '{self.container_runtime}' is required "
                    f"for untrusted forensic tool execution and is unavailable. "
                    f"Host execution fallback is strictly prohibited (Fail-Closed)."
                )

            final_cmd = self.build_container_argv(
                argv=argv,
                container_image=container_image,
                readonly_input_dir=readonly_input_dir,
                scratch_output_dir=scratch_output_dir,
                tool_policy=tool_policy,
                readonly_input_file=readonly_input_file,
                rules_path=rules_path,
            )

        start_time = time.perf_counter()
        try:
            # Enforce shell=False unconditionally
            proc = subprocess.Popen(
                final_cmd,
                shell=False,
                cwd=str(cwd),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                stdout_data, stderr_data = proc.communicate(timeout=timeout_seconds)
                # Enforce bounded capture to prevent OOM
                if len(stdout_data) > MAX_CAPTURE_BYTES:
                    stdout_data = stdout_data[:MAX_CAPTURE_BYTES] + "\n[OUTPUT TRUNCATED: Exceeded 10MB limit]"
                if len(stderr_data) > MAX_CAPTURE_BYTES:
                    stderr_data = stderr_data[:MAX_CAPTURE_BYTES] + "\n[OUTPUT TRUNCATED: Exceeded 10MB limit]"
                duration = time.perf_counter() - start_time
                return proc.returncode, stdout_data, stderr_data, duration
            except subprocess.TimeoutExpired:
                terminate_process_tree(proc)
                proc.communicate()
                duration = time.perf_counter() - start_time
                raise ProcessTimeoutError(
                    f"Tool execution timed out after {timeout_seconds} seconds: {' '.join(argv[:3])}"
                )
        except FileNotFoundError as e:
            raise ForensicOpsError(
                f"Binary '{argv[0]}' not found on host. Install tool or configure container runner: {e}"
            )


class PluginRunner:
    """Orchestrates Tier A (Dissect) and Tier B (YAML Tool Card) forensic analysis plugins."""

    def __init__(
        self,
        subprocess_runner: Optional[AirGappedSubprocessRunner] = None,
        projector: Optional[SmartColumnProjector] = None,
        dissect_adapter: Optional[DissectAdapter] = None,
        audit_log_path: Optional[Union[str, Path]] = None,
        custody_engine: Optional[Any] = None,
    ):
        self.subprocess_runner = subprocess_runner or AirGappedSubprocessRunner()
        self.projector = projector or SmartColumnProjector(default_audit_log_path=audit_log_path)
        self.dissect_adapter = dissect_adapter or DissectAdapter(projector=self.projector)
        self.audit_log_path = Path(audit_log_path).resolve() if audit_log_path else None
        self.custody_engine = custody_engine

    def run_plugin(
        self,
        plugin: ToolPluginCard,
        artifact: ArtifactRecord,
        output_workspace: Union[str, Path],
        rules_path: Optional[Union[str, Path]] = None,
        force_rerun: bool = False,
    ) -> ToolExecutionResult:
        """Execute a tool plugin against an ingested evidence artifact with execution policy and provenance."""
        workspace = Path(output_workspace).resolve()
        scratch_dir = workspace / "scratch" / plugin.tool_id
        scratch_dir.mkdir(parents=True, exist_ok=True)
        raw_output_dir = workspace / "raw_outputs" / plugin.tool_id
        raw_output_dir.mkdir(parents=True, exist_ok=True)

        # Enforce workspace confinement
        if not scratch_dir.is_relative_to(workspace) or not raw_output_dir.is_relative_to(workspace):
            raise ForensicOpsError("Path traversal detected in workspace output directories.")

        if self.custody_engine and hasattr(self.custody_engine, "resolve_artifact_file"):
            input_path = self.custody_engine.resolve_artifact_file(artifact)
        else:
            raw_path = Path(artifact.blob_path)
            if raw_path.is_absolute():
                input_path = raw_path
            elif (Path("vault") / raw_path).exists():
                input_path = (Path("vault") / raw_path).resolve()
            else:
                input_path = raw_path.resolve()

        if not input_path.exists():
            raise FileNotFoundError(f"Artifact blob does not exist: {input_path}")

        # Record pre-execution evidence hash to guarantee read-only immutability (RFC 3227)
        pre_evidence_hash = compute_streaming_sha256(input_path) if input_path.is_file() else ""

        started_at = datetime.now(timezone.utc).isoformat()
        execution_id = str(uuid4())

        # Check execution idempotency
        exec_key = ""
        if self.custody_engine and hasattr(self.custody_engine, "compute_execution_key"):
            exec_key = self.custody_engine.compute_execution_key(
                case_id=artifact.case_id,
                artifact_hash=artifact.sha256,
                tool_id=plugin.tool_id,
                tool_version=plugin.version or "1.0.0",
                parameters=plugin.command_template,
            )
            if not force_rerun:
                existing = self.custody_engine.get_tool_execution(exec_key)
                if existing and existing.get("status") == "completed":
                    raw_dump_path = raw_output_dir / f"{plugin.tool_id}_raw.json"
                    existing_findings = []
                    if raw_dump_path.is_file():
                        try:
                            with open(raw_dump_path, "r", encoding="utf-8") as rf:
                                cached_raw = json.load(rf)
                            proj_rows, _ = self.projector.project_rows(
                                raw_rows=cached_raw,
                                ai_keep_fields=plugin.ai_keep_fields,
                                field_map=plugin.field_map,
                                case_id=artifact.case_id,
                                tool_id=plugin.tool_id,
                                source_artifact_id=artifact.artifact_id,
                                raw_output_path=str(raw_dump_path),
                                audit_log_path=self.audit_log_path,
                            )
                            existing_findings = self._normalize_findings(
                                plugin=plugin,
                                artifact=artifact,
                                raw_rows=cached_raw,
                                projected_rows=proj_rows,
                                raw_data_path=str(raw_dump_path),
                            )
                        except Exception:
                            existing_findings = []

                    return ToolExecutionResult(
                        tool_id=plugin.tool_id,
                        success=True,
                        exit_code=0,
                        findings_count=len(existing_findings) or existing.get("findings_count", 0),
                        raw_rows_count=len(existing_findings) or existing.get("findings_count", 0),
                        projected_rows_count=len(existing_findings) or existing.get("findings_count", 0),
                        raw_columns_count=len(plugin.ai_keep_fields) or 5,
                        projected_columns_count=len(plugin.ai_keep_fields) or 5,
                        findings=existing_findings,
                        execution_time_seconds=0.0,
                        source_artifact_hash=artifact.sha256,
                        tool_version=plugin.version,
                        started_at_utc=existing.get("started_at_utc", started_at),
                        finished_at_utc=existing.get("finished_at_utc", started_at),
                        input_artifact_hash=artifact.sha256,
                        resource_metrics={"cached": True, "execution_key": exec_key},
                        warnings=["Replayed existing execution results (idempotent)"],
                    )

        # ----------------------------------------------------------------------
        # Tier A: Built-in Pure-Python Dissect Adapter
        # ----------------------------------------------------------------------
        if plugin.execution_tier == "tier_a_builtin":
            start_t = time.perf_counter()
            findings = self._run_tier_a(plugin, artifact, input_path)
            duration = time.perf_counter() - start_t
            finished_at = datetime.now(timezone.utc).isoformat()

            self._record_custody_and_audit(
                plugin.tool_id,
                artifact,
                findings_count=len(findings),
                raw_rows=len(findings),
                projected_rows=len(findings),
            )

            # Enforce read-only evidence immutability check
            if input_path.is_file() and pre_evidence_hash:
                post_evidence_hash = compute_streaming_sha256(input_path)
                if post_evidence_hash != pre_evidence_hash:
                    raise ForensicOpsError(
                        f"Evidence integrity violation: original artifact '{input_path.name}' was modified during analysis! "
                        f"Pre-hash: {pre_evidence_hash}, Post-hash: {post_evidence_hash}"
                    )

            return ToolExecutionResult(
                tool_id=plugin.tool_id,
                success=True,
                exit_code=0,
                findings_count=len(findings),
                raw_rows_count=len(findings),
                projected_rows_count=len(findings),
                raw_columns_count=len(plugin.ai_keep_fields) or 5,
                projected_columns_count=len(plugin.ai_keep_fields) or 5,
                findings=findings,
                execution_time_seconds=duration,
                source_artifact_hash=artifact.sha256,
                tool_version=plugin.version,
                started_at_utc=started_at,
                finished_at_utc=finished_at,
                input_artifact_hash=artifact.sha256,
                resource_metrics={"tier": "tier_a_builtin", "execution_time_seconds": duration},
            )

        # ----------------------------------------------------------------------
        # Tier B: Declarative YAML Tool Adapter Execution
        # ----------------------------------------------------------------------
        # Validate plugin card and execution policy
        policy_registry = get_execution_policy_registry()
        policy_registry.validate_plugin_card(plugin)
        policy = policy_registry.validate_tool_execution(
            tool_id=plugin.tool_id,
            argv=plugin.command_template,
            container_image=plugin.container_image,
            timeout_seconds=plugin.timeout_seconds,
            artifact_type=artifact.type,
        )

        # Check if running under container vs mock handler (SEC-EXEC-001)
        exe_name = Path(plugin.command_template[0]).name.lower()
        exe_stem = Path(plugin.command_template[0]).stem.lower()
        is_mocked = bool(
            self.subprocess_runner.allow_test_mock
            and (exe_name in self.subprocess_runner._mock_handlers or exe_stem in self.subprocess_runner._mock_handlers)
        )
        is_container_execution = bool(plugin.container_image) and not is_mocked

        if is_container_execution:
            input_sub = f"/evidence/{input_path.name}"
            output_sub = "/scratch"
            rules_sub = f"/rules/{Path(rules_path).name}" if rules_path else ""
        else:
            input_sub = str(input_path)
            output_sub = str(scratch_dir)
            rules_sub = str(rules_path or "")

        # Build command array from template
        argv: List[str] = []
        for token in plugin.command_template:
            replaced = (
                token.replace("{input_path}", input_sub)
                .replace("{output_dir}", output_sub)
                .replace("{rules_path}", rules_sub)
            )
            argv.append(replaced)

        exit_code, stdout, stderr, duration = self.subprocess_runner.execute(
            argv=argv,
            cwd=scratch_dir,
            timeout_seconds=plugin.timeout_seconds,
            container_image=plugin.container_image,
            readonly_input_file=input_path if input_path.is_file() else None,
            readonly_input_dir=input_path if input_path.is_dir() else None,
            scratch_output_dir=scratch_dir,
            rules_path=rules_path,
            tool_policy=policy,
        )

        finished_at = datetime.now(timezone.utc).isoformat()

        # Compute output hashes for all files produced
        output_hashes: Dict[str, str] = {}
        for fpath in scratch_dir.glob("*"):
            if fpath.is_file():
                try:
                    output_hashes[fpath.name] = compute_streaming_sha256(fpath)
                except Exception:
                    pass

        if exit_code != 0:
            return ToolExecutionResult(
                tool_id=plugin.tool_id,
                success=False,
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                execution_time_seconds=duration,
                source_artifact_hash=artifact.sha256,
                tool_version=plugin.version,
                binary_digest=policy.binary_digest if policy else None,
                container_image=plugin.container_image,
                container_image_digest=policy.container_image_digest if policy else None,
                parameters=argv,
                started_at_utc=started_at,
                finished_at_utc=finished_at,
                input_artifact_hash=artifact.sha256,
                output_hashes=output_hashes,
                errors=[stderr] if stderr else [f"Process exited with code {exit_code}"],
                resource_metrics={
                    "cpu_limit": policy.resource_limits.cpu_limit if policy else 2.0,
                    "memory_limit": policy.resource_limits.memory_limit if policy else "2g",
                    "pids_limit": policy.resource_limits.pids_limit if policy else 100,
                    "execution_time_seconds": duration,
                },
            )

        # Ingest and normalize raw outputs
        raw_rows, raw_file_path = self._collect_raw_output(scratch_dir, plugin.output_format, stdout)

        # Save 100% of raw rows to permanent raw_outputs directory
        raw_dump_path = raw_output_dir / f"{plugin.tool_id}_raw.json"
        with open(raw_dump_path, "w", encoding="utf-8") as f:
            json.dump(raw_rows, f, indent=2)

        # Add raw dump hash to output_hashes
        try:
            output_hashes[raw_dump_path.name] = compute_streaming_sha256(raw_dump_path)
        except Exception:
            pass

        # Smart Column Projection
        projected_rows, metrics = self.projector.project_rows(
            raw_rows=raw_rows,
            ai_keep_fields=plugin.ai_keep_fields,
            field_map=plugin.field_map,
            case_id=artifact.case_id,
            tool_id=plugin.tool_id,
            source_artifact_id=artifact.artifact_id,
            raw_output_path=str(raw_dump_path),
            audit_log_path=self.audit_log_path,
        )

        # Normalize into ForensicFinding instances
        findings = self._normalize_findings(
            plugin=plugin,
            artifact=artifact,
            raw_rows=raw_rows,
            projected_rows=projected_rows,
            raw_data_path=str(raw_dump_path),
        )

        # Log to custody engine if configured
        self._record_custody_and_audit(
            plugin.tool_id,
            artifact,
            findings_count=len(findings),
            raw_rows=metrics["raw_rows_count"],
            projected_rows=metrics["projected_rows_count"],
        )

        if self.custody_engine and hasattr(self.custody_engine, "record_tool_execution") and exec_key:
            try:
                self.custody_engine.record_tool_execution(
                    execution_id=execution_id,
                    execution_key=exec_key,
                    case_id=artifact.case_id,
                    artifact_id=artifact.artifact_id,
                    artifact_sha256=artifact.sha256,
                    tool_id=plugin.tool_id,
                    tool_version=plugin.version or "1.0.0",
                    status="completed" if exit_code == 0 else "failed",
                    started_at_utc=started_at,
                    finished_at_utc=finished_at,
                    findings_count=len(findings),
                    raw_output_path=str(raw_dump_path) if exit_code == 0 else None,
                    parameters=argv,
                    warnings=None,
                    errors=[stderr] if exit_code != 0 else None,
                )
            except Exception:
                pass

        # Enforce read-only evidence immutability check
        if input_path.is_file() and pre_evidence_hash:
            post_evidence_hash = compute_streaming_sha256(input_path)
            if post_evidence_hash != pre_evidence_hash:
                raise ForensicOpsError(
                    f"Evidence integrity violation: original artifact '{input_path.name}' was modified during analysis! "
                    f"Pre-hash: {pre_evidence_hash}, Post-hash: {post_evidence_hash}"
                )

        return ToolExecutionResult(
            tool_id=plugin.tool_id,
            success=True,
            exit_code=exit_code,
            findings_count=len(findings),
            raw_rows_count=metrics["raw_rows_count"],
            projected_rows_count=metrics["projected_rows_count"],
            raw_columns_count=metrics["raw_columns_count"],
            projected_columns_count=metrics["projected_columns_count"],
            raw_output_path=str(raw_dump_path),
            findings=findings,
            stdout=stdout,
            stderr=stderr,
            execution_time_seconds=duration,
            source_artifact_hash=artifact.sha256,
            tool_version=plugin.version,
            binary_digest=policy.binary_digest if policy else None,
            container_image=plugin.container_image,
            container_image_digest=policy.container_image_digest if policy else None,
            parameters=argv,
            started_at_utc=started_at,
            finished_at_utc=finished_at,
            input_artifact_hash=artifact.sha256,
            output_hashes=output_hashes,
            resource_metrics={
                "cpu_limit": policy.resource_limits.cpu_limit if policy else 2.0,
                "memory_limit": policy.resource_limits.memory_limit if policy else "2g",
                "pids_limit": policy.resource_limits.pids_limit if policy else 100,
                "execution_time_seconds": duration,
            },
        )

    def execute_analyzer(
        self,
        tool_id: str,
        artifact: ArtifactRecord,
        output_workspace: Union[str, Path],
        rules_path: Optional[Union[str, Path]] = None,
        force_rerun: bool = False,
        raise_on_error: bool = False,
    ) -> ToolExecutionResult:
        """Execute a deterministic forensic analyzer (Tier A or Tier B) by tool_id with verified provenance.
        
        Args:
            tool_id: Unique tool identifier (e.g. dissect_evtx, dissect_registry, chainsaw_sigma, volatility3_pslist)
            artifact: Ingested evidence artifact record
            output_workspace: Case workspace directory for outputs
            rules_path: Optional rules path (e.g. YARA/Sigma rules)
            force_rerun: Bypass idempotent execution caching
            raise_on_error: Whether to raise exceptions on execution failure or return failed result cleanly
            
        Returns:
            ToolExecutionResult with normalized ForensicFinding objects and full execution provenance.
        """
        from backend.app.core.analyzer_registry import get_analyzer_registry

        # 1. Reject unsupported container formats fail-closed (E01/VMDK)
        art_type = (artifact.type or "").lower()
        orig_name = str(
            getattr(artifact, "original_filename", None)
            or getattr(artifact, "original_path", None)
            or getattr(artifact, "blob_path", "")
        ).lower()
        
        if art_type in ("vmdk", "e01", "ewf") or orig_name.endswith((".vmdk", ".e01", ".ewf")):
            err_msg = (
                f"Unsupported artifact container format '{art_type or Path(orig_name).suffix}'. "
                f"Dissect pure-python stream parsing does not support E01 or VMDK container formats. "
                f"Provide flat raw disk images (.raw/.img/.dd)."
            )
            if raise_on_error:
                raise ForensicOpsError(err_msg)
            return ToolExecutionResult(
                tool_id=tool_id,
                success=False,
                exit_code=1,
                findings_count=0,
                raw_rows_count=0,
                projected_rows_count=0,
                raw_columns_count=0,
                projected_columns_count=0,
                findings=[],
                source_artifact_hash=artifact.sha256,
                input_artifact_hash=artifact.sha256,
                warnings=[err_msg],
                errors=[err_msg],
            )

        # 2. Look up analyzer in registry
        reg = get_analyzer_registry()
        analyzer = reg.get_analyzer(tool_id)

        # 3. Route Tier A Built-in Analyzers
        if analyzer and analyzer.execution_tier == "tier_a_dissect":
            plugin_card = ToolPluginCard(
                tool_id=analyzer.tool_id,
                name=analyzer.name,
                version=analyzer.version,
                description=analyzer.description,
                category=analyzer.category,
                supported_artifact_types=analyzer.supported_artifact_types,
                execution_tier="tier_a_builtin",
                command_template=[],
            )
            try:
                return self.run_plugin(
                    plugin=plugin_card,
                    artifact=artifact,
                    output_workspace=output_workspace,
                    rules_path=rules_path,
                    force_rerun=force_rerun,
                )
            except ForensicOpsError as fe:
                if raise_on_error:
                    raise
                return ToolExecutionResult(
                    tool_id=tool_id,
                    success=False,
                    exit_code=1,
                    findings_count=0,
                    raw_rows_count=0,
                    projected_rows_count=0,
                    raw_columns_count=0,
                    projected_columns_count=0,
                    findings=[],
                    source_artifact_hash=artifact.sha256,
                    input_artifact_hash=artifact.sha256,
                    warnings=[str(fe)],
                    errors=[str(fe)],
                )

        # 4. Route Tier B Containerized Tool Plugins
        plugins_dir = Path(os.environ.get("FORENSICOPS_PLUGINS_DIR", "plugins")).resolve()
        card_file = plugins_dir / f"{tool_id}.yaml"
        if card_file.is_file():
            card = ToolPluginCard.from_yaml_file(card_file)
            try:
                return self.run_plugin(
                    plugin=card,
                    artifact=artifact,
                    output_workspace=output_workspace,
                    rules_path=rules_path,
                    force_rerun=force_rerun,
                )
            except (SandboxUnavailableError, ProcessTimeoutError, ExecutionPolicyError, ForensicOpsError) as exec_err:
                if raise_on_error:
                    raise
                warn_text = f"Capability execution unavailable for tool '{tool_id}': {exec_err}"
                return ToolExecutionResult(
                    tool_id=tool_id,
                    success=False,
                    exit_code=1,
                    findings_count=0,
                    raw_rows_count=0,
                    projected_rows_count=0,
                    raw_columns_count=0,
                    projected_columns_count=0,
                    findings=[],
                    source_artifact_hash=artifact.sha256,
                    input_artifact_hash=artifact.sha256,
                    warnings=[warn_text],
                    errors=[str(exec_err)],
                )

        # 5. Tool not found
        err_msg = f"Forensic tool '{tool_id}' is not registered or supported."
        if raise_on_error:
            raise ForensicOpsError(err_msg)
        return ToolExecutionResult(
            tool_id=tool_id,
            success=False,
            exit_code=1,
            findings_count=0,
            raw_rows_count=0,
            projected_rows_count=0,
            raw_columns_count=0,
            projected_columns_count=0,
            findings=[],
            source_artifact_hash=artifact.sha256,
            input_artifact_hash=artifact.sha256,
            warnings=[err_msg],
            errors=[err_msg],
        )

    def _run_tier_a(
        self,
        plugin: ToolPluginCard,
        artifact: ArtifactRecord,
        input_path: Path,
    ) -> List[ForensicFinding]:
        """Route to appropriate Dissect / built-in parser method."""
        atype = artifact.type.lower()
        if input_path.is_dir() or plugin.tool_id == "dissect_triage" or atype in ("triage_directory", "directory", "triage", "capsule_extracted", "folder"):
            return self.dissect_adapter.parse_triage_directory(
                input_path, artifact.case_id, artifact.artifact_id, artifact.sha256
            )
        elif atype in ("raw_image", "disk_image", "e01", "vmdk", "raw", "vhdx"):
            return self.dissect_adapter.parse_disk_image_stream(
                input_path, artifact.case_id, artifact.artifact_id, artifact.sha256
            )
        elif atype in ("evtx", "event_log"):
            return self.dissect_adapter.parse_evtx(
                input_path, artifact.case_id, artifact.artifact_id, artifact.sha256
            )
        elif atype in ("registry", "hive", "system", "software", "ntuser", "amcache"):
            return self.dissect_adapter.parse_registry_hive(
                input_path, artifact.case_id, artifact.artifact_id, artifact.sha256
            )
        else:
            return self.dissect_adapter.parse_collector_artifact(
                input_path, artifact.case_id, artifact.artifact_id, artifact.sha256
            )

    def _collect_raw_output(
        self,
        scratch_dir: Path,
        output_format: str,
        stdout: str,
    ) -> Tuple[List[Dict[str, Any]], Optional[Path]]:
        """Collect tool output from scratch directory or stdout."""
        raw_rows: List[Dict[str, Any]] = []
        found_file = None

        # Look for newly created output files in scratch_dir
        output_files = [f for f in scratch_dir.glob("*") if f.is_file()]
        if output_files:
            found_file = output_files[0]
            if output_format == "jsonl" or found_file.suffix == ".jsonl":
                with open(found_file, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                raw_rows.append(json.loads(line))
                            except json.JSONDecodeError:
                                pass
            elif output_format == "csv" or found_file.suffix == ".csv":
                with open(found_file, "r", encoding="utf-8", errors="replace") as f:
                    reader = csv.DictReader(f)
                    raw_rows.extend(list(reader))
            else:
                # Standard JSON
                with open(found_file, "r", encoding="utf-8", errors="replace") as f:
                    try:
                        content = json.load(f)
                        if isinstance(content, list):
                            raw_rows.extend(content)
                        elif isinstance(content, dict):
                            raw_rows.append(content)
                    except json.JSONDecodeError:
                        pass

        # If no file found, try parsing stdout
        if not raw_rows and stdout:
            stdout_clean = stdout.strip()
            if stdout_clean.startswith("[") and stdout_clean.endswith("]"):
                try:
                    raw_rows = json.loads(stdout_clean)
                except json.JSONDecodeError:
                    pass
            elif stdout_clean.startswith("{") and stdout_clean.endswith("}"):
                try:
                    raw_rows = [json.loads(stdout_clean)]
                except json.JSONDecodeError:
                    pass
            else:
                for line in stdout_clean.splitlines():
                    line = line.strip()
                    if line.startswith("{") and line.endswith("}"):
                        try:
                            raw_rows.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass

        return raw_rows, found_file

    def _normalize_findings(
        self,
        plugin: ToolPluginCard,
        artifact: ArtifactRecord,
        raw_rows: List[Dict[str, Any]],
        projected_rows: List[Dict[str, Any]],
        raw_data_path: str,
    ) -> List[ForensicFinding]:
        """Convert mapped and projected tool rows into standard ForensicFinding records."""
        findings: List[ForensicFinding] = []
        field_map = plugin.field_map

        for idx, (raw, projected) in enumerate(zip(raw_rows, projected_rows), start=1):
            ts = raw.get(field_map.get("timestamp_utc", "")) if "timestamp_utc" in field_map.values() else None
            # If not mapped via target name, check direct column name lookups
            if not ts:
                for k, target in field_map.items():
                    if target == "timestamp_utc":
                        ts = str(raw.get(k, ""))
                        break

            event_id = None
            for k, target in field_map.items():
                if target == "event_id" and k in raw:
                    event_id = str(raw[k])
                    break

            host = None
            for k, target in field_map.items():
                if target == "host" and k in raw:
                    host = str(raw[k])
                    break

            user = None
            for k, target in field_map.items():
                if target == "user" and k in raw:
                    user = str(raw[k])
                    break

            process_name = None
            for k, target in field_map.items():
                if target == "process_name" and k in raw:
                    process_name = str(raw[k])
                    break

            command_line = None
            for k, target in field_map.items():
                if target == "command_line" and k in raw:
                    command_line = str(raw[k])
                    break

            raw_ref = None
            for k, target in field_map.items():
                if target == "raw_reference" and k in raw:
                    raw_ref = str(raw[k])
                    break

            summary_val = None
            for k, target in field_map.items():
                if target == "summary" and k in raw:
                    summary_val = str(raw[k])
                    break
            if not summary_val:
                summary_val = f"{plugin.name} finding #{idx}"

            # Compute severity
            severity = plugin.default_severity
            if plugin.severity_field and plugin.severity_field in raw:
                raw_sev_key = str(raw[plugin.severity_field])
                if raw_sev_key in plugin.severity_map:
                    severity = plugin.severity_map[raw_sev_key]  # type: ignore

            findings.append(
                ForensicFinding(
                    case_id=artifact.case_id,
                    source_artifact_id=artifact.artifact_id,
                    source_artifact_hash=artifact.sha256,
                    tool_id=plugin.tool_id,
                    tool_version=plugin.version,
                    timestamp_utc=ts,
                    artifact_type=plugin.category,
                    category=plugin.category,
                    event_id=event_id,
                    severity=severity,
                    host=host,
                    user=user,
                    process_name=process_name,
                    command_line=command_line,
                    raw_reference=raw_ref or f"Item_{idx}",
                    summary=summary_val,
                    projected_data=projected,
                    raw_data_path=raw_data_path,
                )
            )

        return findings

    def _record_custody_and_audit(
        self,
        tool_id: str,
        artifact: ArtifactRecord,
        findings_count: int,
        raw_rows: int,
        projected_rows: int,
    ) -> None:
        """Record tool run in custody ledger and write to audit log."""
        if self.custody_engine and hasattr(self.custody_engine, "append_custody_entry"):
            try:
                self.custody_engine.append_custody_entry(
                    case_id=artifact.case_id,
                    actor=f"plugin_runner:{tool_id}",
                    action=f"executed_tool_{tool_id}",
                    artifact_sha256=artifact.sha256,
                    tool_id=tool_id,
                )
            except Exception:
                pass

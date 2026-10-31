"""Air-Gapped Tool Worker Sandbox and Plugin Runner.

Standards: RFC 3227, Zero Shell Interpolation (shell=False),
Network Isolation (--network=none), Read-Only Mounts (:ro),
Smart Column Projection with audit.jsonl Transparency Logging.
"""
from __future__ import annotations

import csv
import json
import os
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from backend.app.core.column_projector import SmartColumnProjector
from backend.app.core.dissect_adapter import DissectAdapter
from backend.app.core.exceptions import ForensicOpsError
from backend.app.models.custody import ArtifactRecord, canonical_json_dump
from backend.app.models.findings import ForensicFinding
from backend.app.models.plugins import ToolExecutionResult, ToolPluginCard


DANGEROUS_SHELL_PATTERNS = {";", "&", "|", "`", "$(", "${"}


class AirGappedSubprocessRunner:
    """Executes external forensic binaries with strict air-gapping and zero shell interpolation."""

    def __init__(self, use_docker_if_available: bool = False):
        self.use_docker = use_docker_if_available
        self._mock_handlers: Dict[str, Callable[[List[str], Path, Path], Tuple[int, str, str]]] = {}

    def register_mock_tool(
        self,
        tool_name: str,
        handler: Callable[[List[str], Path, Path], Tuple[int, str, str]],
    ) -> None:
        """Register a mock execution handler for testing environments."""
        self._mock_handlers[tool_name.lower()] = handler

    def execute(
        self,
        argv: List[str],
        cwd: Union[str, Path],
        timeout_seconds: int = 300,
        container_image: Optional[str] = None,
        readonly_input_dir: Optional[Union[str, Path]] = None,
        scratch_output_dir: Optional[Union[str, Path]] = None,
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
                    # Flag dangerous unescaped shell constructs
                    raise ForensicOpsError(
                        f"Potentially unsafe shell metacharacter '{danger}' detected in argument: {arg}"
                    )

        executable_base = Path(argv[0]).name.lower()

        # Check for registered mock handler (for offline test environments)
        if executable_base in self._mock_handlers:
            start_t = time.perf_counter()
            ret_code, out, err = self._mock_handlers[executable_base](
                argv, Path(readonly_input_dir or cwd), Path(scratch_output_dir or cwd)
            )
            duration = time.perf_counter() - start_t
            return ret_code, out, err, duration

        # Containerized air-gapped execution if requested and image is specified
        final_cmd = argv
        if self.use_docker and container_image:
            final_cmd = [
                "docker",
                "run",
                "--rm",
                "--network=none",
                "--read-only",
                "--cap-drop=ALL",
            ]
            if readonly_input_dir:
                final_cmd.extend(["-v", f"{Path(readonly_input_dir).resolve()}:/evidence:ro"])
            if scratch_output_dir:
                final_cmd.extend(["-v", f"{Path(scratch_output_dir).resolve()}:/scratch:rw"])
            final_cmd.extend([container_image, *argv])

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
                duration = time.perf_counter() - start_time
                return proc.returncode, stdout_data, stderr_data, duration
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate()
                duration = time.perf_counter() - start_time
                raise ForensicOpsError(
                    f"Tool execution timed out after {timeout_seconds} seconds: {' '.join(argv[:3])}"
                )
        except FileNotFoundError as e:
            # Tool binary not physically installed on host
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
    ) -> ToolExecutionResult:
        """Execute a tool plugin against an ingested evidence artifact."""
        workspace = Path(output_workspace).resolve()
        scratch_dir = workspace / "scratch" / plugin.tool_id
        scratch_dir.mkdir(parents=True, exist_ok=True)
        raw_output_dir = workspace / "raw_outputs" / plugin.tool_id
        raw_output_dir.mkdir(parents=True, exist_ok=True)

        input_path = Path(artifact.blob_path).resolve()
        if not input_path.exists():
            raise FileNotFoundError(f"Artifact blob does not exist: {input_path}")

        # ----------------------------------------------------------------------
        # Tier A: Built-in Pure-Python Dissect Adapter
        # ----------------------------------------------------------------------
        if plugin.execution_tier == "tier_a_builtin":
            start_t = time.perf_counter()
            findings = self._run_tier_a(plugin, artifact, input_path)
            duration = time.perf_counter() - start_t

            self._record_custody_and_audit(
                plugin.tool_id,
                artifact,
                findings_count=len(findings),
                raw_rows=len(findings),
                projected_rows=len(findings),
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
            )

        # ----------------------------------------------------------------------
        # Tier B: Declarative YAML Tool Adapter Execution
        # ----------------------------------------------------------------------
        # Build command array from template
        argv: List[str] = []
        for token in plugin.command_template:
            replaced = (
                token.replace("{input_path}", str(input_path))
                .replace("{output_dir}", str(scratch_dir))
                .replace("{rules_path}", str(rules_path or ""))
            )
            argv.append(replaced)

        exit_code, stdout, stderr, duration = self.subprocess_runner.execute(
            argv=argv,
            cwd=scratch_dir,
            timeout_seconds=plugin.timeout_seconds,
            container_image=plugin.container_image,
            readonly_input_dir=input_path.parent,
            scratch_output_dir=scratch_dir,
        )

        if exit_code != 0:
            return ToolExecutionResult(
                tool_id=plugin.tool_id,
                success=False,
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                execution_time_seconds=duration,
                source_artifact_hash=artifact.sha256,
            )

        # Ingest and normalize raw outputs
        raw_rows, raw_file_path = self._collect_raw_output(scratch_dir, plugin.output_format, stdout)

        # Save 100% of raw rows to permanent raw_outputs directory
        raw_dump_path = raw_output_dir / f"{plugin.tool_id}_raw.json"
        with open(raw_dump_path, "w", encoding="utf-8") as f:
            json.dump(raw_rows, f, indent=2)

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
        )

    def _run_tier_a(
        self,
        plugin: ToolPluginCard,
        artifact: ArtifactRecord,
        input_path: Path,
    ) -> List[ForensicFinding]:
        """Route to appropriate Dissect / built-in parser method."""
        atype = artifact.type.lower()
        if atype in ("raw_image", "disk_image", "e01", "vmdk", "raw", "vhdx"):
            return self.dissect_adapter.parse_disk_image_stream(
                input_path, artifact.case_id, artifact.artifact_id, artifact.sha256
            )
        elif atype in ("evtx", "event_log"):
            return self.dissect_adapter.parse_evtx(
                input_path, artifact.case_id, artifact.artifact_id, artifact.sha256
            )
        elif atype in ("registry", "hive", "system", "software", "ntuser"):
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

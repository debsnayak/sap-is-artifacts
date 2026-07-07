#!/usr/bin/env python3
"""
sap_is_github_sync.py
======================
Syncs SAP Integration Suite (Cloud Foundry) design-time artifacts into a
local GitHub repository checkout, committing only NEW/CHANGED versions,
and detects drift in both directions:

  * Forward drift  - SAP IS content changed without a version bump
  * Reverse drift  - files in the Git repo were edited outside this pipeline
  * Certificate drift - security material approaching expiry

Designed to run unattended (e.g. from a GitHub Actions workflow) against a
repository that has already been `git checkout`-ed to REPO_DIR.

Usage:
    python sap_is_github_sync.py --env PRD --config config/environments.yaml
    python sap_is_github_sync.py --env PRD --config config/environments.yaml --dry-run
    python sap_is_github_sync.py --env PRD --config config/environments.yaml --no-push

Requires: requests, PyYAML   (pip install requests pyyaml)
"""

import argparse
import base64
import csv
import hashlib
import io
import json
import logging
import os
import subprocess
import sys
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests
import yaml

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("sap_is_github_sync")


def atomic_write_text(path: Path, content: str):
    """Write content to path atomically - either the full new content lands, or the old
    file is left untouched. Prevents a killed/cancelled run from leaving a truncated
    (non-empty but invalid) JSON file behind."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + f".tmp{os.getpid()}")
    tmp.write_text(content)
    os.replace(tmp, path)  # atomic on POSIX and Windows


def atomic_write_bytes(path: Path, data: bytes):
    """Same guarantee as atomic_write_text but for binary content (used to store the
    raw SAP IS export zip byte-for-byte, so a killed/cancelled run can never leave a
    truncated/corrupt zip behind)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + f".tmp{os.getpid()}")
    tmp.write_bytes(data)
    os.replace(tmp, path)

# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------

@dataclass
class EnvConfig:
    name: str
    host: str                     # e.g. https://<tenant>.it-cpi<xx>-rt.cfapps.<region>.hana.ondemand.com
    token_url: str                # OAuth token endpoint
    client_id: str
    client_secret: str
    repo_dir: str                 # local path to the checked-out GitHub repo
    branch: str = "main"
    git_remote: str = "origin"
    git_user_name: str = "sap-is-sync-bot"
    git_user_email: str = "sap-is-sync-bot@users.noreply.github.com"
    cert_expiry_warning_days: int = 30
    verify_ssl: bool = True


def load_config(path: str, env_name: str) -> EnvConfig:
    with open(path, "r") as fh:
        raw = yaml.safe_load(fh)
    envs = raw.get("environments", {})
    if env_name not in envs:
        raise SystemExit(f"Environment '{env_name}' not found in {path}. Available: {list(envs)}")
    e = envs[env_name]

    def resolve(v):
        # Allow ${ENV_VAR} indirection so secrets stay in CI secrets, not the YAML file
        if isinstance(v, str) and v.startswith("${") and v.endswith("}"):
            var = v[2:-1]
            val = os.environ.get(var)
            if val is None:
                raise SystemExit(f"Required environment variable '{var}' is not set")
            return val
        return v

    return EnvConfig(
        name=env_name,
        host=resolve(e["host"]),
        token_url=resolve(e["token_url"]),
        client_id=resolve(e["client_id"]),
        client_secret=resolve(e["client_secret"]),
        repo_dir=resolve(e.get("repo_dir", ".")),
        branch=e.get("branch", "main"),
        git_remote=e.get("git_remote", "origin"),
        git_user_name=e.get("git_user_name", "sap-is-sync-bot"),
        git_user_email=e.get("git_user_email", "sap-is-sync-bot@users.noreply.github.com"),
        cert_expiry_warning_days=int(e.get("cert_expiry_warning_days", 30)),
        verify_ssl=bool(e.get("verify_ssl", True)),
    )


# --------------------------------------------------------------------------
# SAP Integration Suite client
# --------------------------------------------------------------------------

# Maps a logical artifact class to (OData entity set, repo subfolder, file extension label)
ARTIFACT_CLASSES = {
    "iflow":              {"entity": "IntegrationDesigntimeArtifacts",   "folder": "iflows"},
    "message_mapping":    {"entity": "MessageMappingDesigntimeArtifacts","folder": "message_mappings"},
    "value_mapping":      {"entity": "ValueMappingDesigntimeArtifacts",  "folder": "value_mappings"},
    "script_collection":  {"entity": "ScriptCollectionDesigntimeArtifacts", "folder": "script_collections"},
}


class SapIsClient:
    def __init__(self, cfg: EnvConfig):
        self.cfg = cfg
        self._token: Optional[str] = None
        self._session = requests.Session()

    def authenticate(self):
        log.info("Authenticating to SAP IS tenant (%s)", self.cfg.name)
        resp = self._session.post(
            self.cfg.token_url,
            data={"grant_type": "client_credentials"},
            auth=(self.cfg.client_id, self.cfg.client_secret),
            verify=self.cfg.verify_ssl,
            timeout=30,
        )
        resp.raise_for_status()
        self._token = resp.json()["access_token"]
        self._session.headers.update({
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/json",
        })
        log.info("Authenticated OK")

    def _api(self, path: str, params: dict = None) -> dict:
        url = f"{self.cfg.host}/api/v1/{path}"
        # SAP IS OData v2 services default to Atom/XML unless JSON is explicitly requested.
        # The Accept header (set in authenticate()) covers most cases; $format=json is the
        # OData v2 belt-and-braces query param some tenants still require.
        merged_params = {"$format": "json", **(params or {})}
        resp = self._session.get(url, params=merged_params, verify=self.cfg.verify_ssl, timeout=60)
        resp.raise_for_status()
        try:
            return resp.json().get("d", {})
        except ValueError:
            snippet = resp.text[:300].replace("\n", " ")
            content_type = resp.headers.get("Content-Type", "unknown")
            raise RuntimeError(
                f"Non-JSON response from {url} "
                f"(status={resp.status_code}, content-type={content_type}). "
                f"The host/endpoint is likely correct, but the tenant returned Atom/XML instead of JSON "
                f"(SAP IS OData v2 default format). If this persists even with Accept: application/json "
                f"and $format=json set, check whether an intermediary (proxy/API gateway) is stripping "
                f"the Accept header. Response body starts with: {snippet!r}"
            ) from None

    def list_packages(self) -> list:
        data = self._api("IntegrationPackages")
        return data.get("results", [])

    def list_artifacts(self, package_id: str, entity_set: str) -> list:
        # Artifacts are nested under IntegrationPackages(Id)/<EntitySet>
        path = f"IntegrationPackages('{package_id}')/{entity_set}"
        try:
            data = self._api(path)
            return data.get("results", [])
        except requests.HTTPError as ex:
            if ex.response is not None and ex.response.status_code == 404:
                return []
            raise

    def download_artifact_content(self, entity_set: str, artifact_id: str, version: str) -> bytes:
        # GET .../<EntitySet>(Id='..',Version='..')/$value returns a zip archive
        url = f"{self.cfg.host}/api/v1/{entity_set}(Id='{artifact_id}',Version='{version}')/$value"
        resp = self._session.get(url, verify=self.cfg.verify_ssl, timeout=120)
        resp.raise_for_status()
        return resp.content

    def download_package_content(self, package_id: str) -> bytes:
        # GET .../IntegrationPackages('Id')/$value returns the ENTIRE package as a zip -
        # same $value convention as individual artifacts, just at the package level.
        # Note: packages in "Configure Only" mode cannot be exported this way - SAP IS
        # returns an error for those; callers should treat that as skip-with-warning,
        # not a fatal failure of the whole run.
        url = f"{self.cfg.host}/api/v1/IntegrationPackages('{package_id}')/$value"
        resp = self._session.get(url, verify=self.cfg.verify_ssl, timeout=300)
        resp.raise_for_status()
        return resp.content

    def list_security_material(self) -> list:
        # Certificates / keystore entries - metadata only, never the key material itself
        try:
            data = self._api("SecurityMaterials")
            return data.get("results", [])
        except requests.HTTPError:
            log.warning("SecurityMaterials API not available on this tenant/plan - skipping certificate inventory")
            return []


# --------------------------------------------------------------------------
# Manifest (authoritative sync state)
# --------------------------------------------------------------------------

class Manifest:
    """
    sync_manifest.json structure:
    {
      "<artifact_id>": {
        "class": "iflow",
        "package_id": "...",
        "name": "...",
        "version": "1.4.0",
        "sha256": "...",
        "last_synced": "2026-07-01T02:00:00Z"
      },
      ...
    }
    """

    def __init__(self, path: Path):
        self.path = path
        self.data: dict = {}
        if path.exists() and path.stat().st_size > 0:
            try:
                self.data = json.loads(path.read_text())
            except json.JSONDecodeError as ex:
                log.warning(
                    "sync_manifest.json exists but could not be parsed (%s) - treating as empty. "
                    "Every artifact will be re-evaluated as new this run.", ex
                )
                self.data = {}

    def get(self, artifact_id: str) -> Optional[dict]:
        return self.data.get(artifact_id)

    def update(self, artifact_id: str, **kwargs):
        entry = self.data.setdefault(artifact_id, {})
        entry.update(kwargs)
        entry["last_synced"] = datetime.now(timezone.utc).isoformat()

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(self.path, json.dumps(self.data, indent=2, sort_keys=True))


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_dir(path: Path) -> str:
    """Deterministic checksum of a directory's file contents (for reverse-drift checks)."""
    h = hashlib.sha256()
    for f in sorted(path.rglob("*")):
        if f.is_file():
            h.update(str(f.relative_to(path)).encode())
            h.update(f.read_bytes())
    return h.hexdigest()


def safe_name(name: str) -> str:
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in name)


def extract_zip(content: bytes, dest_dir: Path):
    if dest_dir.exists():
        for f in dest_dir.rglob("*"):
            if f.is_file():
                f.unlink()
    dest_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(content)) as zf:
        zf.extractall(dest_dir)


def zip_artifact_for_restore(artifact_dir: Path, output_zip: Path = None) -> Path:
    """Zip an artifact folder's CONTENTS (not the folder itself) so the result is a
    valid SAP IS import package as-is - no manual 're-zip the right way' step needed.

    This is the inverse of extract_zip(): SAP IS expects META-INF/, metainfo.prop, and
    src/main/resources/ at the ROOT of the zip. Naively zipping the folder (e.g. right-click
    -> Compress, or `zip -r x.zip folder/`) nests everything one level too deep and SAP IS
    rejects or silently mishandles the import. This function always writes entries with
    paths relative to artifact_dir's contents, so the root is correct regardless of platform
    or which zip tool would otherwise have been used.
    """
    artifact_dir = Path(artifact_dir).resolve()
    if not artifact_dir.is_dir():
        raise FileNotFoundError(f"Not a directory: {artifact_dir}")

    if output_zip is None:
        output_zip = artifact_dir.parent / f"{artifact_dir.name}.zip"
    output_zip = Path(output_zip)

    # Sidecar metadata lives next to the folder (see sync engine), so it's naturally
    # excluded already - nothing to filter out. Any stray .artifact.json inside an
    # older-style folder is skipped defensively anyway.
    with zipfile.ZipFile(output_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in sorted(artifact_dir.rglob("*")):
            if f.is_file() and f.name != "artifact.json":
                arcname = f.relative_to(artifact_dir).as_posix()  # forward slashes, cross-platform
                zf.write(f, arcname)

    return output_zip


def run_git(repo_dir: str, *args) -> str:
    result = subprocess.run(["git", "-C", repo_dir, *args], capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


# --------------------------------------------------------------------------
# Core sync
# --------------------------------------------------------------------------

@dataclass
class DriftReport:
    forward_drift: list = field(default_factory=list)   # SAP IS changed without version bump
    reverse_drift: list = field(default_factory=list)   # Git repo edited outside pipeline
    cert_drift: list = field(default_factory=list)       # certificates nearing expiry
    synced: list = field(default_factory=list)           # artifacts newly synced this run

    def has_findings(self) -> bool:
        return bool(self.forward_drift or self.reverse_drift or self.cert_drift)

    def to_dict(self) -> dict:
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "synced": self.synced,
            "forward_drift": self.forward_drift,
            "reverse_drift": self.reverse_drift,
            "cert_drift": self.cert_drift,
        }


class SyncEngine:
    def __init__(self, cfg: EnvConfig, client: SapIsClient, dry_run: bool = False, package_filter: list = None):
        self.cfg = cfg
        self.client = client
        self.dry_run = dry_run
        self.repo_root = Path(cfg.repo_dir)
        self.manifest = Manifest(self.repo_root / "sync_manifest.json")
        self.report = DriftReport()
        # Case-insensitive match against either the package Id or the package Name
        self.package_filter = {p.strip().lower() for p in package_filter} if package_filter else None

    def run(self):
        packages = self.client.list_packages()
        log.info("Found %d integration package(s) on tenant", len(packages))

        if self.package_filter:
            before = len(packages)
            packages = [
                p for p in packages
                if p.get("Id", "").lower() in self.package_filter
                or p.get("Name", "").lower() in self.package_filter
            ]
            matched = {p.get("Id", "").lower() for p in packages} | {p.get("Name", "").lower() for p in packages}
            unmatched = self.package_filter - matched
            if unmatched:
                log.warning("No match found on tenant for requested package(s): %s", ", ".join(sorted(unmatched)))
            log.info("Package filter applied: %d of %d package(s) selected", len(packages), before)

        for pkg in packages:
            pkg_id = pkg["Id"]
            pkg_name = safe_name(pkg.get("Name", pkg_id))
            pkg_dir = self.repo_root / "packages" / pkg_name
            self._write_package_manifest(pkg_dir, pkg)
            self._process_package_zip(pkg_id, pkg_name, pkg_dir, pkg)

            for cls_key, cls_meta in ARTIFACT_CLASSES.items():
                artifacts = self.client.list_artifacts(pkg_id, cls_meta["entity"])
                for art in artifacts:
                    self._process_artifact(pkg_id, pkg_name, cls_key, cls_meta, art)

        self._check_certificate_drift()
        self.manifest.save()
        self._write_drift_report()

        if not self.dry_run:
            self._commit_and_push()
        else:
            log.info("[dry-run] Skipping git commit/push")

        return self.report

    # -- package metadata -------------------------------------------------

    def _write_package_manifest(self, pkg_dir: Path, pkg: dict):
        pkg_dir.mkdir(parents=True, exist_ok=True)
        meta = {
            "id": pkg["Id"],
            "name": pkg.get("Name"),
            "version": pkg.get("Version"),
            "description": pkg.get("ShortText") or pkg.get("Description"),
            "mode": pkg.get("Mode"),
        }
        atomic_write_text(pkg_dir / "package.json", json.dumps(meta, indent=2))

    def _process_package_zip(self, pkg_id: str, pkg_name: str, pkg_dir: Path, pkg: dict):
        """Whole-package export: the entire Integration Package as a single zip, stored
        exactly as SAP IS returns it - byte-for-byte, same principle as individual
        artifacts. Restoring a whole package is then just: pull this one file, Import.
        Manifest key is namespaced (package:<id>) so it never collides with an artifact ID.
        """
        if pkg.get("Mode") == "CONFIGURE_ONLY":
            log.info("Package '%s' is Configure Only - whole-package export not supported by SAP IS, skipping", pkg_name)
            return

        manifest_key = f"package:{pkg_id}"
        current_version = str(pkg.get("Version"))
        manifest_entry = self.manifest.get(manifest_key)

        package_zip_path = pkg_dir / f"{pkg_name}.zip"

        # --- Reverse drift check ---
        if manifest_entry and package_zip_path.exists():
            on_disk_hash = sha256_bytes(package_zip_path.read_bytes())
            if on_disk_hash != manifest_entry.get("content_sha256"):
                self.report.reverse_drift.append({
                    "artifact_id": manifest_key,
                    "name": pkg_name,
                    "package": pkg_name,
                    "message": "Package zip differs from last synced state without a new sync run "
                               "- possible manual edit in Git outside the pipeline.",
                })

        needs_sync = (manifest_entry is None) or (manifest_entry.get("version") != current_version)

        try:
            if not needs_sync:
                if manifest_entry:
                    content = self.client.download_package_content(pkg_id)
                    content_hash = sha256_bytes(content)
                    if content_hash != manifest_entry.get("source_sha256"):
                        self.report.forward_drift.append({
                            "artifact_id": manifest_key,
                            "name": pkg_name,
                            "package": pkg_name,
                            "version": current_version,
                            "message": "SAP IS package content checksum changed without a version increment.",
                        })
                return

            log.info("New package version detected: %s  %s -> %s",
                     pkg_name, manifest_entry.get("version") if manifest_entry else "(none)", current_version)
            content = self.client.download_package_content(pkg_id)
            source_hash = sha256_bytes(content)

            if not self.dry_run:
                atomic_write_bytes(package_zip_path, content)
                content_hash = source_hash
            else:
                content_hash = source_hash

            self.manifest.update(
                manifest_key,
                **{
                    "class": "package",
                    "package_id": pkg_id,
                    "name": pkg_name,
                    "version": current_version,
                    "source_sha256": source_hash,
                    "content_sha256": content_hash,
                },
            )
            self.report.synced.append({
                "artifact_id": manifest_key, "name": pkg_name, "package": pkg_name,
                "class": "package", "version": current_version,
            })
        except requests.HTTPError as ex:
            status = ex.response.status_code if ex.response is not None else "?"
            log.warning("Whole-package export failed for '%s' (HTTP %s) - skipping package-level zip "
                        "this run; individual artifact sync is unaffected. %s", pkg_name, status, ex)

    # -- per-artifact processing -------------------------------------------

    def _process_artifact(self, pkg_id: str, pkg_name: str, cls_key: str, cls_meta: dict, art: dict):
        artifact_id = art["Id"]
        artifact_name = safe_name(art.get("Name", artifact_id))
        current_version = str(art.get("Version"))

        manifest_entry = self.manifest.get(artifact_id)
        # The artifact is stored as a single zip file - exactly the bytes SAP IS exported,
        # byte-for-byte. No extraction, no re-zipping ever needed: pull this file from the
        # repo and import it into SAP IS as-is.
        class_dir = self.repo_root / "packages" / pkg_name / cls_meta["folder"]
        artifact_zip_path = class_dir / f"{artifact_name}.zip"
        sidecar_path = class_dir / f"{artifact_name}.json"

        # --- Reverse drift check: has the on-disk zip been hand-edited since last sync? ---
        if manifest_entry and artifact_zip_path.exists():
            on_disk_hash = sha256_bytes(artifact_zip_path.read_bytes())
            if on_disk_hash != manifest_entry.get("content_sha256"):
                self.report.reverse_drift.append({
                    "artifact_id": artifact_id,
                    "name": artifact_name,
                    "package": pkg_name,
                    "message": "Repository zip differs from last synced state without a new sync run "
                               "- possible manual edit in Git outside the pipeline.",
                })

        # --- Is this a new version we need to pull? ---
        needs_sync = (manifest_entry is None) or (manifest_entry.get("version") != current_version)

        if not needs_sync:
            # Same version reported by SAP IS - but check for a silent (un-versioned) content change
            if manifest_entry:
                content = self.client.download_artifact_content(cls_meta["entity"], artifact_id, current_version)
                content_hash = sha256_bytes(content)
                if content_hash != manifest_entry.get("source_sha256"):
                    self.report.forward_drift.append({
                        "artifact_id": artifact_id,
                        "name": artifact_name,
                        "package": pkg_name,
                        "version": current_version,
                        "message": "SAP IS content checksum changed without a version increment "
                                   "- artifact may have been saved without creating a new version.",
                    })
            return

        log.info("New version detected: [%s] %s  %s -> %s",
                 cls_key, artifact_name,
                 manifest_entry.get("version") if manifest_entry else "(none)",
                 current_version)

        content = self.client.download_artifact_content(cls_meta["entity"], artifact_id, current_version)
        source_hash = sha256_bytes(content)

        if not self.dry_run:
            # Write the raw zip exactly as downloaded - this IS the SAP IS export, unmodified.
            atomic_write_bytes(artifact_zip_path, content)
            atomic_write_text(sidecar_path, json.dumps({
                "id": artifact_id,
                "name": art.get("Name"),
                "class": cls_key,
                "package_id": pkg_id,
                "version": current_version,
                "sha256": source_hash,
                "synced_at": datetime.now(timezone.utc).isoformat(),
            }, indent=2))
            content_hash = source_hash  # stored file is byte-identical to what was downloaded
        else:
            content_hash = source_hash  # best effort in dry-run, no write performed

        self.manifest.update(
            artifact_id,
            **{
                "class": cls_key,
                "package_id": pkg_id,
                "name": art.get("Name"),
                "version": current_version,
                "source_sha256": source_hash,
                "content_sha256": content_hash,
            },
        )
        self.report.synced.append({
            "artifact_id": artifact_id, "name": artifact_name, "package": pkg_name,
            "class": cls_key, "version": current_version,
        })

    # -- certificate / security material drift -----------------------------

    def _check_certificate_drift(self):
        materials = self.client.list_security_material()
        if not materials:
            return

        rows = []
        now = datetime.now(timezone.utc)
        for m in materials:
            alias = m.get("Alias") or m.get("Name")
            expiry_raw = m.get("ExpiryDate") or m.get("ValidTo")
            expiry = self._parse_sap_date(expiry_raw)
            days_left = (expiry - now).days if expiry else None
            rows.append({
                "alias": alias,
                "type": m.get("Type"),
                "owner": m.get("User") or m.get("Owner", ""),
                "expiry": expiry.isoformat() if expiry else "unknown",
                "days_left": days_left,
            })
            if days_left is not None and days_left <= self.cfg.cert_expiry_warning_days:
                self.report.cert_drift.append({
                    "alias": alias,
                    "expiry": expiry.isoformat(),
                    "days_left": days_left,
                    "message": f"Certificate '{alias}' expires in {days_left} day(s).",
                })

        if not self.dry_run:
            sec_dir = self.repo_root / "security"
            sec_dir.mkdir(parents=True, exist_ok=True)
            with open(sec_dir / "certificate_inventory.csv", "w", newline="") as fh:
                writer = csv.DictWriter(fh, fieldnames=["alias", "type", "owner", "expiry", "days_left"])
                writer.writeheader()
                writer.writerows(rows)

    @staticmethod
    def _parse_sap_date(raw) -> Optional[datetime]:
        if not raw:
            return None
        # SAP OData often returns /Date(1735689600000)/ style timestamps
        if isinstance(raw, str) and raw.startswith("/Date("):
            millis = int(raw[6:-2].split("+")[0].split("-")[0])
            return datetime.fromtimestamp(millis / 1000, tz=timezone.utc)
        try:
            return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        except ValueError:
            return None

    # -- drift report --------------------------------------------------------

    def _write_drift_report(self):
        report_dir = self.repo_root / "drift_report"
        report_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        report_path = report_dir / f"drift_{ts}.json"
        payload = self.report.to_dict()

        if not self.dry_run:
            content = json.dumps(payload, indent=2)
            atomic_write_text(report_path, content)
            latest = report_dir / "latest.json"
            atomic_write_text(latest, content)

        log.info("Sync summary: %d synced, %d forward drift, %d reverse drift, %d cert warning(s)",
                  len(self.report.synced), len(self.report.forward_drift),
                  len(self.report.reverse_drift), len(self.report.cert_drift))

        for item in self.report.forward_drift:
            log.warning("FORWARD DRIFT: %s", item["message"] + f" [{item['name']}]")
        for item in self.report.reverse_drift:
            log.warning("REVERSE DRIFT: %s", item["message"] + f" [{item['name']}]")
        for item in self.report.cert_drift:
            log.warning("CERT DRIFT: %s", item["message"])

    # -- git commit / push ----------------------------------------------------

    def _commit_and_push(self):
        status = run_git(str(self.repo_root), "status", "--porcelain")
        if not status:
            log.info("No changes to commit.")
            return

        run_git(str(self.repo_root), "config", "user.name", self.cfg.git_user_name)
        run_git(str(self.repo_root), "config", "user.email", self.cfg.git_user_email)
        run_git(str(self.repo_root), "add", "-A")

        if self.report.synced:
            lines = [f"- {a['package']}/{a['name']} -> v{a['version']} ({a['class']})" for a in self.report.synced]
            msg = f"SAP IS sync ({self.cfg.name}): {len(self.report.synced)} artifact(s) updated\n\n" + "\n".join(lines)
        else:
            msg = f"SAP IS sync ({self.cfg.name}): metadata/inventory refresh"

        run_git(str(self.repo_root), "commit", "-m", msg)
        run_git(str(self.repo_root), "push", self.cfg.git_remote, self.cfg.branch)
        log.info("Pushed sync commit to %s/%s", self.cfg.git_remote, self.cfg.branch)


# --------------------------------------------------------------------------
# Notification hook (extend for Slack / Teams / email)
# --------------------------------------------------------------------------

def notify_drift(report: DriftReport, cfg: EnvConfig):
    if not report.has_findings():
        return
    webhook = os.environ.get("DRIFT_NOTIFY_WEBHOOK_URL")
    if not webhook:
        log.info("DRIFT_NOTIFY_WEBHOOK_URL not set - skipping external notification (findings logged above)")
        return
    summary = (
        f"SAP IS <-> GitHub drift detected on {cfg.name}: "
        f"{len(report.forward_drift)} forward, {len(report.reverse_drift)} reverse, "
        f"{len(report.cert_drift)} certificate warning(s)."
    )
    try:
        requests.post(webhook, json={"text": summary}, timeout=15)
    except requests.RequestException as ex:
        log.warning("Failed to post drift notification: %s", ex)


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Sync SAP Integration Suite artifacts to GitHub with drift detection")
    parser.add_argument("--env", help="Environment name as defined in the config file")
    parser.add_argument("--config", help="Path to environments.yaml")
    parser.add_argument("--dry-run", action="store_true", help="Do not write files or push to git")
    parser.add_argument("--no-push", action="store_true", help="Write files/commit locally but do not push")
    parser.add_argument(
        "--packages",
        help="Comma-separated list of Integration Package Id(s) or Name(s) to sync. "
             "If omitted, ALL packages on the tenant are synced.",
    )
    parser.add_argument(
        "--list-packages",
        action="store_true",
        help="Authenticate, print every package Id/Name available on the tenant, and exit "
             "(use this first to find the exact names to pass to --packages).",
    )
    parser.add_argument(
        "--make-restore-zip",
        metavar="ARTIFACT_DIR",
        help="Legacy-compatibility command for repos synced before artifacts were stored as "
             "raw zips: re-zips an extracted artifact FOLDER's contents into a ready-to-import "
             "ZIP. Not needed for artifacts synced by the current version of this script - those "
             "are already stored as a ready-to-import .zip file, no re-zipping required.",
    )
    parser.add_argument(
        "--output",
        help="Optional output path for --make-restore-zip (defaults to <ARTIFACT_DIR>.zip next to the folder)",
    )
    args = parser.parse_args()

    if args.make_restore_zip:
        out = zip_artifact_for_restore(Path(args.make_restore_zip), Path(args.output) if args.output else None)
        log.info("Restore-ready zip written to: %s", out)
        log.info("Upload this file as-is in SAP IS (Import Integration Flow / Mapping / Script Collection).")
        return

    if not args.env or not args.config:
        parser.error("--env and --config are required unless using --make-restore-zip")

    cfg = load_config(args.config, args.env)
    client = SapIsClient(cfg)
    client.authenticate()

    if args.list_packages:
        packages = client.list_packages()
        log.info("%d package(s) available on tenant '%s':", len(packages), cfg.name)
        for p in packages:
            print(f"  Id={p.get('Id')}\tName={p.get('Name')}")
        return

    package_filter = [p for p in args.packages.split(",")] if args.packages else None

    engine = SyncEngine(cfg, client, dry_run=args.dry_run, package_filter=package_filter)
    if args.no_push:
        engine._commit_and_push = lambda: log.info("--no-push set: skipping push")  # noqa: SLF001

    report = engine.run()
    notify_drift(report, cfg)

    # Non-zero exit on forward/reverse drift so CI can flag the run, without failing on cert warnings alone
    if report.forward_drift or report.reverse_drift:
        sys.exit(2)


if __name__ == "__main__":
    main()

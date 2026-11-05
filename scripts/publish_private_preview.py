# Private-only publisher: never send preview bundles to public Actions artifacts.
#!/usr/bin/env python3
"""Publish a sanitized CEO preview only to the verified private Enterprise-HQ repository."""
import base64
import hashlib
import json
import os
import pathlib
import urllib.error
import urllib.parse
import urllib.request
import zipfile

REPOSITORY = "bhagyamehta1-lab/Enterprise-HQ"
API = "https://api.github.com"
TOKEN = os.environ.get("ENTERPRISE_HQ_WRITE_TOKEN", "")
CANDIDATE = os.environ.get("CANDIDATE_SHA", "")
RUN_ID = os.environ.get("GITHUB_RUN_ID", "")
ROOT = pathlib.Path(os.environ.get("PREVIEW_DIR", "/dev/shm/enterprise_workspace/CEO_PREVIEW"))
FORBIDDEN_NAMES = {".env", ".env.local", ".env.production", "id_rsa", "credentials.json"}
FORBIDDEN_SUFFIXES = {".map", ".ts", ".tsx", ".sqlite", ".db"}
ALLOWED_PREVIEW_FILES = frozenset({
    "ply-erp-ceo-preview-build.zip",
    "CEO_APP_WALKTHROUGH.md",
    "preview-manifest.json",
})


def validate_preview_write_target(repository, path):
    if repository != REPOSITORY:
        raise SystemExit("Preview write rejected: repository is not Enterprise-HQ.")
    prefix = "previews/PLY-0003/" + CANDIDATE + "/"
    if not path.startswith(prefix):
        raise SystemExit("Preview write rejected: path is outside the exact PLY-0003 candidate directory.")
    relative = path[len(prefix):]
    if relative not in ALLOWED_PREVIEW_FILES or "/" in relative or "\\\\" in relative:
        raise SystemExit("Preview write rejected: file is not one of the three explicit private preview destinations.")
    return path


def self_test_write_path_guards():
    allowed = "previews/PLY-0003/" + CANDIDATE + "/preview-manifest.json"
    assert validate_preview_write_target(REPOSITORY, allowed) == allowed
    blocked = (
        ("bhagyamehta1-lab/PLY_ERP", allowed),
        (REPOSITORY, "state/ceo_command_audit.json"),
        (REPOSITORY, "previews/PLY-0003/" + CANDIDATE + "/extra.zip"),
        (REPOSITORY, "previews/PLY-0003/" + CANDIDATE + "/../preview-manifest.json"),
        ("bhagyamehta1-lab/ply-erp-builder", allowed),
    )
    for repository, path in blocked:
        try:
            validate_preview_write_target(repository, path)
        except SystemExit:
            continue
        raise SystemExit("Preview write-path self-test failed: an unauthorized target was accepted.")

self_test_write_path_guards()

if not TOKEN:
    raise SystemExit("Private preview destination credential is unavailable.")
if len(CANDIDATE) != 40 or any(c not in "0123456789abcdef" for c in CANDIDATE):
    raise SystemExit("Candidate SHA is invalid.")
if not RUN_ID.isdigit():
    raise SystemExit("Workflow run identity is invalid.")

HEADERS = {
    "Authorization": "Bearer " + TOKEN,
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "Content-Type": "application/json",
}

def api_request(method, path, payload=None, allow_404=False):
    if method.upper() not in ("GET", "HEAD"):
        prefix = "/repos/" + REPOSITORY + "/contents/"
        if method.upper() != "PUT" or not path.startswith(prefix):
            raise SystemExit("Private preview GitHub write rejected: only exact Enterprise-HQ preview Contents writes are allowed.")
        validate_preview_write_target(REPOSITORY, urllib.parse.unquote(path[len(prefix):].split("?", 1)[0]))
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(API + path, data=data, headers=HEADERS, method=method)
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if allow_404 and exc.code == 404:
            return None
        raise SystemExit("Private preview GitHub API request failed with HTTP " + str(exc.code)) from None

metadata = api_request("GET", "/repos/" + REPOSITORY)
if metadata.get("full_name", "").casefold() != REPOSITORY.casefold() or metadata.get("private") is not True:
    raise SystemExit("Enterprise-HQ identity/private visibility verification failed.")

dist = ROOT / "dist"
walkthrough = ROOT / "CEO_APP_WALKTHROUGH.md"
if not dist.is_dir() or not walkthrough.is_file():
    raise SystemExit("Preview bundle or walkthrough is missing.")

for file_path in ROOT.rglob("*"):
    if not file_path.is_file():
        continue
    if file_path.name in FORBIDDEN_NAMES or file_path.suffix.lower() in FORBIDDEN_SUFFIXES:
        raise SystemExit("Preview bundle contains a prohibited file type.")

archive = ROOT / "ply-erp-ceo-preview-build.zip"
with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as bundle:
    for file_path in sorted(dist.rglob("*")):
        if file_path.is_file():
            bundle.write(file_path, pathlib.Path("dist") / file_path.relative_to(dist))
    bundle.write(walkthrough, "CEO_APP_WALKTHROUGH.md")

archive_bytes = archive.read_bytes()
if len(archive_bytes) > 80 * 1024 * 1024:
    raise SystemExit("Preview archive exceeds the safe GitHub Contents API size limit.")

prefix = "previews/PLY-0003/" + CANDIDATE + "/"

def upload(relative_path, content, message):
    if relative_path not in ALLOWED_PREVIEW_FILES:
        raise SystemExit("Private preview upload rejected: destination is not explicitly allowlisted.")
    path = validate_preview_write_target(REPOSITORY, prefix + relative_path)
    existing = api_request(
        "GET",
        "/repos/" + REPOSITORY + "/contents/" + path + "?ref=main",
        allow_404=True,
    )
    payload = {
        "message": message,
        "content": base64.b64encode(content).decode("ascii"),
        "branch": "main",
    }
    if existing and existing.get("sha"):
        payload["sha"] = existing["sha"]
    result = api_request("PUT", "/repos/" + REPOSITORY + "/contents/" + path, payload)
    record = result.get("content") or {}
    if record.get("path") != path or not record.get("sha"):
        raise SystemExit("Private preview upload response did not verify.")
    verified = api_request("GET", "/repos/" + REPOSITORY + "/contents/" + path + "?ref=main")
    if verified.get("sha") != record["sha"]:
        raise SystemExit("Private preview uploaded content SHA did not verify.")
    return {"path": path, "git_blob_sha": record["sha"], "size_bytes": len(content)}

archive_sha256 = hashlib.sha256(archive_bytes).hexdigest()
archive_record = upload(
    "ply-erp-ceo-preview-build.zip",
    archive_bytes,
    "preview(PLY-0003): private CEO preview archive " + CANDIDATE,
)
walkthrough_record = upload(
    "CEO_APP_WALKTHROUGH.md",
    walkthrough.read_bytes(),
    "docs(PLY-0003): private CEO application walkthrough " + CANDIDATE,
)
manifest = {
    "artifact_name": "ply-erp-ceo-preview-build",
    "candidate_sha": CANDIDATE,
    "worker_run_id": RUN_ID,
    "destination_repository": REPOSITORY,
    "destination_visibility": "PRIVATE",
    "archive_sha256": archive_sha256,
    "files": [archive_record, walkthrough_record],
    "public_actions_artifact": False,
    "source_maps_included": False,
    "database_or_customer_data_included": False,
}
manifest_record = upload(
    "preview-manifest.json",
    json.dumps(manifest, indent=2).encode("utf-8"),
    "docs(PLY-0003): private preview manifest " + CANDIDATE,
)

print("ENTERPRISE_HQ_PRIVATE_REPOSITORY=VERIFIED")
print("CEO_PREVIEW_ARCHIVE_UPLOAD=PASS")
print("CEO_PREVIEW_WALKTHROUGH_UPLOAD=PASS")
print("CEO_PREVIEW_MANIFEST_UPLOAD=PASS")
print("CEO_PREVIEW_ARCHIVE_SHA256=" + archive_sha256)
print("CEO_PREVIEW_DESTINATION=PRIVATE_ENTERPRISE_HQ")
print("PUBLIC_ACTIONS_ARTIFACT=NOT_USED")

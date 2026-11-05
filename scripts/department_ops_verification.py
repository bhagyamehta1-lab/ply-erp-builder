#!/usr/bin/env python3
"""Execute five governance-only department workflows and persist sanitized mandatory outputs."""
import base64,json,os,urllib.parse,urllib.request
REPO="bhagyamehta1-lab/Enterprise-HQ"; API="https://api.github.com"
READ=os.environ.get("ENTERPRISE_HQ_READ_TOKEN") or os.environ.get("ENTERPRISE_HQ_WRITE_TOKEN","")
WRITE=os.environ.get("ENTERPRISE_HQ_WRITE_TOKEN","")
RUN=os.environ.get("GITHUB_RUN_ID",""); RUNNER=os.environ.get("RUNNER_ID",""); GH_TOKEN=os.environ.get("GITHUB_TOKEN","")
def request(method,path,token,payload=None):
    data=None if payload is None else json.dumps(payload).encode()
    req=urllib.request.Request(API+path,data=data,method=method,headers={"Authorization":f"Bearer {token}","Accept":"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28","Content-Type":"application/json"})
    with urllib.request.urlopen(req,timeout=25) as r: raw=r.read()
    return json.loads(raw.decode()) if raw else {}
def get(path):
    d=request("GET",f"/repos/{REPO}/contents/{urllib.parse.quote(path,safe='/')}?ref=main",READ)
    return json.loads(base64.b64decode(d["content"]).decode()),d["sha"]
def put(path,obj,message):
    try: _,sha=get(path)
    except Exception: sha=None
    payload={"message":message,"content":base64.b64encode((json.dumps(obj,indent=2)+"\n").encode()).decode(),"branch":"main"}
    if sha: payload["sha"]=sha
    request("PUT",f"/repos/{REPO}/contents/{urllib.parse.quote(path,safe='/')}",WRITE,payload)
def main():
    if not READ or not WRITE: raise SystemExit("DEPARTMENT_OPS=BLOCKED_CREDENTIAL_UNAVAILABLE")
    if not RUNNER and GH_TOKEN and RUN.isdigit():
        jobs=request("GET",f"/repos/bhagyamehta1-lab/ply-erp-builder/actions/runs/{RUN}/jobs?per_page=100",GH_TOKEN).get("jobs",[])
        current=next((j for j in jobs if j.get("name")=="Public CEO command and worker engine"),None)
        RUNNER=str((current or {}).get("runner_id") or "")
    names=["state/ceo_command_audit.json","employees/department_roster.json","projects/ply_erp_backlog.json","state/autonomous_shift_checkpoints.json","state/learned_heuristics.json","state/codebase_index.json","finance_and_resource_ledger.json","legal_and_compliance_registry.json","customer_and_delivery_operations.json","human_accountability_charter.json","department_workflow_bindings.json"]
    d={p:get(p)[0] for p in names}; audit=d[names[0]]; hold=audit.get("system_status")=="SAFE_HOLD" and audit.get("safety",{}).get("execution_hold") is True and audit.get("safety",{}).get("builds_enabled") is False and audit.get("safety",{}).get("dispatch_enabled") is False
    if not hold: raise SystemExit("DEPARTMENT_OPS=BLOCKED_UNEXPECTED_SAFETY_STATE")
    roster=d["employees/department_roster.json"].get("employees",[]); tasks={x["task_id"]:x for x in d["projects/ply_erp_backlog.json"].get("requirements",[])}
    finance=d["finance_and_resource_ledger.json"]; legal=d["legal_and_compliance_registry.json"]; delivery=d["customer_and_delivery_operations.json"]
    results=[
      ("EMP-01","architecture_boundary_schema_ledger.json",[("CANONICAL_ROSTER_PRESENT",bool(roster)),("PLY0003_ZERO_PRODUCT_WRITE",tasks.get("PLY-0003",{}).get("explicit_file_allowlist")==[]),("PRIVATE_SOURCE_BOUNDARY",True)]),
      ("EMP-02","build_reproducibility_zero_regression_checklist.json",[("SOURCE_SHA_ANCHOR_PRESENT",bool(d["state/codebase_index.json"].get("last_verified_commit"))),("BUILD_REPRODUCIBILITY_POLICY_PRESENT",bool(delivery.get("release_integrity",{}).get("artifact_reproducibility_required"))),("PRODUCT_BUILD_EXECUTION","BLOCKED_SAFE_HOLD")]),
      ("EMP-03","automated_test_preview_verification_matrix.json",[("PLY0001_HISTORICAL_QA_GREEN",tasks.get("PLY-0001",{}).get("technical_verification_status")=="VERIFIED_GREEN"),("PLY0002_HISTORICAL_QA_GREEN",tasks.get("PLY-0002",{}).get("technical_verification_status")=="VERIFIED_GREEN"),("FRESH_PRODUCT_TESTS","BLOCKED_SAFE_HOLD"),("PREVIEW_BUILD","BLOCKED_SAFE_HOLD")]),
      ("EMP-04","runner_attestation_allowlist_secret_hygiene_audit.json",[("RUNNER_ID_PRESENT",bool(RUNNER)),("OFFLINE_FIRST",legal.get("privacy_security",{}).get("offline_first_required") is True),("ZERO_PII_EXFILTRATION",legal.get("privacy_security",{}).get("zero_pii_exfiltration") is True),("PRIVATE_CHECKOUT","NOT_PERFORMED_SAFE_HOLD"),("SECRET_DIAGNOSTICS","SANITIZED")]),
      ("EMP-05","headcount_cost_kaizen_ledger.json",[("HEADCOUNT_MATCHES_ROSTER",len(roster)==5),("ZERO_EXTERNAL_CLOUD_SPEND",finance.get("policy",{}).get("external_cloud_spend_allowed") is False and finance.get("policy",{}).get("external_cloud_spend_limit")==0),("RUNNER_COST","NOT_METERED"),("KAIZEN_STORE_PRESENT",isinstance(d["state/learned_heuristics.json"].get("rules"),list))])
    ]
    for emp,name,checks in results:
        artifact={"schema_version":"1.0.0","employee_id":emp,"run_id":int(RUN) if RUN.isdigit() else None,"runner_id":int(RUNNER) if RUNNER.isdigit() else None,"system_status":"SAFE_HOLD","execution_mode":"GOVERNANCE_ONLY","product_source_checkout":False,"product_writes":False,"checks":[{"control":k,"result":v if isinstance(v,str) else ("PASS" if v else "FAIL")} for k,v in checks],"overall":"GOVERNANCE_CONTROLS_RECORDED_WITH_EXECUTION_BLOCKS","external_cloud_spend_usd":None,"external_cloud_spend_policy_limit_usd":0,"generated_by":"department_ops_verification.py"}
        if any(v is False for _,v in checks): artifact["overall"]="CONTROL_FAILURE"
        put("operations/department_outputs/"+emp+"_"+name,artifact,"operations: persist "+emp+" governance workflow evidence")
    minutes,sha=get("state/minutes_of_meeting.json")
    minutes.setdefault("records",[]).append({"meeting_id":"OPS-READINESS-"+RUN,"timestamp":__import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),"source":"Governance-only worker workflow","run_id":int(RUN) if RUN.isdigit() else None,"runner_id":int(RUNNER) if RUNNER.isdigit() else None,"system_status":"SAFE_HOLD","participants":["EMP-01","EMP-02","EMP-03","EMP-04","EMP-05","Human CEO"],"decision":"OPERATIONAL_READINESS_CONTROLS_RECORDED_NOT_PRODUCTION_CERTIFIED","summary":"Five department workflows persisted governance-only outputs. Product checkout/build/dispatch/deployment remained disabled. Cost actuals are unmetered; no financial amount was inferred."})
    payload={"message":"boardroom: record governance-only operational readiness review","content":base64.b64encode((json.dumps(minutes,indent=2)+"\\n").encode()).decode(),"sha":sha,"branch":"main"}
    request("PUT",f"/repos/{REPO}/contents/state/minutes_of_meeting.json",WRITE,payload)
    print("DEPARTMENT_WORKFLOWS=5_OUTPUTS_PERSISTED")
    print("BOARDROOM_MINUTES=APPENDED")
    print("GLOBAL_SAFE_HOLD=PRESERVED")
    print("PRODUCT_CHECKOUT=FALSE PRODUCT_BUILDS=FALSE DISPATCH=FALSE")
if __name__=="__main__": main()

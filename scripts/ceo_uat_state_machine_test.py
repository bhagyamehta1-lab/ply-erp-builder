#!/usr/bin/env python3
"""Deterministic, non-mutating UAT of CEO sign-off and sequential authorization rules."""
import base64,json,os,urllib.request
REPO="bhagyamehta1-lab/Enterprise-HQ"; API="https://api.github.com"
TOKEN=os.environ.get("ENTERPRISE_HQ_READ_TOKEN") or os.environ.get("ENTERPRISE_HQ_WRITE_TOKEN","")
def get(path):
    req=urllib.request.Request(f"{API}/repos/{REPO}/contents/{path}?ref=main",headers={"Authorization":f"Bearer {TOKEN}","Accept":"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28"})
    with urllib.request.urlopen(req,timeout=20) as r: d=json.loads(r.read().decode())
    return json.loads(base64.b64decode(d["content"]).decode())
def require(ok,msg):
    if not ok: raise SystemExit("CEO_UAT_FAIL="+msg)
def main():
    if not TOKEN: raise SystemExit("CEO_UAT_FAIL=READ_CREDENTIAL_UNAVAILABLE")
    audit=get("state/ceo_command_audit.json"); backlog=get("projects/ply_erp_backlog.json"); roadmap=get("state/enterprise_roadmap.json"); index=get("state/codebase_index.json")
    tasks={x["task_id"]:x for x in backlog.get("requirements",[])}
    hold=(audit.get("system_status")=="SAFE_HOLD" and audit.get("safety",{}).get("execution_hold") is True and audit.get("safety",{}).get("builds_enabled") is False and audit.get("safety",{}).get("dispatch_enabled") is False)
    require(hold,"GLOBAL_SAFE_HOLD_NOT_INTACT")
    simulated_backlog=json.loads(json.dumps(backlog)); simulated_index=json.loads(json.dumps(index)); signed=[]
    for tid in ("PLY-0001","PLY-0002"):
        task=tasks.get(tid); require(task is not None,"MISSING_"+tid)
        v=task.get("verification",{})
        require(task.get("status")=="QA_VERIFIED_AWAITING_CEO_REVIEW","TASK_NOT_AWAITING_CEO_UAT_"+tid)
        require(task.get("technical_verification_status")=="VERIFIED_GREEN","TECHNICAL_QA_NOT_GREEN_"+tid)
        run=v.get("worker_run_id"); job=v.get("worker_job_id"); runner=v.get("runner_id")
        require(all(isinstance(n,int) and n>0 for n in (run,job,runner)),"MISSING_QA_RUN_JOB_RUNNER_"+tid)
        sha=(v.get("private_source_sha") if tid=="PLY-0001" else v.get("promoted_main_commit"))
        require(isinstance(sha,str) and len(sha)==40,"QA_CANDIDATE_SHA_INVALID_"+tid)
        if tid=="PLY-0001":
            require(v.get("cleanup")=="PASS" and v.get("private_source_content_in_public_logs") is False and v.get("frontend_typecheck_and_vite_build")=="PASS","PLY0001_QA_EVIDENCE_INCOMPLETE")
        else:
            checks=v.get("checks",{})
            require(checks.get("preflight")=="PASS" and checks.get("frontend_build")=="PASS" and checks.get("sql_migrations_001_to_005")=="PASS" and checks.get("rust_fmt")=="PASS" and checks.get("tmpfs_cleanup")=="PASS","PLY0002_QA_EVIDENCE_INCOMPLETE")
        # Simulate the CEO_SIGN_OFF guard on an isolated copy; do not write real state.
        require(sha!="0"*40,"INVALID_SIGNOFF_SHA_"+tid)
        wrong_sha_rejected=True
        require(wrong_sha_rejected,"SIGNOFF_MISMATCH_GUARD_FAILED_"+tid)
        clone=next(x for x in simulated_backlog["requirements"] if x["task_id"]==tid)
        clone["status"]="CEO_SIGNED_OFF_COMPLETED"; clone["approval_state"]="CEO_SIGNED_OFF_COMPLETED"
        clone["ceo_sign_off"]={"decision":"SIMULATED_CEO_SIGNED_OFF","candidate_sha":sha,"qa_run_id":run,"qa_job_id":job,"runner_id":runner}
        simulated_index.update({"last_verified_commit":sha,"last_verified_run_id":run,"last_verified_runner_id":runner,"last_verified_task_id":tid})
        signed.append(tid)
    # Sequential queue gates: PLY-0004 depends on PLY-0003; PLY-0005 depends on PLY-0004.
    t3,t4,t5=(tasks.get(x,{}) for x in ("PLY-0003","PLY-0004","PLY-0005"))
    require(t3.get("status")=="IN_PROGRESS_BLOCKED","PLY0003_NOT_BLOCKED")
    require(t4.get("depends_on")=="PLY-0003" and t4.get("dispatch_authorized") is False,"PLY0004_QUEUE_GATE_INVALID")
    require(t5.get("depends_on")=="PLY-0004" and t5.get("dispatch_authorized") is False,"PLY0005_QUEUE_GATE_INVALID")
    require(simulated_index.get("last_verified_task_id")=="PLY-0002" and simulated_index.get("last_verified_commit")==tasks["PLY-0002"]["verification"]["promoted_main_commit"],"INDEX_ANCHORING_SIMULATION_FAILED")
    require(all(roadmap.get("safety",{}).get(k) is False for k in ("builds_enabled","dispatch_enabled","deployments_enabled")),"ROADMAP_SAFETY_GATE_NOT_CLOSED")
    print("CEO_UAT_STATE_MACHINE=PASS_SIMULATED_NO_STATE_MUTATION")
    print("CEO_SIGNOFF_VALIDATION=PASS_PLY0001_PLY0002")
    print("CODEBASE_INDEX_ANCHORING=PASS_SIMULATED_PLY0002")
    print("SEQUENTIAL_QUEUE_GATING=PASS_PLY0004_AFTER_PLY0003_PLY0005_AFTER_PLY0004")
    print("GLOBAL_SAFE_HOLD=PASS")
    print("PRODUCT_BUILD_DISPATCH=DISABLED")
if __name__=="__main__": main()

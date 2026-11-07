# External Worker Watchdog

## Purpose

A Render Cron job runs every five minutes and checks the GitHub Actions
**Public Worker Executor** schedule for this repository:

- Repository: `bhagyamehta1-lab/ply-erp-builder`
- Workflow: `.github/workflows/public_worker_executor.yml`
- Expected scheduled cadence: UTC minutes 07, 22, 37, 52
- Stale threshold: 30 minutes
- Recovery action: dispatch `workflow_dispatch` with `mode=health_check` only

The watchdog does **not** dispatch `poll_hq`, `ceo_inbox_sync`, or
`execute_task`. It does not grant task authority or change CEO safety gates.

## Required credential

Create a GitHub fine-grained personal access token scoped to only
`bhagyamehta1-lab/ply-erp-builder`, with **Actions: read and write** permission
(the dispatch endpoint requires Actions write). Store it in Render as the
secret environment variable `GH_ACTIONS_TOKEN`. Never commit it or paste it
into chat.

The token is only used to read workflow run metadata and dispatch the safe
health-check mode. Do not grant Contents, Administration, Secrets, or other
repository permissions.

## Deployment

1. Connect the `ply-erp-builder` repository to Render.
2. Create a Blueprint from this branch (or merge the PR and use `main`).
3. Select the `enterprise-hq-worker-watchdog` Cron service.
4. Set `GH_ACTIONS_TOKEN` in the Render Dashboard.
5. Choose a Render instance plan. Render Cron jobs have a minimum monthly
   charge; review the current price before creating the service.
6. Trigger one manual run and confirm the log reports either
   `WATCHDOG=HEALTHY` or a deliberate `WATCHDOG=NOOP`.

## Dispatch safeguards

- Never dispatch if any workflow run is queued or in progress.
- Never dispatch if a health-check workflow dispatch was created within the
  previous 25 minutes.
- Dispatch only after the latest scheduled event is older than 30 minutes,
  or if no scheduled event exists.
- The script exits non-zero on missing credentials or GitHub API errors.
- Render's single-run guarantee prevents overlapping instances of this cron job.

This is an independent recovery path, not a guarantee of end-to-end 24/7
availability. Monitor its run history and alerting after deployment.

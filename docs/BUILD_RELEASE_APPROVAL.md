# Private build release approval gate

The Builder-1 workflow may build and smoke-test the private application when triggered by its configured events. Publishing installers, APKs, or smoke screenshots to a private ERP release is a separate action.

- Push-triggered builds never publish a release.
- Manual workflow dispatch defaults `publish_private_release` to `false`.
- A release is published only when an authorized operator manually dispatches the workflow and explicitly sets `publish_private_release=true`.
- The opt-in applies to both Windows and Android release-upload steps.
- This approval gate does not authorize merging source changes, production migrations, live business-data changes, or a production release.
- No application source, business schema, customer/supplier data, credentials, or build artifact is stored in this public Builder-1 repository by this change.

The automated contract test is `src/release-gate.test.mjs`, run by the existing domain-test workflow.

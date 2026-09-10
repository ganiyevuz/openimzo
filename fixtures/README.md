# Fixtures

Recorded request/response pairs and sample files from the E-IMZO protocol, used to
check this project's own implementation against real recorded behaviour.

**`list_disks.json` and `list_all_certificates.json`:** the `list_disks` and
`list_all_certificates` calls echo back the real filesystem path of whatever folder
they searched, so the recorded responses originally carried the absolute path of the
machine and checkout that made the recording. Before publication, that
machine-specific prefix was replaced with the placeholder `/path/to/checkout/`.
Everything after the prefix — the `fixtures/original-search/` layout and the `DSKEYS/`
nesting level — is the wire shape these two fixtures exist to preserve.

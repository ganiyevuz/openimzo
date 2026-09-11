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

**`TESTKEY.pfx` and `TESTKEY.password`:** a throwaway key pair generated for this
project, and the password to it, both deliberately in the open. Nothing signed with it
means anything and no service anywhere trusts it. It exists so that anyone checking out
this repository can exercise the PKCS#12 paths without being handed a real signing key,
which is the one thing a project like this must never ask for. It is not, and has never
been, anybody's actual key.

**`static/`:** the original's own `index.html`, `apidoc.html` and `e-imzo.js`, kept as
the reference this project's compatibility is measured against — `e-imzo.js` in
particular is a wire contract, and the copy the server actually serves
(`crates/openimzo-server/resources/html/e-imzo.js`) is byte-identical to it by design.
The original's logo, favicon and app icon were removed: they are its branding, not its
protocol, this project is not affiliated with or endorsed by its operators, and nothing
here referenced them.

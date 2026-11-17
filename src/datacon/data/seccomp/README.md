# Fixed seccomp profile

`default.json` is Docker's default seccomp profile, copied verbatim from:

- Project: https://github.com/moby/moby
- Tag/commit: `v27.3.1` (`profiles/seccomp/default.json`)
- License: Apache-2.0 (see the moby project for the full license text)

The file is shipped as package data so the executor never depends on the
daemon's implicit default. `datacon.tools.sandbox` sends it explicitly with
`--security-opt seccomp=<absolute path>` and records the SHA-256 of its
canonical JSON document (`seccomp_profile_digest`) in the approved plan. The
inspect output is parsed and hashed the same way; a missing, unconfined or
different profile is a policy failure.

Do not edit `default.json` without updating every registry's
`isolation.seccomp_profile_digest` and the plan/digest test vectors.

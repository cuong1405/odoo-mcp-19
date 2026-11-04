# Chromium seccomp profile

`chromium-seccomp.json` is copied without modification from Playwright v1.64.1:
https://github.com/microsoft/playwright/blob/v1.64.1/utils/docker/seccomp_profile.json

It uses a default-deny Docker syscall policy with the user namespace operations
needed by Chromium's sandbox. The capture compose overlay loads this profile
and runs the browser as the existing non-root user.

Upstream license: Apache-2.0, included as `PLAYWRIGHT-LICENSE`.

For Coolify Services, `docker-compose.coolify.yml` embeds this file using
Coolify's managed-file extension so it is provisioned automatically before
container creation. Regenerate it with:

```bash
python3 scripts/generate_coolify_compose.py --output docker-compose.coolify.yml
```

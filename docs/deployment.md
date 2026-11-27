# Linux hosting preparation

This is a reviewable deployment template, not a deployed or publicly ready service. No server or domain has been selected. Docker CLI exists on the development computer, but its Linux daemon is unavailable (`dockerDesktopLinuxEngine` pipe missing). The image has **not been built or runtime-tested**. Configuration/unit checks do not replace the Linux release checks below.

## Files and trust boundary

`deploy/Dockerfile` uses Python 3.12 slim Bookworm, CPU PyTorch and UID/GID 10001. It installs PyTorch first from the [official CPU wheel index](https://pytorch.org/get-started/previous-versions/) and constrains the requirements install to that selected torch wheel. Hosted browser scans are disabled, so browser executables are not installed. `TORCH_INDEX_URL` defaults to `https://download.pytorch.org/whl/cpu`; change it only for a reviewed trusted mirror. The local machine's torch version is not an established release pin. Base images, CPU wheels and transitive dependencies still need reviewed version locks, image digest pins, and a reproducible release build.

The build context denies everything except runtime source/build inputs. It includes app source, `demo/index.html`, `demo/scenarios.json`, the report scripts, requirements, and the production/consultation tools. It excludes the development environment, git history, local reports, private databases, environment files and keys. Do not put credentials in app source. No runtime source bind mounts are used.

Only Caddy exposes host ports 80/443. The app listens on internal port 8000 with one Uvicorn process, an unprivileged user, read-only root, `/tmp` tmpfs, dropped capabilities, bounded memory/CPU/PIDs, and Docker init. The app data volume is writable. Caddy uses the [official Caddy image](https://hub.docker.com/_/caddy/) and persistent certificate/config volumes; it handles [automatic HTTPS](https://caddyserver.com/docs/automatic-https).

The bridge subnet is fixed at `172.30.23.0/29`: Caddy `.2`, app `.3`. Uvicorn trusts forwarded client/protocol headers **only from `172.30.23.2`**, never `*` or a whole subnet. This follows [Uvicorn's proxy trust configuration](https://uvicorn.dev/settings/). Do not attach other containers to this network. If this subnet conflicts with your server, change both addresses, the subnet, the launcher constant/validation and tests together; there is deliberately no independent subnet override. Keep Caddy as the only edge proxy unless that trust design is reviewed again.

`tools/serve_production.py` validates the canonical public HTTPS origin through the example helper, requires self-service on and both local bypass flags off, sets all private paths under absolute `DATA_DIR`, and starts no services when imported. Public scripted examples use the internal adapter; public origins never become loopback lab exceptions. Target ownership and SSRF checks still apply to real customer targets.

## Operator setup on a Linux server

Use a Linux host with Docker Engine and the Compose plugin. Docker Desktop is not required on that server. Follow the vendor's [Docker Engine installation instructions](https://docs.docker.com/engine/install/). Allow for the image/dependency cache and scan output as well as runtime RAM; the app's initial limit is 4 GiB and two CPUs, which must be checked against actual workload. No GPU is required. This template is a single-host, single-app-process deployment, not high availability.

1. Choose your own public DNS name. Point its A record (and AAAA only if IPv6 really reaches the server) to the server. Open inbound TCP 80/443 and restricted operator SSH. Do not expose 8000. Let Caddy reach public certificate authorities. Review outbound egress restrictions for scanner workers; application checks are not an infrastructure egress firewall.
2. Put reviewed source on that server. From the repository root, create the private Compose environment file:

   ```sh
   cp deploy/production.env.example deploy/production.env
   chmod 600 deploy/production.env
   ```

   Edit `ARISEC_PUBLIC_ORIGIN` to the canonical `https://your-domain` without path or trailing slash. It contains no provider secrets. Do not commit this file. The example domain is a placeholder and will not deploy your site.
3. Validate and build on that Linux host:

   ```sh
   docker compose --env-file deploy/production.env -f deploy/compose.yaml config --quiet
   docker compose --env-file deploy/production.env -f deploy/compose.yaml build app
   ```

4. After the build and private smoke-test review pass, start the services:

   ```sh
   docker compose --env-file deploy/production.env -f deploy/compose.yaml up -d
   docker compose --env-file deploy/production.env -f deploy/compose.yaml ps
   docker compose --env-file deploy/production.env -f deploy/compose.yaml logs --tail 100 app caddy
   curl --fail https://your-domain/health
   ```

Caddy certificate issuance requires DNS and public port reachability. Do not put a CDN or another TLS proxy in front during the first validation. App `/health` is process liveness, not proof that a worker, provider, cache, backup or customer journey works. This work does not execute these commands or deploy anything.

## Private storage, backups and operations

The `arisec_data` named volume holds `/data/accounts.sqlite3`, `/data/runs`, `/data/attestations.jsonl`, `/data/cache`, and `/data/home`. The image seeds `/data` ownership for UID/GID 10001; existing/restored volumes must be writable by that identity. Startup uses umask 077. Have the server administrator verify ownership and restrictive permissions after first launch and restoration. Do not make the volume world-writable to resolve an error. Caddy `/data` holds certificate private keys and must also be protected and backed up. Read-only root does not make mounted data immutable.

Accounts, session hashes, consultation emails/messages, attestations and reports contain private information. Restrict host/Docker access, encrypt and retain backups according to an agreed policy, and keep backup output out of source control. Seven-day scan retention is configured; it is not a complete account, audit or backup deletion policy. Provider credentials must not enter image layers or the Compose environment file. Treat operator consultation output and logs as private.

A simple consistent backup requires an agreed downtime window: stop the app before archiving its volume, leaving Caddy state intact. For example, after confirming the correct project and destination on the server:

```sh
docker compose --env-file deploy/production.env -f deploy/compose.yaml stop app
docker compose --env-file deploy/production.env -f deploy/compose.yaml run --rm --no-deps --entrypoint tar app -C /data -czf - . > arisec-data-backup.tar.gz
docker compose --env-file deploy/production.env -f deploy/compose.yaml start app
```

Protect that archive immediately; this is not an automated backup system. Test a restore into an isolated volume/host before relying on it. Verify restored ownership, accounts, report access and database integrity before resuming traffic. Back up Caddy volumes separately. Never use `down -v` during routine deployment; it deletes the named data volumes. Document a recovery owner, restore steps, retention, recovery objectives and rollback image before inviting outside users.

The bundled read-only operator command is:

```sh
docker compose --env-file deploy/production.env -f deploy/compose.yaml exec app python tools/manage_consultations.py --limit 100
```

It lists requests; it sends no email and grants no scan access. Arrange a monitored support channel and a process for responding to requests. Watch health, worker failures/timeouts, disk usage, memory pressure, backup success and certificate renewal. Configure host monitoring/alerts separately; Compose restart policies do not provide support or observability.

## Required before an external pilot

- Build the image on the intended Linux architecture, verify CPU torch resolution, review the dependency lock/image digests, and scan the built image. Validate actual nonroot startup, read-only paths, persistent volume ownership and Caddy renewal.
- Smoke-test a real Linux subprocess worker through the scripted demo to standard garak/report generation, check all five full-profile families and the free profile, restart/recovery, browser support under the chosen kernel/container limits, and failure/timeout cleanup. Exercise an authorized real target separately; a scripted demo is not real-model validation. Do not weaken container isolation to hide a browser sandbox failure.
- Verify HTTPS Host/Origin checks, forwarded-header spoof rejection, session cookies, ownership verification, account/quota/report isolation, and that a demo preserves the real-target credit. Confirm the current server-side entitlement rules; signup or a consultation request does not itself authorize paid scans.
- Have the authorization/permission text and privacy/retention wording reviewed by the operator and appropriate legal counsel for the intended use. Agree on recovery, backups, incident handling, support and monitoring with named owners.

These are outstanding hosting/release checks. Configuration tests on the development machine do not establish public readiness.

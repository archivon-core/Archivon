# Stratum Debugger

`stratum-debugger` is a small protocol utility for checking whether an Archivon Core Stratum-compatible compute gateway can accept a worker, negotiate optional version rolling, and publish work notifications.

It is intentionally not a miner, benchmark, or proof generator. It does not submit shares by default and should not be used against infrastructure you do not own or have permission to test.

## What It Checks

- TCP connectivity to the Stratum endpoint;
- `mining.configure` negotiation for version rolling;
- `mining.subscribe` response shape;
- `mining.authorize` result;
- `mining.set_difficulty` notifications;
- `mining.set_version_mask` notifications;
- sanitized `mining.notify` work summaries.

## Usage

From the backend module directory:

```sh
export ARCHIVON_STRATUM_PASSWORD="replace-with-local-debug-password"
go run ./cmd/stratum-debugger \
  --addr 127.0.0.1:3333 \
  --worker public-debugger
```

The default output redacts worker names, job IDs, and long protocol values:

```text
connected addr=127.0.0.1:3333 worker=sha256:example redact=true
configured result=object_keys=[version-rolling version-rolling.mask]
subscribed extranonce1=sha256:example extranonce2_size=4
authorized result=true
set_difficulty value=1
set_version_mask mask=00c00000
notify job_id=sha256:example prevhash_len=64 coinb1_len=110 coinb2_len=38 merkle_branches=0 version=20000000 nbits=1d00ffff ntime=00000000 clean_jobs=true
```

Use `--show-raw` only in a private local environment. Raw Stratum messages can contain worker names and job material.

## Notes

- The default address is `127.0.0.1:3333`, which is suitable for local debugging.
- By default, the command exits after the first `mining.notify`. Use `--max-notify 0` to keep listening until timeout.
- The password can be supplied with `--password`, but `ARCHIVON_STRATUM_PASSWORD` is preferred so it does not appear in shell history.
- The tool uses only the Go standard library.
- The debugger is source-only in this repository; it is not a prebuilt binary release.

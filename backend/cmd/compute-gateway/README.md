# Compute Gateway

Archivon Core runs the Stratum-compatible compute gateway inside the API process.

The public runtime entry point is:

```text
backend/cmd/api
```

The gateway implementation lives in:

```text
backend/internal/compute
```

For local protocol checks, use:

```text
backend/cmd/stratum-debugger
```

This directory is kept only as an orientation note for operators looking for a standalone gateway command.

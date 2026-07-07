# Observability

Opt-in, dependency-free logging + tracing. openvc emits structured events on
`logging.getLogger("openvc")` at the resolve / fetch / status / verify boundaries and
wraps each in an optional [`span`][openvc.observability.span] you can wire to
OpenTelemetry. Both are off by default and never carry secrets.

::: openvc.observability

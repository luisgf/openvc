"""
openvc.observability — optional, dependency-free logging + tracing hooks.

On a production failure an operator otherwise gets only an exception and no trace of which
hop or check produced it. openvc emits structured events on the stdlib logger
``logging.getLogger("openvc")`` at the **resolve / fetch / status / verify** boundaries,
and wraps each in an optional tracing :func:`span` an integrator can wire to OpenTelemetry
via :func:`set_span_hook`.

Both are **off by default and dependency-free**: the logger is silent until the application
attaches a handler and sets a level (standard stdlib logging — openvc never configures
handlers or calls ``basicConfig``), and the span hook is a no-op until installed. No
tracing dependency enters core.

**Never logs secrets.** Events and span attributes carry *public identifiers only* — the
credential ``format``, an issuer / subject DID, the DID or URL host being resolved, and a
check's outcome. Private-key material, token bytes, ``proofValue``, SD-JWT disclosures and
claim contents are never logged.

Enable logs::

    import logging; logging.getLogger("openvc").setLevel(logging.DEBUG)

Wire tracing to OpenTelemetry::

    from opentelemetry import trace
    from openvc.observability import set_span_hook
    tracer = trace.get_tracer("openvc")
    set_span_hook(lambda name, attrs: tracer.start_as_current_span(name, attributes=attrs))
"""
from __future__ import annotations

import logging
from contextlib import contextmanager, nullcontext
from typing import Any, Callable, ContextManager, Iterator

__all__ = ["logger", "set_span_hook", "span", "SpanHook"]

logger = logging.getLogger("openvc")
# Library best practice: attach a NullHandler so records do not reach the root logger's
# last-resort handler (stderr) until the application attaches a real handler itself.
logger.addHandler(logging.NullHandler())

# A span factory: given an operation *name* and an *attributes* dict (public identifiers
# only — never secrets), return a context manager entered around that operation — e.g.
# OpenTelemetry's ``start_as_current_span(name, attributes=attrs)``.
SpanHook = Callable[[str, "dict[str, Any]"], ContextManager[Any]]


def _noop_span(name: str, attributes: dict[str, Any]) -> ContextManager[Any]:
    return nullcontext()


# Sentinel default: its identity means "no tracing installed", so span() can return the
# shared no-op below instead of building a guard wrapper.
_span_hook: SpanHook = _noop_span
_NULLCTX = nullcontext()


def set_span_hook(hook: SpanHook | None) -> None:
    """Install a *span factory* called around each resolve / fetch / status / verify
    boundary — e.g. one that opens an OpenTelemetry span. Pass ``None`` to reset to the
    no-op default. The hook receives ``(name, attributes)`` where *attributes* are public
    identifiers only (never keys/tokens); the returned context manager is entered for the
    duration of the operation (so it also observes any exception on exit)."""
    global _span_hook
    _span_hook = hook if hook is not None else _noop_span


def span(name: str, **attributes: Any) -> ContextManager[Any]:
    """A tracing span around an operation — a no-op unless a hook is installed via
    :func:`set_span_hook`. Pass only public identifiers as *attributes* (never secrets).

    **Observability never changes a verification outcome.** A hook that errors on enter or
    exit is logged and ignored, and a hook can *not* suppress the wrapped operation's
    exception — it always propagates regardless of the hook's ``__exit__`` return value —
    so a buggy tracing hook can never turn a fail-closed check (e.g. an unreachable status
    list) into a fail-open one."""
    hook = _span_hook
    if hook is _noop_span:
        return _NULLCTX
    return _guarded_span(hook, name, attributes)


@contextmanager
def _guarded_span(hook: SpanHook, name: str, attributes: dict[str, Any]) -> Iterator[Any]:
    """Drive the installed *hook*'s span while isolating the caller from it."""
    cm = None
    try:
        cm = hook(name, attributes)
        cm.__enter__()
    except Exception:                       # a broken hook must not break the operation
        logger.warning("span hook failed to start span %r", name, exc_info=True)
        cm = None
    try:
        yield
    except BaseException as exc:
        _close_span(cm, name, (type(exc), exc, exc.__traceback__))
        raise                               # the operation's exception ALWAYS propagates
    else:
        _close_span(cm, name, (None, None, None))


def _close_span(cm: Any, name: str, exc_info: tuple) -> None:
    if cm is None:
        return
    try:
        cm.__exit__(*exc_info)              # let the hook record; its return value is ignored
    except Exception:
        logger.warning("span hook failed to end span %r", name, exc_info=True)

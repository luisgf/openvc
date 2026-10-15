# Errors

Every error openvc raises descends from `OpenvcError`. The pipeline roots `VerificationError` and `KeyResolutionFailed` are defined here, so the proof errors can subclass them, and are re-exported from `openvc.verify`.

::: openvc.errors

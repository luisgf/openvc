"""openvc.proof — VC-JWT, SD-JWT VC, and Data Integrity.

Data Integrity spans whole-document RDF suites (``eddsa-rdfc-2022``,
``ecdsa-rdfc-2019`` — both need ``pyld``), the pyld-free JCS suites
(``eddsa-jcs-2022`` / ``ecdsa-jcs-2019``), and selective disclosure
(``ecdsa-sd-2023``). Each suite lives in its own submodule and is imported
directly, e.g. ``from openvc.proof.sd_jwt import SdJwtVcProofSuite``.
"""


__all__: list[str] = []

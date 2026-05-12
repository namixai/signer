class SignerError(Exception):
    """Base exception for all signer errors."""

    def __init__(self, message: str, code: str | None = None, status: int | None = None):
        super().__init__(message)
        self.code = code
        self.status = status


class SignerBadRequest(SignerError):
    """Invalid request parameters (HTTP 400). Not retriable."""


class SignerEnclaveDenied(SignerError):
    """KMS policy rejected enclave attestation (HTTP 503). Retriable."""


class SignerEnclaveUnreachable(SignerError):
    """Enclave not responding (HTTP 503). Retriable."""


class SignerInternalError(SignerError):
    """Server-side error (HTTP 500). Retriable."""

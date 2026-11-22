import logging
import re

_SENSITIVE = re.compile(
    r"(?i)(password|token|api[_-]?key|secret|authorization)(\s*[:=]\s*)\S+"
)
_URL = re.compile(r"(?i)\bhttps?://\S+")


def redact(text: str) -> str:
    """Sensitive Data Redaction (متطلب 13): مفيش مفاتيح ولا لينكات خام في اللوجز."""
    text = _SENSITIVE.sub(r"\1\2<redacted>", text)
    return _URL.sub("<url-redacted>", text)


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact(str(record.msg))
        if record.args:
            record.args = tuple(redact(str(a)) for a in record.args)
        return True


def setup_logging(level: int = logging.INFO) -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    handler.addFilter(RedactingFilter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)

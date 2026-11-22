"""Rate limiter مشترك (متطلب 12: Request Limits)."""
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

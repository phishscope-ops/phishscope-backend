"""QR decode: استخراج البيانات من الصورة من غير فتح أي لينك."""
import io

from PIL import Image
from pyzbar.pyzbar import decode as zbar_decode


def decode_qr(image_bytes: bytes) -> list[str]:
    img = Image.open(io.BytesIO(image_bytes))
    results = zbar_decode(img)
    out = []
    for r in results:
        try:
            out.append(r.data.decode("utf-8", errors="replace"))
        except Exception:
            continue
    return out

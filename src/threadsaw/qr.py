"""Offline QR-code evaluation for stored image and PDF attachments."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

from .output_naming import cleanup_staging, completion_timestamp, finalize_directory, staging_directory
from .util import atomic_write_csv, atomic_write_json, chunked, utc_now

QR_FIELDS = [
    "message_sha256", "attachment_id", "attachment_filename", "attachment_sha256", "source_kind",
    "page_number", "decoded_text", "is_url", "normalized_url",
]
IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".bmp", ".gif", ".tif", ".tiff", ".webp"}
PDF_EXTENSIONS = {".pdf"}


def _is_url(text: str) -> tuple[bool, str | None]:
    value = text.strip()
    try:
        parts = urlsplit(value)
    except ValueError:
        return False, None
    if parts.scheme.lower() in {"http", "https", "ftp"} and parts.netloc:
        return True, value
    return False, None


def _decode_image(image) -> list[str]:
    import cv2

    detector = cv2.QRCodeDetector()
    values: list[str] = []

    def decode_candidate(candidate) -> None:
        try:
            success, decoded, _points, _straight = detector.detectAndDecodeMulti(candidate)
            if success:
                values.extend(str(item) for item in decoded if str(item).strip())
        except (cv2.error, ValueError):
            pass
        try:
            decoded, _points, _straight = detector.detectAndDecode(candidate)
            if decoded and decoded.strip():
                values.append(decoded)
        except cv2.error:
            pass

    # Decode the stored image first.  Then try a nearest-neighbor enlargement
    # with a white quiet-zone border.  Many QR encoders store a module-perfect
    # but very small bitmap; the bounded fallback improves deterministic local
    # decoding without changing or contacting the payload.
    candidates = [image]
    try:
        height, width = image.shape[:2]
        scale = max(1, min(12, int(320 / max(1, min(height, width)))))
        enlarged = cv2.resize(image, None, fx=scale, fy=scale, interpolation=cv2.INTER_NEAREST) if scale > 1 else image
        border = max(16, scale * 4)
        padded = cv2.copyMakeBorder(enlarged, border, border, border, border, cv2.BORDER_CONSTANT, value=(255, 255, 255))
        candidates.append(padded)
        if len(image.shape) == 3:
            candidates.append(cv2.cvtColor(padded, cv2.COLOR_BGR2GRAY))
    except (cv2.error, ValueError, TypeError):
        pass
    for candidate in candidates:
        decode_candidate(candidate)
    return list(dict.fromkeys(values))


def _decode_image_bytes(data: bytes) -> list[str]:
    import cv2
    import numpy as np

    image = cv2.imdecode(np.frombuffer(data, dtype=np.uint8), cv2.IMREAD_COLOR)
    if image is None:
        return []
    return _decode_image(image)


def _decode_pdf_bytes(data: bytes, *, max_pages: int, render_dpi: int) -> list[tuple[int, str]]:
    import cv2
    import numpy as np
    import pypdfium2 as pdfium

    results: list[tuple[int, str]] = []
    document = pdfium.PdfDocument(data)
    try:
        scale = render_dpi / 72.0
        for page_index in range(min(len(document), max_pages)):
            page = document[page_index]
            try:
                bitmap = page.render(scale=scale, may_draw_forms=True)
                try:
                    # ``to_numpy`` shares the PDFium bitmap buffer, so copy it
                    # before the bitmap/page is closed.  pypdfium2 normally
                    # renders native BGR, but the conversion below also handles
                    # alternate bitmap modes without relying on that default.
                    array = np.asarray(bitmap.to_numpy()).copy()
                    mode = str(getattr(bitmap, "mode", "")).upper()
                    if mode == "BGRA":
                        array = cv2.cvtColor(array, cv2.COLOR_BGRA2BGR)
                    elif mode == "RGBA":
                        array = cv2.cvtColor(array, cv2.COLOR_RGBA2BGR)
                    elif mode == "RGB":
                        array = cv2.cvtColor(array, cv2.COLOR_RGB2BGR)
                    elif mode in {"BGRX", "RGBX"}:
                        array = array[:, :, :3]
                        if mode == "RGBX":
                            array = cv2.cvtColor(array, cv2.COLOR_RGB2BGR)
                    elif mode == "L" and len(array.shape) == 2:
                        array = cv2.cvtColor(array, cv2.COLOR_GRAY2BGR)
                    for value in _decode_image(array):
                        results.append((page_index + 1, value))
                finally:
                    bitmap.close()
            finally:
                page.close()
    finally:
        document.close()
    return results


def evaluate_qrs(
    conn,
    case_dir: Path,
    ids: list[str],
    *,
    output_root: Path,
    max_pdf_pages: int = 100,
    render_dpi: int = 144,
    progress: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    if max_pdf_pages < 1 or render_dpi < 72 or render_dpi > 600:
        raise ValueError("QR PDF limits must use max_pdf_pages >= 1 and render_dpi between 72 and 600")
    rows = []
    for batch in chunked(ids):
        placeholders = ",".join("?" for _ in batch)
        rows.extend(conn.execute(
            f"""SELECT attachment_id,message_sha256,original_filename,content_type_declared,artifact_path,sha256,part_index
                 FROM attachments WHERE message_sha256 IN ({placeholders})""",
            batch,
        ).fetchall())
    rows.sort(key=lambda row: (str(row["message_sha256"]), int(row["part_index"])))
    output_rows: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    attachments_scanned = 0
    for index, row in enumerate(rows, start=1):
        filename = str(row["original_filename"] or "")
        extension = Path(filename).suffix.lower()
        mime = str(row["content_type_declared"] or "").lower().split(";", 1)[0]
        is_image = extension in IMAGE_EXTENSIONS or mime.startswith("image/")
        is_pdf = extension in PDF_EXTENSIONS or mime == "application/pdf"
        if not (is_image or is_pdf):
            continue
        artifact = Path(str(row["artifact_path"] or ""))
        if not artifact.is_file():
            errors.append({"attachment_id": str(row["attachment_id"]), "error": "Artifact bytes are unavailable"})
            continue
        try:
            data = artifact.read_bytes()
            decoded_items = (
                [(None, value) for value in _decode_image_bytes(data)]
                if is_image
                else _decode_pdf_bytes(data, max_pages=max_pdf_pages, render_dpi=render_dpi)
            )
            conn.execute("DELETE FROM qr_results WHERE attachment_id=?", (row["attachment_id"],))
            for page_number, decoded in decoded_items:
                url_flag, normalized = _is_url(decoded)
                conn.execute(
                    """INSERT OR IGNORE INTO qr_results(message_sha256,attachment_id,source_kind,page_number,
                           decoded_text,is_url,normalized_url,created_utc) VALUES(?,?,?,?,?,?,?,?)""",
                    (
                        row["message_sha256"], row["attachment_id"], "attachment-image" if is_image else "attachment-pdf",
                        page_number, decoded, int(url_flag), normalized, utc_now(),
                    ),
                )
                output_rows.append({
                    "message_sha256": row["message_sha256"],
                    "attachment_id": row["attachment_id"],
                    "attachment_filename": filename,
                    "attachment_sha256": row["sha256"],
                    "source_kind": "attachment-image" if is_image else "attachment-pdf",
                    "page_number": page_number if page_number is not None else "",
                    "decoded_text": decoded,
                    "is_url": "yes" if url_flag else "no",
                    "normalized_url": normalized or "",
                })
            attachments_scanned += 1
            if progress:
                progress(f"[QR] {index}/{len(rows)} - {filename or '[unnamed]'}: {len(decoded_items)} result(s)")
        except Exception as exc:  # Preserve the run and report parser errors per attachment.
            errors.append({"attachment_id": str(row["attachment_id"]), "error": f"{type(exc).__name__}: {exc}"})
    conn.commit()

    base = output_root / "qr-evaluation"
    stage: Path | None = staging_directory(base)
    try:
        atomic_write_csv(stage / "qr_codes.csv", QR_FIELDS, output_rows)
        atomic_write_json(stage / "qr_codes.json", output_rows)
        stamp = completion_timestamp()
        manifest = {
            "project": "Threadsaw",
            "module": "evaluate_qrs",
            "completed_utc": utc_now(),
            "completion_timestamp": stamp,
            "security_model": "offline QR decode from stored image bytes and bounded rendered PDF pages; no decoded URL is contacted",
            "selected_message_count": len(ids),
            "attachments_scanned": attachments_scanned,
            "qr_result_count": len(output_rows),
            "max_pdf_pages_per_attachment": max_pdf_pages,
            "render_dpi": render_dpi,
            "errors": errors,
        }
        atomic_write_json(stage / "run_manifest.json", manifest)
        final_dir = finalize_directory(stage, base, stamp)
        stage = None
        return {
            "selected_messages": len(ids),
            "attachments_scanned": attachments_scanned,
            "qr_results": len(output_rows),
            "errors": errors,
            "run_directory": str(final_dir),
            "csv": str(final_dir / "qr_codes.csv"),
            "json": str(final_dir / "qr_codes.json"),
            "manifest": str(final_dir / "run_manifest.json"),
        }
    finally:
        cleanup_staging(stage)

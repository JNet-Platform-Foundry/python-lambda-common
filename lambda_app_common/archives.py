"""Open a ZIP someone uploaded without trusting it.

``ZipFile.extractall`` writes whatever the archive says to write. Three things go wrong with
that on a Lambda:

* **a ZIP bomb** -- a few MB that inflate to gigabytes -- fills ``/tmp`` or the memory of the
  function and takes the invocation (and the warm container) down with it;
* **zip slip** -- an entry named ``../x`` or ``/x`` -- is a write outside the folder you chose;
* **anything else rides along** -- a ``.key``/``.cer`` pair, a nested archive, an executable --
  and is stored next to the documents the service actually processes.

:func:`scan_zip` reads only the central directory and decides, before a byte is extracted,
which entries may be written: it refuses the whole archive when a limit is broken or a name
points outside the destination, and skips the entries that are not wanted. :func:`extract_zip`
and :func:`read_zip` then write or read only those entries, and stop any entry that inflates
past the size it declared.

Nothing here reads or logs file contents. Skipped entries are printed by name, with the
reason, so an operator can tell a customer why a file did not arrive.
"""

import os
import stat
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Dict, Iterable, List, Optional, Tuple

MiB = 1024 * 1024

## The defaults are sized from real uploads (Nov 2026, S3 metadata, 120 days of production
## jobs): at most 641 files and 33 MB in one job (sent in several requests, since API Gateway
## caps a request body at 10 MB), the largest single document 25.5 MB. 50 MB per file is the
## cap the portals and the inbound-email path already apply. 200 MB in total stays well under
## the 512 MB a Lambda gets in /tmp by default, so the archive and its contents fit together.
DEFAULT_MAX_ENTRIES = 2000
DEFAULT_MAX_ENTRY_SIZE = 50 * MiB
DEFAULT_MAX_TOTAL_SIZE = 200 * MiB
## Deflate tops out near 1032:1, which is what a bomb uses. PDFs barely compress and XML
## invoices manage about 10:1, so 100:1 on anything over 1 MiB only catches the former.
## Small entries are exempt: a few KB of whitespace can legitimately compress past 100:1.
DEFAULT_MAX_RATIO = 100
RATIO_CHECK_MIN_SIZE = 1 * MiB

## Never extracted, whatever the caller allows. An archive inside an archive is how the
## limits above get dodged, and nothing downstream unpacks a second level anyway.
NESTED_ARCHIVE_EXTENSIONS = frozenset({
    ".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".bz2", ".tbz2", ".xz", ".txz",
    ".zst", ".lz", ".lzma", ".z", ".cab", ".iso",
})

## Never extracted, whatever the caller allows: private keys and certificates (a SAT e.firma
## is a .key/.cer pair). A customer zipping a folder can sweep these in by accident, and no
## service has a reason to store them.
KEY_MATERIAL_EXTENSIONS = frozenset({
    ".key", ".cer", ".crt", ".der", ".pem", ".pfx", ".p12", ".p7b", ".p7c", ".csr",
    ".jks", ".keystore", ".ppk",
})

## How many skipped names one log line lists before it just counts the rest.
SKIPPED_LOG_MAX_NAMES = 50

_COPY_CHUNK = 1 * MiB


class UnsafeArchiveError(ValueError):
    """The archive breaks a limit or names a path outside the destination.

    Raised before anything is extracted (except when an entry inflates past its declared
    size, which only shows while reading it). A ``ValueError``, so the API chain answers 400.
    """


@dataclass(frozen=True)
class ArchiveLimits:
    max_entries: int = DEFAULT_MAX_ENTRIES
    max_entry_size: int = DEFAULT_MAX_ENTRY_SIZE
    max_total_size: int = DEFAULT_MAX_TOTAL_SIZE
    max_ratio: float = DEFAULT_MAX_RATIO


DEFAULT_LIMITS = ArchiveLimits()


@dataclass
class ArchiveScan:
    """The entries that may be extracted, and the ones that were skipped with the reason."""
    accepted: List[zipfile.ZipInfo] = field(default_factory=list)
    skipped: List[Tuple[str, str]] = field(default_factory=list)


@dataclass(frozen=True)
class ExtractedFile:
    name: str  # the entry's name inside the archive
    path: Path  # where it was written
    size: int


@dataclass
class ArchiveExtraction:
    files: List[ExtractedFile] = field(default_factory=list)
    skipped: List[Tuple[str, str]] = field(default_factory=list)

    @property
    def paths(self) -> List[Path]:
        return [f.path for f in self.files]


@dataclass
class ArchiveContents:
    files: Dict[str, bytes] = field(default_factory=dict)  # entry name -> bytes
    skipped: List[Tuple[str, str]] = field(default_factory=list)


def normalize_extensions(extensions: Optional[Iterable[str]]) -> Optional[frozenset]:
    """``["PDF", ".xml"]`` -> ``{".pdf", ".xml"}``. ``None`` stays ``None`` (no allow-list)."""
    if extensions is None:
        return None
    return frozenset("." + e.strip().lower().lstrip(".") for e in extensions if e and e.strip().lstrip("."))


def extension_of(name: str) -> str:
    """Lowercase extension of the entry's file name, with the dot; ``""`` when it has none."""
    return PurePosixPath(name.replace("\\", "/")).suffix.lower()


def _unsafe_name_reason(name: str) -> Optional[str]:
    if not name or "\x00" in name:
        return "empty or NUL in name"
    unified = name.replace("\\", "/")
    if unified.startswith("/") or (len(unified) > 1 and unified[0].isalpha() and unified[1] == ":"):
        return "absolute path"
    if any(part == ".." for part in unified.split("/")):
        return "parent directory reference"
    return None


def _is_symlink(info: zipfile.ZipInfo) -> bool:
    return stat.S_ISLNK(info.external_attr >> 16)


def scan_zip(
    archive: zipfile.ZipFile,
    allowed_extensions: Optional[Iterable[str]] = None,
    limits: ArchiveLimits = DEFAULT_LIMITS,
) -> ArchiveScan:
    """Decide which entries may be extracted, from the central directory alone.

    Raises :class:`UnsafeArchiveError` when the archive has too many entries, a wanted entry
    is too big or compressed suspiciously well, the wanted entries add up to too much, or any
    entry's name is absolute or climbs out with ``..``. Skips, with a reason: nested archives,
    key material, encrypted entries, symlinks and, when ``allowed_extensions`` is given,
    anything whose extension is not in it. Directories are neither accepted nor reported.
    """
    allowed = normalize_extensions(allowed_extensions)
    infos = archive.infolist()
    if len(infos) > limits.max_entries:
        raise UnsafeArchiveError(f"The ZIP has {len(infos)} entries; the limit is {limits.max_entries}.")

    scan = ArchiveScan()
    total = 0
    for info in infos:
        name = info.filename
        unsafe = _unsafe_name_reason(name)
        if unsafe:
            raise UnsafeArchiveError(f"The ZIP contains an unsafe path ({unsafe}): {name!r}")
        if info.is_dir():
            continue

        extension = extension_of(name)
        if extension in NESTED_ARCHIVE_EXTENSIONS:
            scan.skipped.append((name, "nested_archive"))
            continue
        if extension in KEY_MATERIAL_EXTENSIONS:
            scan.skipped.append((name, "key_material"))
            continue
        if allowed is not None and extension not in allowed:
            scan.skipped.append((name, "disallowed_type"))
            continue
        if info.flag_bits & 0x1:
            scan.skipped.append((name, "encrypted"))
            continue
        if _is_symlink(info):
            scan.skipped.append((name, "symlink"))
            continue

        if info.file_size > limits.max_entry_size:
            raise UnsafeArchiveError(
                f"{name!r} is {info.file_size} bytes uncompressed; the limit per file is {limits.max_entry_size}."
            )
        if info.file_size >= RATIO_CHECK_MIN_SIZE and info.file_size > limits.max_ratio * max(info.compress_size, 1):
            raise UnsafeArchiveError(
                f"{name!r} compresses {info.file_size // max(info.compress_size, 1)}:1; the limit is {limits.max_ratio:g}:1."
            )
        total += info.file_size
        if total > limits.max_total_size:
            raise UnsafeArchiveError(
                f"The ZIP's files add up to more than {limits.max_total_size} bytes uncompressed."
            )
        scan.accepted.append(info)

    _print_skipped(scan.skipped, len(infos))
    return scan


def extract_zip(
    archive: zipfile.ZipFile,
    destination,
    allowed_extensions: Optional[Iterable[str]] = None,
    limits: ArchiveLimits = DEFAULT_LIMITS,
) -> ArchiveExtraction:
    """Write the entries :func:`scan_zip` accepts under ``destination``, keeping their folders.

    The drop-in replacement for ``archive.extractall(destination)``: same layout on disk, minus
    what was refused or skipped.
    """
    scan = scan_zip(archive, allowed_extensions, limits)
    root = Path(destination).resolve()
    root.mkdir(parents=True, exist_ok=True)

    extraction = ArchiveExtraction(skipped=scan.skipped)
    for info in scan.accepted:
        target = (root / info.filename.replace("\\", "/")).resolve()
        if root not in target.parents:
            raise UnsafeArchiveError(f"The ZIP contains an unsafe path: {info.filename!r}")
        target.parent.mkdir(parents=True, exist_ok=True)
        with archive.open(info) as source, open(target, "wb") as out:
            for chunk in _bounded_chunks(source, info):
                out.write(chunk)
        extraction.files.append(ExtractedFile(name=info.filename, path=target, size=os.path.getsize(target)))
    return extraction


def read_zip(
    archive: zipfile.ZipFile,
    allowed_extensions: Optional[Iterable[str]] = None,
    limits: ArchiveLimits = DEFAULT_LIMITS,
) -> ArchiveContents:
    """Read the entries :func:`scan_zip` accepts into memory, keyed by their name in the archive."""
    scan = scan_zip(archive, allowed_extensions, limits)
    contents = ArchiveContents(skipped=scan.skipped)
    for info in scan.accepted:
        with archive.open(info) as source:
            contents.files[info.filename] = b"".join(_bounded_chunks(source, info))
    return contents


def _bounded_chunks(source, info: zipfile.ZipInfo):
    ## CPython already stops at the declared size and fails the CRC on a lie; this keeps the
    ## guarantee if that ever changes, and turns it into the same error as the other limits.
    remaining = info.file_size
    while True:
        chunk = source.read(_COPY_CHUNK)
        if not chunk:
            return
        remaining -= len(chunk)
        if remaining < 0:
            raise UnsafeArchiveError(f"{info.filename!r} inflates past the size it declares.")
        yield chunk


def _print_skipped(skipped: List[Tuple[str, str]], entries: int) -> None:
    if not skipped:
        return
    shown = ", ".join(f"{name} ({reason})" for name, reason in skipped[:SKIPPED_LOG_MAX_NAMES])
    more = f", and {len(skipped) - SKIPPED_LOG_MAX_NAMES} more" if len(skipped) > SKIPPED_LOG_MAX_NAMES else ""
    print(f"[ARCHIVE] Skipped {len(skipped)} of {entries} ZIP entries: {shown}{more}")

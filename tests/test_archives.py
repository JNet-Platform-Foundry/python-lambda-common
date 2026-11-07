"""An uploaded ZIP is opened without trusting it: limits, no zip slip, only the wanted types."""

import io
import zipfile

import pytest

from lambda_app_common.archives import (
    KEY_MATERIAL_EXTENSIONS,
    MiB,
    ArchiveLimits,
    UnsafeArchiveError,
    _bounded_chunks,
    extract_zip,
    normalize_extensions,
    read_zip,
    scan_zip,
)


def make_zip(entries, compression=zipfile.ZIP_DEFLATED):
    """``entries``: {name: bytes} or a list of (name_or_ZipInfo, bytes)."""
    buffer = io.BytesIO()
    items = entries.items() if isinstance(entries, dict) else entries
    with zipfile.ZipFile(buffer, "w", compression) as zf:
        for name, data in items:
            zf.writestr(name, data)
    buffer.seek(0)
    return zipfile.ZipFile(buffer)


def accepted_names(scan):
    return [info.filename for info in scan.accepted]


# --- types --------------------------------------------------------------------------------

def test_only_the_allowed_types_are_accepted_and_the_rest_are_skipped_by_name():
    archive = make_zip({"a.pdf": b"%PDF", "b.XML": b"<x/>", "notes.txt": b"hi", "run.exe": b"MZ"})

    scan = scan_zip(archive, allowed_extensions=["pdf", ".xml"])

    assert accepted_names(scan) == ["a.pdf", "b.XML"]
    assert scan.skipped == [("notes.txt", "disallowed_type"), ("run.exe", "disallowed_type")]


@pytest.mark.parametrize("name", ["firma.key", "firma.cer", "cert.pfx", "cert.p12", "key.pem", "FIEL.KEY"])
def test_key_material_is_never_extracted_even_without_an_allow_list(name):
    archive = make_zip({name: b"secret", "a.pdf": b"%PDF"})

    scan = scan_zip(archive)

    assert accepted_names(scan) == ["a.pdf"]
    assert scan.skipped == [(name, "key_material")]


def test_the_questionnaire_extensions_are_all_key_material():
    assert {".key", ".cer", ".pfx", ".p12", ".pem"} <= KEY_MATERIAL_EXTENSIONS


def test_key_material_is_skipped_even_when_a_caller_allows_it():
    scan = scan_zip(make_zip({"firma.key": b"x"}), allowed_extensions=["key"])

    assert scan.accepted == []
    assert scan.skipped == [("firma.key", "key_material")]


@pytest.mark.parametrize("name", ["inner.zip", "inner.rar", "inner.7z", "inner.tar.gz", "dir/inner.ZIP"])
def test_nested_archives_are_skipped(name):
    scan = scan_zip(make_zip({name: b"PK", "a.pdf": b"%PDF"}))

    assert accepted_names(scan) == ["a.pdf"]
    assert scan.skipped == [(name, "nested_archive")]


def test_encrypted_entries_are_skipped():
    archive = make_zip({"locked.pdf": b"%PDF", "open.pdf": b"%PDF"})
    archive.getinfo("locked.pdf").flag_bits |= 0x1  # writestr can't encrypt; mark it as read back
    scan = scan_zip(archive, allowed_extensions=["pdf"])

    assert accepted_names(scan) == ["open.pdf"]
    assert scan.skipped == [("locked.pdf", "encrypted")]


def test_symlink_entries_are_skipped():
    info = zipfile.ZipInfo("link.pdf")
    info.external_attr = (0o120777 << 16)
    scan = scan_zip(make_zip([(info, b"/etc/passwd")]))

    assert scan.accepted == []
    assert scan.skipped == [("link.pdf", "symlink")]


def test_directory_entries_are_neither_accepted_nor_reported():
    scan = scan_zip(make_zip({"folder/": b"", "folder/a.pdf": b"%PDF"}), allowed_extensions=["pdf"])

    assert accepted_names(scan) == ["folder/a.pdf"]
    assert scan.skipped == []


def test_normalize_extensions():
    assert normalize_extensions(["PDF", ".Xml", " xlsx ", "", "."]) == {".pdf", ".xml", ".xlsx"}
    assert normalize_extensions(None) is None


# --- zip slip -----------------------------------------------------------------------------

@pytest.mark.parametrize("name", ["../evil.pdf", "a/../../evil.pdf", "/etc/evil.pdf", "C:/evil.pdf",
                                  "..\\evil.pdf", "\\evil.pdf"])
def test_a_path_outside_the_destination_refuses_the_whole_archive(name, tmp_path):
    archive = make_zip({"ok.pdf": b"%PDF", name: b"%PDF"})

    with pytest.raises(UnsafeArchiveError, match="unsafe path"):
        extract_zip(archive, tmp_path / "out")

    assert not (tmp_path / "out").exists() or not any((tmp_path / "out").rglob("*"))
    assert not (tmp_path / "evil.pdf").exists()


def test_a_disallowed_entry_with_a_climbing_path_still_refuses_the_archive():
    # Checked before the type filter: an archive that tries it is not one to half-trust.
    with pytest.raises(UnsafeArchiveError):
        scan_zip(make_zip({"../x.key": b"x"}), allowed_extensions=["pdf"])


# --- bombs --------------------------------------------------------------------------------

def test_too_many_entries_refuses_the_archive():
    archive = make_zip({f"{i}.pdf": b"%PDF" for i in range(6)})

    with pytest.raises(UnsafeArchiveError, match="6 entries; the limit is 5"):
        scan_zip(archive, limits=ArchiveLimits(max_entries=5))


def test_an_entry_over_the_per_file_limit_refuses_the_archive():
    archive = make_zip({"big.pdf": b"x" * 2048}, compression=zipfile.ZIP_STORED)

    with pytest.raises(UnsafeArchiveError, match="limit per file"):
        scan_zip(archive, limits=ArchiveLimits(max_entry_size=1024))


def test_the_total_over_the_limit_refuses_the_archive():
    archive = make_zip({"a.pdf": b"x" * 600, "b.pdf": b"x" * 600}, compression=zipfile.ZIP_STORED)

    with pytest.raises(UnsafeArchiveError, match="add up to more than 1000"):
        scan_zip(archive, limits=ArchiveLimits(max_total_size=1000))


def test_skipped_entries_do_not_count_towards_the_size_limits():
    archive = make_zip({"a.pdf": b"x" * 600, "big.txt": b"x" * 5000}, compression=zipfile.ZIP_STORED)

    scan = scan_zip(archive, allowed_extensions=["pdf"], limits=ArchiveLimits(max_entry_size=1000, max_total_size=1000))

    assert accepted_names(scan) == ["a.pdf"]


def test_a_bomb_is_refused_on_its_compression_ratio():
    archive = make_zip({"bomb.xml": b"\0" * (4 * MiB)})  # deflates about 1000:1

    with pytest.raises(UnsafeArchiveError, match="compresses"):
        scan_zip(archive)


def test_small_entries_that_compress_very_well_are_fine():
    archive = make_zip({"blank.xml": b" " * (512 * 1024)})

    assert accepted_names(scan_zip(archive)) == ["blank.xml"]


def test_an_entry_inflating_past_its_declared_size_is_stopped():
    archive = make_zip({"a.pdf": b"x" * 10})
    info = archive.getinfo("a.pdf")
    lying = zipfile.ZipInfo("a.pdf")
    lying.file_size = 4

    with archive.open(info) as source, pytest.raises(UnsafeArchiveError, match="inflates past"):
        list(_bounded_chunks(source, lying))


def test_the_error_is_a_value_error_so_the_api_answers_400():
    assert issubclass(UnsafeArchiveError, ValueError)


# --- extract / read -----------------------------------------------------------------------

def test_extract_keeps_the_layout_and_writes_only_accepted_entries(tmp_path):
    archive = make_zip({"Batch/a.pdf": b"%PDF-a", "Batch/a.xml": b"<a/>", "Batch/firma.key": b"k",
                        "Batch/inner.zip": b"PK"})

    extraction = extract_zip(archive, tmp_path, allowed_extensions=["pdf", "xml"])

    written = sorted(p.relative_to(tmp_path).as_posix() for p in tmp_path.rglob("*") if p.is_file())
    assert written == ["Batch/a.pdf", "Batch/a.xml"]
    assert (tmp_path / "Batch" / "a.pdf").read_bytes() == b"%PDF-a"
    assert [(f.name, f.size) for f in extraction.files] == [("Batch/a.pdf", 6), ("Batch/a.xml", 4)]
    assert extraction.paths == [(tmp_path / "Batch" / "a.pdf").resolve(), (tmp_path / "Batch" / "a.xml").resolve()]
    assert extraction.skipped == [("Batch/firma.key", "key_material"), ("Batch/inner.zip", "nested_archive")]


def test_a_refused_archive_writes_nothing(tmp_path):
    archive = make_zip({"a.pdf": b"%PDF", "bomb.xml": b"\0" * (4 * MiB)})

    with pytest.raises(UnsafeArchiveError):
        extract_zip(archive, tmp_path / "out")

    assert not (tmp_path / "out").exists()


def test_read_returns_the_accepted_entries_in_memory():
    contents = read_zip(make_zip({"a.pdf": b"%PDF", "b.cer": b"c"}), allowed_extensions=["pdf"])

    assert contents.files == {"a.pdf": b"%PDF"}
    assert contents.skipped == [("b.cer", "key_material")]


def test_skipped_names_are_logged_without_their_content(capsys):
    scan_zip(make_zip({"a.pdf": b"%PDF", "firma.key": b"PRIVATE-KEY-BYTES"}), allowed_extensions=["pdf"])

    out = capsys.readouterr().out
    assert "Skipped 1 of 2 ZIP entries: firma.key (key_material)" in out
    assert "PRIVATE-KEY-BYTES" not in out


def test_the_skipped_log_line_is_bounded(capsys):
    scan_zip(make_zip({f"{i}.txt": b"x" for i in range(60)}), allowed_extensions=["pdf"])

    out = capsys.readouterr().out
    assert "Skipped 60 of 60 ZIP entries" in out
    assert "and 10 more" in out
    assert "59.txt" not in out

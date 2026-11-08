import pytest
from pydantic import ValidationError

from koda_tracker.upgrade_elf import ElfEvidence, eval_elf


def _evidence(*, complete=True, providers=None):
    platform = {"architecture": "x86_64", "elfClass": 64, "byteOrder": "little"}
    if providers is None:
        providers = [{
            **platform, "soname": "libdemo.so.1",
            "symbols": [{"name": "demo_open", "version": "DEMO_1.0"}, {"name": "demo_close", "version": "DEMO_2.0", "defaultVersion": True}],
        }]
    return {
        "kind": "elf", "source": "readelf", "complete": complete,
        "consumers": [{
            **platform, "name": "app", "needed": [{
                "soname": "libdemo.so.1",
                "symbols": [{"name": "demo_open", "version": "DEMO_1.0"}, {"name": "demo_close"}],
            }],
        }],
        "providers": providers,
    }


def test_exact_soname_and_symbol_requirements_are_reported():
    data = _evidence()
    assert eval_elf(ElfEvidence.model_validate(data), "amd64")[0] == "conditions_met"

    data["providers"][0]["symbols"][0]["version"] = "DEMO_2.0"
    status, reasons = eval_elf(ElfEvidence.model_validate(data), "x86_64")
    assert status == "conflict" and "demo_open@DEMO_1.0" in reasons[0]

    data["providers"][0]["soname"] = "libdemo.so.2"
    status, reasons = eval_elf(ElfEvidence.model_validate(data), "x86_64")
    assert status == "conflict" and "libdemo.so.1" in reasons[0]


@pytest.mark.parametrize("mismatch", [{"architecture": "aarch64"}, {"elfClass": 32}, {"byteOrder": "big"}])
def test_wrong_candidate_platform_and_consumer_profile_are_distinguished(mismatch):
    data = _evidence()
    data["providers"][0].update(mismatch)
    assert eval_elf(ElfEvidence.model_validate(data), "x86_64")[0] == "conflict"

    data["consumers"][0].update(mismatch)
    assert eval_elf(ElfEvidence.model_validate(data), "x86_64")[0] == "unknown"


def test_missing_provider_in_partial_evidence_is_unknown():
    data = _evidence(complete=False, providers=[])
    assert eval_elf(ElfEvidence.model_validate(data), "x86_64")[0] == "unknown"

    data["complete"] = True
    assert eval_elf(ElfEvidence.model_validate(data), "x86_64")[0] == "conflict"

    data["consumers"][0]["needed"] = []
    assert eval_elf(ElfEvidence.model_validate(data), "x86_64")[0] == "unknown"


def test_tentative_import_and_ambiguous_providers_are_unknown():
    data = _evidence()
    data["providers"][0]["symbols"].pop()
    data["consumers"][0]["needed"][0]["symbols"][1]["definite"] = False
    assert eval_elf(ElfEvidence.model_validate(data), "x86_64")[0] == "unknown"

    data = _evidence()
    data["providers"].append(data["providers"][0])
    assert eval_elf(ElfEvidence.model_validate(data), "x86_64")[0] == "unknown"

    data = _evidence()
    data["providers"][0]["symbols"][1]["defaultVersion"] = False
    assert eval_elf(ElfEvidence.model_validate(data), "x86_64")[0] == "unknown"


def test_model_rejects_unknown_evidence_fields_and_coercions():
    with pytest.raises(ValidationError):
        ElfEvidence.model_validate({**_evidence(), "assumedCompatible": True})
    with pytest.raises(ValidationError):
        ElfEvidence.model_validate({**_evidence(), "complete": "true"})


def test_version_definition_needed_even_without_a_named_import():
    data = _evidence()
    data["consumers"][0]["needed"][0]["versions"] = ["DEMO_3.0"]
    status, reasons = eval_elf(ElfEvidence.model_validate(data), "x86_64")
    assert status == "conflict" and "DEMO_3.0" in reasons[0]
    data["providers"][0]["versions"] = ["DEMO_3.0"]
    assert eval_elf(ElfEvidence.model_validate(data), "x86_64")[0] == "conditions_met"


def test_readelf_collector_matches_needed_version_index_and_preserves_default_exports():
    from pathlib import Path
    import runpy

    script = runpy.run_path(str(Path(__file__).resolve().parents[2] / "scripts" / "elf-upgrade-evidence.py"))
    header = """ELF Header:
  Class:                             ELF64
  Data:                              2's complement, little endian
  Type:                              DYN (Shared object file)
  Machine:                           Advanced Micro Devices X86-64
"""
    consumer = script["parse_readelf"](header + """
 0x0000000000000001 (NEEDED)             Shared library: [libdemo.so.1]
 0x0000000000000001 (NEEDED)             Shared library: [libunrelated.so.1]
Symbol table '.dynsym' contains 4 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND
     1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND demo_open@SHARED_1.0 (2)
     2: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND unrelated@SHARED_1.0 (3)
     3: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND demo_close

Version needs section '.gnu.version_r' contains 2 entries:
  000000: Version: 1  File: libdemo.so.1  Cnt: 1
  0x0010:   Name: SHARED_1.0  Flags: none  Version: 2
  0x0020: Version: 1  File: libunrelated.so.1  Cnt: 1
  0x0030:   Name: SHARED_1.0  Flags: none  Version: 3
""")
    provider = script["parse_readelf"](header + """
 0x000000000000000e (SONAME)             Library soname: [libdemo.so.1]
Symbol table '.dynsym' contains 3 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND
     1: 0000000000001000     0 FUNC    GLOBAL DEFAULT  1 demo_open@SHARED_1.0
     2: 0000000000001000     0 FUNC    GLOBAL DEFAULT  1 demo_close@@SHARED_2.0

Version definition section '.gnu.version_d' contains 2 entries:
  0x0000: Rev: 1  Flags: none  Index: 2  Cnt: 1  Name: SHARED_1.0
  0x0020: Rev: 1  Flags: none  Index: 3  Cnt: 1  Name: SHARED_2.0
""")
    evidence = ElfEvidence.model_validate(script["build_evidence"]([("consumer", consumer)], [provider], [provider], True))
    requirements = evidence.consumers[0].needed[0]
    assert [(item.name, item.version, item.definite) for item in requirements.symbols] == [
        ("demo_open", "SHARED_1.0", True), ("demo_close", None, False),
    ]
    assert requirements.versions == ["SHARED_1.0"]
    assert eval_elf(evidence, "x86_64")[0] == "conditions_met"

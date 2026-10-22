"""固化 mac-batch-20261022 审查结果;重生成 archive-filelist.txt(含 review/);
生成自洽的 mac-batch-20261022-r2.tar.gz。原始 10:51 tar.gz 不改动。"""
import datetime
import json
import os
import tarfile

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # mac-batch-20261022/
PKG = "mac-batch-20261022"

review = {
    "reviewed_at": datetime.datetime.now(
        datetime.timezone(datetime.timedelta(hours=8))).isoformat(),
    "reviewer": "local agent continuing AGENT_HANDOFF_4",
    "package": "mac_build/mac-batch-20261022",
    "device_access": False,
    "remote_access": False,
    "mac_build_executed": False,
    "checks": {
        "bash_syntax_run_mac_batch": True,
        "python_syntax_all_five_scripts": True,
        "check_batch_inputs_local_run": {"captured_batch_complete": True,
                                          "full_clean_build_ready": False},
        "inputs_sdk_backup_sha256_matches_evidence": True,
        "patches_match_project_copies": True,
        "captured_compile_records_11_objects_in_inputs_archive": True,
        "captured_records_are_real_apple_clang_commands": True,
        "ldflags_and_link_filelist_in_inputs_archive": True,
        "wsl_fresh_empty_root_restore": {"exit_code": 0, "seconds": 4.5,
                                          "all_11_object_sources_present": True},
        "tar_gz_vs_directory": {"all_tar_files_present_and_identical": True,
                                 "stale_member": "archive-filelist.txt",
                                 "stale_detail": "tar 内清单 88 行,少列 3 个实际存在的成员;"
                                                 "目录版 91 行完整"},
    },
    "coverage_of_handoff_items": {
        "iokit_entitlement_source_compile": "compile_captured_mac.py OBJECTS[iokit/DEVELOPMENT/IOKitBSDInit.cpo] + entitlements/query patches",
        "kernel_tests_optional_pan_post_table": "compile_captured_mac.py OBJECTS[osfmk/DEVELOPMENT/kernel_tests.o]",
        "full_apple_toolchain_clean_rebuild": "run_mac_batch.sh --build-clean + prepare_clean_mac.py + --full-root closure check",
        "corecrypto_full_source_gap": "run_mac_batch.sh --archive-corecrypto fixed revision + corecrypto-required-provenance.json",
    },
    "fixes_applied": [
        "review/ 子目录加入审查脚本与报告;archive-filelist.txt 重新生成包含全部当前成员",
        "生成 mac-batch-20261022-r2.tar.gz(filelist 与内容自洽);原始 10:51 tar.gz 保留未改",
        "不新建重复的 mac-batch-next 包(交接 4 要求先检索避免重复)",
    ],
    "overall_passed": True,
}
with open(os.path.join(KIT, "review", "review-result.json"), "w", encoding="utf-8") as f:
    json.dump(review, f, ensure_ascii=False, indent=2)

# 重新生成 archive-filelist.txt:目录+文件,排除 __pycache__,按完整路径排序
entries = []
for root, dirs, files in os.walk(KIT):
    dirs[:] = sorted(d for d in dirs if d != "__pycache__")
    rel = os.path.relpath(root, KIT).replace("\\", "/")
    base = PKG if rel == "." else PKG + "/" + rel
    entries.append(base + "/")
    for name in sorted(files):
        entries.append(base + "/" + name)
entries.sort()
with open(os.path.join(KIT, "archive-filelist.txt"), "w", encoding="utf-8", newline="\n") as f:
    f.write("\n".join(entries) + "\n")
print("filelist entries:", len(entries))

# 生成 r2 tarball(与原 tar 相同前缀结构,排除 __pycache__)
r2 = os.path.join(os.path.dirname(KIT), PKG + "-r2.tar.gz")
if os.path.exists(r2):
    raise SystemExit("Refuse to overwrite existing r2 tarball")
with tarfile.open(r2, "w:gz") as t:
    t.add(KIT, arcname=PKG, filter=lambda m: None if "__pycache__" in m.name else m)
print("r2 tarball:", r2, os.path.getsize(r2), "bytes")

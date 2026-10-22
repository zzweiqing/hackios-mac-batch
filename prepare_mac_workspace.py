#!/usr/bin/env python3
"""Restore a fresh private Mac workspace from the batch's local captures."""
import argparse,json,os,shutil,tarfile
from pathlib import Path

KIT=Path(__file__).resolve().parent
OLD='/Users/chuzu/Desktop/UniXNU-build/unixnu-mac-offline-20261021/work/UniXNU/'
def extract(archive,destination,strip=0):
    destination.mkdir(parents=True,exist_ok=True)
    with tarfile.open(archive,'r:gz') as stream:
        members=[]
        for member in stream.getmembers():
            parts=Path(member.name).parts[strip:]
            if not parts:continue
            if Path(member.name).is_absolute() or '..' in parts:raise SystemExit('Unsafe archive member')
            member.name=str(Path(*parts))
            if member.issym() and member.linkname.startswith(OLD):
                member.linkname=os.path.relpath(destination/member.linkname[len(OLD):],destination/Path(member.name).parent)
            elif (member.issym() or member.islnk()) and Path(member.linkname).is_absolute():raise SystemExit('Absolute external link')
            if member.issym() or member.islnk():
                resolved=(destination/Path(member.name).parent/member.linkname).resolve()
                if not resolved.is_relative_to(destination.resolve()):raise SystemExit('Escaping relative symlink')
            members.append(member)
        stream.extractall(destination,members=members,filter='fully_trusted')
p=argparse.ArgumentParser(description=__doc__);p.add_argument('root',type=Path);a=p.parse_args();root=a.root.resolve()
if root.exists() and any(root.iterdir()):raise SystemExit('Fresh empty root required')
root.mkdir(parents=True,exist_ok=True)
extract(KIT/'inputs/mac-xnu-sdk-and-objects-backup-20261022.tar.gz',root)
extract(KIT/'inputs/xnu-d8b80295118ef25ac3a784134bcf95cd8e88109f.tar.gz',root/'.cache/xnu-work',1)
shutil.copytree(KIT/'capture/build',root/'build',dirs_exist_ok=True)
shutil.copytree(KIT/'capture/.cache/xnu-work',root/'.cache/xnu-work',dirs_exist_ok=True)
extract(KIT/'inputs/restored-apple-headers.tar.gz',root/'.cache/xnu-work')
# Needed provenance/build scripts are copied as inert source material.
shutil.copytree(KIT/'capture/scripts',root/'scripts',dirs_exist_ok=True)
# Captured compile commands pass -fsanitize-ignorelist pointing at the object root's
# san/kasan-blacklist-arm64, which the original Mac build produced but the backup never
# archived. Materialize it from the fixed XNU source instead of editing captured flags.
kasan_dst=root/'build/xnu/ios-obj/san/kasan-blacklist-arm64'
kasan_src=root/'.cache/xnu-work/san/memory/kasan-blacklist-arm64'
if not kasan_dst.exists():
    if not kasan_src.is_file():raise SystemExit('kasan blacklist missing from fixed XNU source')
    kasan_dst.parent.mkdir(parents=True,exist_ok=True)
    shutil.copy2(kasan_src,kasan_dst)
# Same gap for EXPORT_HDRS/libsa: the backup captured 7 of 8 EXPORT_HDRS dirs.
# Kernel/bsd/iokit TUs never include from libsa (standalone bootstrap only), so an
# empty dir is semantically identical to the missing one; it only silences
# -Wmissing-include-dirs in the captured commands.
(root/'build/xnu/ios-obj/EXPORT_HDRS/libsa').mkdir(parents=True,exist_ok=True)
(root/'batch-restore.json').write_text(json.dumps({'source_commit':'d8b80295118ef25ac3a784134bcf95cd8e88109f','source_archive':'fixed local XNU snapshot','network_used':False,'mac_source_compile_executed':False},indent=2)+'\n')
print(root)

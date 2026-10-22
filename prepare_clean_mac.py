#!/usr/bin/env python3
"""Create a private full-build clone from a user-supplied exact resource root.

Retains captured source libraries/SDK, but drops cloned XNU build outputs only
so every kernel object is produced by one new Apple compiler configuration.
Never modifies the provided source root. No network operations.
"""
import argparse,json,shutil,subprocess
from pathlib import Path
KIT=Path(__file__).resolve().parent
REVISIONS={'corecrypto-2023':'11fba65b12d8830630e248dfa8344caf8b065f26','libpthread':'c0e60fb5ecfc54cf379c261d3f9572cc22ded891'}
p=argparse.ArgumentParser(description=__doc__);p.add_argument('root',type=Path);p.add_argument('full',type=Path);a=p.parse_args();root=a.root.resolve();full=a.full.resolve()
if root==full or root.is_relative_to(full) or full.is_relative_to(root):raise SystemExit('Independent new root required')
if root.exists():raise SystemExit('Refuse to replace an existing clean root')
for name,revision in REVISIONS.items():
    path=full/'refer'/name
    found=subprocess.check_output(['git','-C',str(path),'rev-parse','HEAD'],text=True).strip()
    if found!=revision:raise SystemExit('Wrong fixed source: '+name)
    if subprocess.check_output(['git','-C',str(path),'status','--porcelain'],text=True).strip():raise SystemExit('Modified fixed source: '+name)
shutil.copytree(full,root,symlinks=True)
source=root/'.cache/xnu-work'
if not source.is_dir():raise SystemExit('Full resource root lacks current prepared XNU source')
for patch in ('nabu-mockfs-no-amfi-entitlements.patch','nabu-mockfs-no-amfi-query.patch','nabu-mockfs-console-popup.patch'):
    command=['git','apply',str(KIT/'patches'/patch)]
    check=subprocess.run([command[0],command[1],'--check',command[2]],cwd=source,capture_output=True,text=True)
    if check.returncode==0:subprocess.run(command,cwd=source,check=True)
    elif subprocess.run([command[0],command[1],'--reverse','--check',command[2]],cwd=source,capture_output=True).returncode:raise SystemExit('Patch review required: '+patch)
copied=root/'build/xnu'
if copied.exists():
    # Checked absolute target is within this exact new clone before deletion.
    if not copied.resolve().is_relative_to(root):raise SystemExit('Unsafe cloned output path')
    shutil.rmtree(copied)
(root/'mac-clean-plan.json').write_text(json.dumps({'full_resources':str(full),'fixed_revisions':REVISIONS,'all_xnu_objects_to_rebuild':True,'source_libraries_rebuilt':False,'network_used':False},indent=2)+'\n')
print(root)

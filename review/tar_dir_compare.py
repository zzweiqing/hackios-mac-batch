import tarfile, os, hashlib

t = tarfile.open('mac-batch-20261022.tar.gz', 'r:gz')
names = [m.name for m in t.getmembers() if m.isfile()]
print('tar files:', len(names))
mismatch, missing = [], []
dirmap = {}
for n in names:
    rel = n
    matched = False
    for prefix in ('', './', 'mac-batch-20261022/'):
        if rel.startswith(prefix):
            p = os.path.join('mac-batch-20261022', rel[len(prefix):])
            if os.path.isfile(p):
                h1 = hashlib.sha256(t.extractfile(n).read()).hexdigest()
                h2 = hashlib.sha256(open(p, 'rb').read()).hexdigest()
                if h1 != h2:
                    mismatch.append(rel)
                dirmap[rel[len(prefix):]] = True
                matched = True
                break
    if not matched:
        missing.append(rel)
print('missing in dir:', missing[:10], 'total', len(missing))
print('mismatched:', mismatch[:10], 'total', len(mismatch))
tarset = set(dirmap) | set(n.lstrip('./').removeprefix('mac-batch-20261022/') for n in missing)
extra = []
for root, dirs, files in os.walk('mac-batch-20261022'):
    dirs[:] = [d for d in dirs if d != '__pycache__']
    for f in files:
        full = os.path.join(root, f).replace(os.sep, '/')
        rel = full[len('mac-batch-20261022/'):]
        if rel not in tarset:
            extra.append(rel)
print('extra in dir not in tar:', extra[:15], 'total', len(extra))

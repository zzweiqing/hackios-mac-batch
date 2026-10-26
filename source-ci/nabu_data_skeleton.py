"""Provision directories on the verified volatile Data mount before Apple init."""
import hashlib

from nabu_graphics_startup import _recount_hunks, _replace_once

DATA_PATCH = 'patches/xnu/zzzz-nabu-data-skeleton.patch'

# Parents precede their children. tzinit owns the zoneinfo/icutz symlinks;
# leave those names to the original userspace dataset initialization.
DIRECTORIES = (
    ('db', 0o755, 0, 0),
    ('db/dslocal', 0o755, 0, 0),
    ('db/dslocal/nodes', 0o755, 0, 0),
    ('db/dslocal/nodes/Default', 0o755, 0, 0),
    ('db/dslocal/nodes/Default/users', 0o755, 0, 0),
    ('db/dslocal/nodes/Default/groups', 0o755, 0, 0),
    ('db/dslocal/nodes/Default/config', 0o755, 0, 0),
    ('db/timezone', 0o755, 0, 0),
    ('db/com.apple.xpc.launchd', 0o755, 0, 0),
    ('keybags', 0o700, 0, 0),
    ('keybags/backup', 0o700, 0, 0),
    ('log', 0o755, 0, 0),
    ('log/com.apple.xpc.launchd', 0o755, 0, 0),
    ('run', 0o755, 0, 0),
    ('tmp', 0o1777, 0, 0),
    ('mobile', 0o755, 501, 501),
    ('mobile/Library', 0o755, 501, 501),
    ('mobile/Library/Preferences', 0o755, 501, 501),
    ('mobile/Library/Caches', 0o755, 501, 501),
    ('mobile/Library/Logs', 0o755, 501, 501),
    ('mobile/Containers', 0o755, 501, 501),
    ('mobile/Documents', 0o755, 501, 501),
    ('mobile/Media', 0o755, 501, 501),
    ('mobile/tmp', 0o700, 501, 501),
    ('containers', 0o755, 0, 0),
    ('containers/Data', 0o755, 0, 0),
    ('containers/Data/System', 0o755, 0, 0),
    ('containers/Data/Application', 0o755, 0, 0),
    ('containers/Shared', 0o755, 0, 0),
    ('containers/Shared/SystemGroup', 0o755, 0, 0),
    ('PersonaVolumes', 0o755, 0, 0),
    ('preboot', 0o755, 0, 0),
    ('root', 0o700, 0, 0),
    ('Library', 0o755, 0, 0),
    ('Library/Preferences', 0o755, 0, 0),
)

AFTER_DATA = '''#if (DEVELOPMENT || DEBUG) && defined(XNU_NATIVE_LEGACY_DISPLAY) && XNU_NATIVE_LEGACY_DISPLAY
\tif (!error) {
\t\textern void nabu_graphics_start_after_root(void);
\t\tnabu_graphics_start_after_root();
\t}
#endif
'''

HELPER = r'''static int
native_owner_data_mkdir(proc_t p, user_addr_t scratch, mount_t data_mount,
    const char *path, mode_t mode, uid_t uid, gid_t gid)
{
	vfs_context_t ctx = vfs_context_current();
	vnode_t vp = NULLVP;
	int error = vnode_lookup(path, VNODE_LOOKUP_NOFOLLOW, &vp, ctx);
	if (!error) {
		error = vnode_vtype(vp) != VDIR ? ENOTDIR :
		    (vnode_mount(vp) != data_mount ? EXDEV : 0);
		vnode_put(vp);
		return error;
	}
	if (error != ENOENT) return error;
	char parent[160];
	if (strlen(path) >= sizeof(parent)) return ENAMETOOLONG;
	strlcpy(parent, path, sizeof(parent));
	char *slash = strrchr(parent, '/');
	if (!slash || slash == parent) return EINVAL;
	*slash = 0;
	error = vnode_lookup(parent, VNODE_LOOKUP_NOFOLLOW, &vp, ctx);
	if (error) return error;
	error = vnode_vtype(vp) != VDIR ? ENOTDIR :
	    (vnode_mount(vp) != data_mount ? EXDEV : 0);
	vnode_put(vp);
	if (error) return error;
	/* Use the regular VFS mkdir path and the existing 4 KiB init scratch. */
	struct mkdir_args request = {.path = scratch + 0xa00, .mode = mode};
	int32_t result = 0;
	error = copyout(path, request.path, strlen(path) + 1);
	if (!error) error = mkdir(p, &request, &result);
	if (error) return error;
	error = vnode_lookup(path, VNODE_LOOKUP_NOFOLLOW, &vp, ctx);
	if (error) return error;
	if (vnode_vtype(vp) != VDIR || vnode_mount(vp) != data_mount) {
		vnode_put(vp);
		return EXDEV;
	}
	struct vnode_attr va;
	VATTR_INIT(&va);
	VATTR_SET(&va, va_mode, mode);
	VATTR_SET(&va, va_uid, uid);
	VATTR_SET(&va, va_gid, gid);
	error = vnode_setattr(vp, &va, ctx);
	vnode_put(vp);
	return error;
}

static int
native_owner_data_skeleton(proc_t p, user_addr_t scratch, mount_t data_mount)
{
	static const struct {
		const char *path;
		mode_t mode;
		uid_t uid;
		gid_t gid;
	} dirs[] = {
__DIRECTORIES__
	};
	for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); ++i) {
		int error = native_owner_data_mkdir(p, scratch, data_mount,
		    dirs[i].path, dirs[i].mode, dirs[i].uid, dirs[i].gid);
		if (error) {
			printf("NABU DATA: skeleton failed path=%s error=%d\n", dirs[i].path, error);
			return error;
		}
	}
	printf("NABU DATA: skeleton ready dirs=%lu\n", (unsigned long)(sizeof(dirs) / sizeof(dirs[0])));
	return 0;
}

'''


def helper_source():
    rows = '\n'.join(f'\t\t{{ "/private/var/{path}", 0{mode:o}, {uid}, {gid} }},'
                     for path, mode, uid, gid in DIRECTORIES)
    return HELPER.replace('__DIRECTORIES__', rows)


def add_data_skeleton(text):
    anchor = 'static int\nnative_owner_data_prepare(proc_t p, user_addr_t scratch)\n'
    text = _replace_once(text, anchor, helper_source() + anchor)
    marker = '\tif (!error) native_owner_data_stage = 4;\n'
    text = _replace_once(text, marker,
                         '\tif (!error) error = native_owner_data_skeleton(p, scratch, data_mount);\n' + marker)
    end = '\tnative_owner_data_status = error;\n\treturn error;\n'
    text = _replace_once(text, end, '\tnative_owner_data_status = error;\n' + AFTER_DATA + '\treturn error;\n')
    return text


def skeleton_patch():
    helper = ''.join('+' + line + '\n' for line in helper_source().splitlines())
    patch = ('--- a/bsd/kern/kern_exec.c\n+++ b/bsd/kern/kern_exec.c\n'
             '@@ -7824,3 +7824,3 @@\n' + helper +
             ' static int\n native_owner_data_prepare(proc_t p, user_addr_t scratch)\n {\n'
             '@@ -7879,6 +7879,7 @@\n'
             ' \tif (actual != device || (vfs_flags(data_mount) & MNT_RDONLY) ||\n'
             ' \t    strcmp(vfs_statfs(data_mount)->f_fstypename, "apfs")) error = EINVAL;\n'
             '+\tif (!error) error = native_owner_data_skeleton(p, scratch, data_mount);\n'
             ' \tif (!error) native_owner_data_stage = 4;\n'
             ' \tif (!error) native_gpu_addon_prepare(p, scratch);\n'
             ' \tif (!error) native_staged_apps_prepare(p, scratch, data_mount);\n'
             ' done:\n'
             '@@ -7886,5 +7886,5 @@\n'
             ' \tif (data_root) vnode_put(data_root);\n'
             ' \tnative_owner_data_status = error;\n' +
             ''.join('+' + line + '\n' for line in AFTER_DATA.splitlines()) +
             ' \treturn error;\n }\n #endif\n')
    return _recount_hunks(patch).encode('utf-8')


def wire_graphics_compile_flag(text):
    anchor = 'EXTRA_MAKE_ARGS+=("kern_exec.o_CFLAGS_ADD='
    return _replace_once(text, anchor,
                         anchor + '-DXNU_NATIVE_LEGACY_DISPLAY=${XNU_NATIVE_LEGACY_DISPLAY:-0} ')


def prepare_data_skeleton(upstream):
    path = upstream / DATA_PATCH
    if path.exists():
        raise ValueError('Data skeleton patch already exists; prepare a fresh source tree')
    build = upstream / 'scripts/build-xnu-4k-baseline.sh'
    text = build.read_text(encoding='utf-8')
    old = 'for LATE_PATCH in "$ROOT/patches/xnu/zzz-boot-progress.patch"'
    new = 'for LATE_PATCH in "$ROOT/' + DATA_PATCH + '" "$ROOT/patches/xnu/zzz-boot-progress.patch"'
    text = _replace_once(text, old, new)
    text = wire_graphics_compile_flag(text)
    after = skeleton_patch()
    path.write_bytes(after)
    build.write_text(text, encoding='utf-8')
    return {'patch': DATA_PATCH, 'after_sha256': hashlib.sha256(after).hexdigest(),
            'directories': [row[0] for row in DIRECTORIES], 'runtime_qualified': False}

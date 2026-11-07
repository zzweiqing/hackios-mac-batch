"""Bind FileProtectionNone attributes to the authenticated OwnerData mount only."""
import hashlib
from pathlib import Path


CONTRACT = {
    'version': 1,
    'profile_gate': 'XNU_OWNER_DATA_MOUNT',
    'mount_binding': 'verified OwnerData mount pointer and fsid, before Data skeleton',
    'getattr': 'successful class 0 becomes class D (4) on regular files and directories',
    'setattr': 'class D only, with write authorization and original mixed-attribute errors',
    'content_protection_changed': False,
    'create_changed': False,
    'boot_arg_added': False,
    'symbols': ['_nabu_owner_data_none_publish', '_nabu_owner_data_none_getattr',
                '_nabu_owner_data_none_setattr_prepare', '_nabu_owner_data_none_setattr_finish'],
}

GATE = '#if defined(XNU_OWNER_DATA_MOUNT) && XNU_OWNER_DATA_MOUNT\n'
MARKER = 'NABU_DATA_NONE_V1'
HELPER = r'''/* NABU_DATA_NONE_V1: FileProtectionNone on the verified, unencrypted OwnerData mount. */
#if defined(XNU_OWNER_DATA_MOUNT) && XNU_OWNER_DATA_MOUNT
const char nabu_owner_data_none_source_identity[] __attribute__((used)) =
    "NABUDATA_NONE_SOURCE_SHA256=__SOURCE_ID__";

static mount_t nabu_owner_data_none_mount;
static fsid_t nabu_owner_data_none_fsid;
static unsigned nabu_owner_data_none_published;

/* Called once after OwnerData's device, APFS and writable-mount checks succeed.
 * Save a pointer value and fsid, without retaining a mount reference that would
 * prevent shutdown. Readers dereference only the live mount of their vnode.
 */
__attribute__((noinline, used)) void
nabu_owner_data_none_publish(mount_t mp)
{
    if (!mp || (vfs_flags(mp) & (MNT_RDONLY | MNT_CPROTECT)) ||
        strcmp(vfs_statfs(mp)->f_fstypename, "apfs")) return;
    unsigned unpublished = 0;
    if (!__atomic_compare_exchange_n(&nabu_owner_data_none_published, &unpublished, 1,
        0, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) return;
    nabu_owner_data_none_fsid = vfs_statfs(mp)->f_fsid;
    __atomic_store_n(&nabu_owner_data_none_mount, mp, __ATOMIC_RELEASE);
    printf("NabuDataNone: mount_bound class=4 fsid=%d/%d %s\n",
        nabu_owner_data_none_fsid.val[0], nabu_owner_data_none_fsid.val[1],
        nabu_owner_data_none_source_identity);
}

static int
nabu_owner_data_none_matches(vnode_t vp)
{
    mount_t published = __atomic_load_n(&nabu_owner_data_none_mount, __ATOMIC_ACQUIRE);
    if (!published || (!vnode_isreg(vp) && !vnode_isdir(vp))) return 0;
    mount_t mp = vnode_mount(vp);
    return mp == published && !(vfs_flags(mp) & (MNT_RDONLY | MNT_CPROTECT)) &&
        !strcmp(vfs_statfs(mp)->f_fstypename, "apfs") &&
        vfs_statfs(mp)->f_fsid.val[0] == nabu_owner_data_none_fsid.val[0] &&
        vfs_statfs(mp)->f_fsid.val[1] == nabu_owner_data_none_fsid.val[1];
}

__attribute__((noinline, used)) void
nabu_owner_data_none_getattr(vnode_t vp, struct vnode_attr *vap, int error)
{
    if (!error && VATTR_IS_ACTIVE(vap, va_dataprotect_class) &&
        vap->va_dataprotect_class == 0 && nabu_owner_data_none_matches(vp)) {
        VATTR_RETURN(vap, va_dataprotect_class, 4);
    }
}

/* Other classes remain active for the original filesystem to accept or reject. */
__attribute__((noinline, used)) int
nabu_owner_data_none_setattr_prepare(vnode_t vp, struct vnode_attr *vap,
    vfs_context_t ctx, int *handled)
{
    *handled = 0;
    if (!VATTR_IS_ACTIVE(vap, va_dataprotect_class) || vap->va_dataprotect_class != 4 ||
        !nabu_owner_data_none_matches(vp)) return 0;
    if (ctx == NULL) ctx = vfs_context_current();
    int error = vnode_authorize(vp, NULLVP,
        KAUTH_VNODE_ACCESS | KAUTH_VNODE_WRITE_DATA, ctx);
    if (error) return error;
    VATTR_CLEAR_ACTIVE(vap, va_dataprotect_class);
    *handled = 1;
    return 0;
}

__attribute__((noinline, used)) void
nabu_owner_data_none_setattr_finish(struct vnode_attr *vap, int handled,
    int error, int previously_supported)
{
    if (!handled) return;
    if (!error) {
        VATTR_SET_SUPPORTED(vap, va_dataprotect_class);
    } else {
        VATTR_SET_ACTIVE(vap, va_dataprotect_class);
        if (!previously_supported) VATTR_CLEAR_SUPPORTED(vap, va_dataprotect_class);
    }
}
#endif

'''

GETATTR_SIGNATURE = 'errno_t\nVNOP_GETATTR(vnode_t vp, struct vnode_attr * vap, vfs_context_t ctx)\n'
GETATTR_RESULT = ('\t_err = (*vp->v_op[vnop_getattr_desc.vdesc_offset])(&a);\n'
                  '\tDTRACE_FSINFO(getattr, vnode_t, vp);\n')
SETATTR_SIGNATURE = 'errno_t\nVNOP_SETATTR(vnode_t vp, struct vnode_attr * vap, vfs_context_t ctx)\n'
SETATTR_LOCALS = '\tint _err;\n\tstruct vnop_setattr_args a;\n'
SETATTR_RESULT = ('\t_err = (*vp->v_op[vnop_setattr_desc.vdesc_offset])(&a);\n'
                  '\tDTRACE_FSINFO(setattr, vnode_t, vp);\n')
MOUNT_SIGNATURE = 'static int\nnative_owner_data_prepare(proc_t p, user_addr_t scratch)\n{\n'
MOUNT_CHECK = ('\tif (actual != device || (vfs_flags(data_mount) & MNT_RDONLY) ||\n'
               '\t    strcmp(vfs_statfs(data_mount)->f_fstypename, "apfs")) error = EINVAL;\n')


def identity():
    return hashlib.sha256(Path(__file__).read_bytes().replace(b'\r\n', b'\n')).hexdigest()


def helper_source():
    return HELPER.replace('__SOURCE_ID__', identity())


def _replace(text, before, after):
    if text.count(before) != 1:
        raise ValueError('OwnerData None source anchor missing or duplicated: ' + before[:80])
    return text.replace(before, after, 1)


def _pairs(target):
    if target == 'kern_exec':
        return (
            (MOUNT_SIGNATURE, '/* NABU_DATA_NONE_V1: publish only after verified mount checks. */\n'
             'extern void nabu_owner_data_none_publish(mount_t);\n' + MOUNT_SIGNATURE),
            (MOUNT_CHECK, MOUNT_CHECK + '\tif (!error) nabu_owner_data_none_publish(data_mount);\n'),
        )
    if target != 'kpi_vfs':
        raise ValueError('Unknown OwnerData None source target: ' + target)
    return (
        (GETATTR_SIGNATURE, helper_source() + GETATTR_SIGNATURE),
        (GETATTR_RESULT, GETATTR_RESULT + GATE +
         '\tnabu_owner_data_none_getattr(vp, vap, _err);\n#endif\n'),
        (SETATTR_LOCALS, SETATTR_LOCALS + GATE +
         '\tint nabu_none_handled = 0;\n'
         '\tint nabu_none_supported = VATTR_IS_SUPPORTED(vap, va_dataprotect_class) != 0;\n'
         '\t_err = nabu_owner_data_none_setattr_prepare(vp, vap, ctx, &nabu_none_handled);\n'
         '\tif (_err) return _err;\n'
         '\tif (nabu_none_handled && !vap->va_active) {\n'
         '\t\tnabu_owner_data_none_setattr_finish(vap, 1, 0, nabu_none_supported);\n'
         '\t\treturn 0;\n\t}\n#endif\n'),
        (SETATTR_RESULT, SETATTR_RESULT + GATE +
         '\tnabu_owner_data_none_setattr_finish(vap, nabu_none_handled, _err, nabu_none_supported);\n#endif\n'),
    )


def source(text, target, restore=False):
    changes = _pairs(target)
    if MARKER in text:
        for before, after in reversed(changes):
            text = _replace(text, after, before)
    elif restore:
        return text
    if restore:
        return text
    for before, after in changes:
        text = _replace(text, before, after)
    return text


def metadata(sources):
    if set(sources) != {'kern_exec', 'kpi_vfs'}:
        raise ValueError('Both OwnerData mount and VFS sources are required')
    for target, text in sources.items():
        for _, injected in _pairs(target):
            if text.count(injected) != 1:
                raise ValueError('Cannot bind missing or changed OwnerData None source: ' + target)
    return dict(contract=CONTRACT, generator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                embedded_source_identity=identity(),
                actual_source_sha256={target: hashlib.sha256(text.encode()).hexdigest()
                                      for target, text in sources.items()}, runtime_qualified=False)

"""Round-7 Zip Slip fixture: unsafe extraction + validated safe variant."""
import os
import tarfile
import zipfile


def unsafe_extract_zip(request):
    """BAD: user-uploaded archive extracted with no member-path checks."""
    archive = request.FILES.get('file')
    extract_path = '/tmp/extracted'
    if archive.name.endswith('.zip'):
        with zipfile.ZipFile(archive) as zf:
            zf.extractall(extract_path)
    elif archive.name.endswith('.tar.gz'):
        with tarfile.open(fileobj=archive) as tf:
            tf.extractall(extract_path)
    return 'ok'


def safe_extract_zip(request):
    """SAFE: each member validated against traversal / absolute paths."""
    archive = request.FILES.get('file')
    extract_path = '/tmp/extracted'
    with zipfile.ZipFile(archive) as zf:
        for member in zf.infolist():
            target = os.path.join(extract_path, member.filename)
            if member.filename.startswith('/') or '..' in member.filename:
                raise ValueError('unsafe path in archive member')
            zf.extract(member, extract_path)
    return 'ok'

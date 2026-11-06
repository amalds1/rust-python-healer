"""Acquire exact reviewed Windows tools before any downloaded executable runs."""
import argparse,hashlib,json,os,re,tarfile,urllib.request,zipfile
from pathlib import Path,PurePosixPath

MAX_ARCHIVE=80_000_000
MAX_MEMBER=128_000_000
MAX_EXPANDED=512_000_000

def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(1_048_576),b''):h.update(block)
    return h.hexdigest()

def acquire(url,path,expected,maximum):
    if not re.fullmatch('[a-f0-9]{64}',expected):raise ValueError('invalid_primary_pin')
    if path.exists():raise ValueError('destination_already_exists')
    size=0
    with urllib.request.urlopen(urllib.request.Request(url,headers={'User-Agent':'RustPythonHealer-CI'}),timeout=60) as response,path.open('xb') as out:
        for block in iter(lambda:response.read(1_048_576),b''):
            size+=len(block)
            if size>maximum:raise ValueError('archive_budget_exceeded')
            out.write(block)
    if digest(path)!=expected:raise ValueError('primary_archive_sha256_mismatch')
    return size

def safe_parts(name):
    p=PurePosixPath(name)
    if (p.is_absolute() or '\\' in name or ':' in name or '\x00' in name
            or len(p.parts)>32 or not p.parts or any(x in ('..','.') or x.endswith((' ','.')) for x in p.parts)):
        raise ValueError('unsafe_archive_member')
    reserved={'CON','PRN','AUX','NUL'}|{'COM'+str(i) for i in range(1,10)}|{'LPT'+str(i) for i in range(1,10)}
    if any(x.split('.')[0].upper() in reserved for x in p.parts):raise ValueError('reserved_archive_member')
    return p.parts

def unpack_runtime(archive,destination):
    if destination.exists():raise ValueError('runtime_destination_exists')
    with tarfile.open(archive,'r:gz') as tar:
        members=tar.getmembers()
        if not 1<=len(members)<=20000:raise ValueError('archive_member_count_budget')
        seen=set();total=0
        for m in members:
            parts=safe_parts(m.name)
            if parts[0]!='python' or not(m.isdir() or m.isfile()) or not 0<=m.size<=MAX_MEMBER:
                raise ValueError('runtime_regular_members_only')
            key='/'.join(parts).casefold()
            if key in seen:raise ValueError('duplicate_casefold_member')
            seen.add(key);total+=m.size
            if total>MAX_EXPANDED:raise ValueError('archive_expanded_budget')
        destination.mkdir(mode=0o700)
        tar.extractall(destination,members=members,filter='data')
    return destination/'python/python.exe'

def prepare(minor,destination,pins):
    if os.name!='nt':raise ValueError('native_windows_required')
    if minor not in pins['runtimes']:raise ValueError('undeclared_runtime')
    if destination.exists():raise ValueError('bootstrap_destination_exists')
    destination.mkdir(mode=0o700,parents=True)
    runtime=pins['runtimes'][minor];archive=destination/'runtime.tar.gz'
    runtime_bytes=acquire(runtime['url'],archive,runtime['sha256'],MAX_ARCHIVE)
    if runtime_bytes!=runtime['bytes']:raise ValueError('runtime_primary_size_mismatch')
    exe=unpack_runtime(archive,destination/'runtime')
    if digest(exe)!=runtime['executable_sha256']:raise ValueError('runtime_executable_identity_mismatch')
    ruff=pins['ruff'];wheel=destination/'ruff.whl'
    acquire(ruff['wheel_download_url'],wheel,ruff['wheel_sha256'],20_000_000)
    with zipfile.ZipFile(wheel) as z:
        rows=[i for i in z.infolist() if i.filename==ruff['executable_member']]
        if len(rows)!=1 or rows[0].file_size>30_000_000:raise ValueError('ruff_executable_member_invalid')
        raw=z.read(rows[0])
    if hashlib.sha256(raw).hexdigest()!=ruff['executable_sha256']:raise ValueError('ruff_executable_identity_mismatch')
    ruff_exe=destination/'ruff.exe';ruff_exe.write_bytes(raw)
    report={'status':'EXACT_PRIMARY_TOOL_BYTES_PREPARED_NOT_EXECUTED','python_minor':minor,'python_version':runtime['version'],'python_executable':str(exe.resolve()),'python_sha256':digest(exe),'runtime_archive_sha256':digest(archive),'ruff_executable':str(ruff_exe.resolve()),'ruff_sha256':digest(ruff_exe),'primary_pin_file_sha256':digest(Path(__file__).with_name('ci_toolchain_pins.json')),'source_or_tool_executed':False}
    (destination/'environment.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    return report

def main():
    p=argparse.ArgumentParser();p.add_argument('--minor',required=True);p.add_argument('--destination',type=Path,required=True);a=p.parse_args()
    pins=json.loads(Path(__file__).with_name('ci_toolchain_pins.json').read_text(encoding='utf-8'))
    print(json.dumps(prepare(a.minor,a.destination,pins)))

if __name__=='__main__':main()

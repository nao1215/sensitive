"""Freeze separate country corpora before detector tuning; never call embargo."""
import argparse
import hashlib
import json
from pathlib import Path
import random
import string
from urllib.parse import quote

from country_reference import KINDS, generate_value, valid

ROOT = Path(__file__).resolve().parents[1]


def formatted(kind, value):
    groups = {
        'us_ssn':(3,2,4),'us_itin':(3,2,4),'uk_nhs':(3,3,4),
        'in_aadhaar':(4,4,4),'ca_sin':(3,3,3),'kr_rrn':(6,7),
    }
    if kind=='uk_nino': return value[:2]+' '+value[2:4]+' '+value[4:6]+' '+value[6:8]+' '+value[8:]
    if kind=='br_cpf': return value[:3]+'.'+value[3:6]+'.'+value[6:9]+'-'+value[9:]
    if kind=='br_cnpj': return value[:2]+'.'+value[2:5]+'.'+value[5:8]+'/'+value[8:12]+'-'+value[12:]
    if kind not in groups:return value
    parts=[];offset=0
    for size in groups[kind]:parts.append(value[offset:offset+size]);offset+=size
    return (' ' if kind in ('uk_nhs','in_aadhaar') else '-').join(parts)


def near_miss(kind,value):
    # Pick a mutation rejected by the definition, not one merely different from the positive.
    candidates=[]
    if kind=='kr_rrn':candidates.append(value[:2]+'19'+value[4:])
    for position in reversed(range(len(value))):
        for char in string.digits+string.ascii_uppercase:
            if char!=value[position]:candidates.append(value[:position]+char+value[position+1:])
    return next(candidate for candidate in candidates if not valid(kind,candidate))


def rows(split):
    rng=random.Random(2026111601 if split=='development' else 2026111602)
    surroundings = [('identity=','; result=ok'),('{"subject":"','"}'),('記録 (',') 完了')] if split=='development' else [('audit [','] accepted'),('record.value="','"\n'),('項目:','、保存済み')]
    result=[]
    def append(kind,tag,text,secret=None,modern=False):
        expected=[]
        if secret is not None:
            start=len(text[:text.index(secret)].encode())
            expected=[{'start':start,'end':start+len(secret.encode())}]
        result.append({'id':kind+'/'+tag,'kind':kind,'text':text,'expected':expected,'modern_rrn':modern})
    for kind in KINDS:
        for index in range(96):
            value=generate_value(kind,rng,index)
            before,after=surroundings[index%len(surroundings)]
            variants=[value,formatted(kind,value),''.join('%'+format(ord(c),'02X') for c in value)]
            bad=near_miss(kind,value)
            for variant,secret in enumerate(variants):
                append(kind,f'positive/{index}/{variant}',before+secret+after,secret)
            append(kind,f'near-miss/{index}',before+formatted(kind,bad)+after)
            append(kind,f'embedded/{index}','build'+value+'tail')
            append(kind,f'public-id/{index}','order_id='+value)
        for index in range(32):
            append(kind,f'clean/{index}',f'build=release-{rng.randrange(1000)} status=ok duration_ms={rng.randrange(10000)}')
        if kind=='kr_rrn':
            for index in range(32):
                value=generate_value(kind,rng,index)
                value=value[:-1]+str((int(value[-1])+1)%10)
                assert valid(kind,value,modern_rrn=True) and not valid(kind,value)
                secret=formatted(kind,value)
                before='rrn=' if split=='development' else '주민등록번호: '
                append(kind,f'modern/{index}',before+secret,secret,True)
    return result


def generate(destination,check=False):
    destination.mkdir(parents=True,exist_ok=True)
    manifest={'seeds':{'development':2026111601,'held':2026111602},'rule':'Freeze before implementation; public-ID negatives intentionally share valid identity syntax; held results cannot tune the retained parser.','files':{}}
    for split in ('development','held'):
        content=''.join(json.dumps(row,ensure_ascii=False,separators=(',',':'))+'\n' for row in rows(split))
        name='countries-'+split+'.jsonl'
        data=content.encode()
        manifest['files'][name]={'sha256':hashlib.sha256(data).hexdigest(),'rows':len(content.splitlines())}
        path=destination/name
        if check:
            if path.read_bytes()!=data:raise ValueError('country corpus differs: '+name)
        else:path.write_bytes(data)
    text=json.dumps(manifest,indent=2)+'\n'
    path=destination/'countries-manifest.json'
    if check:
        if path.read_text()!=text:raise ValueError('country manifest differs')
    else:path.write_text(text)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--destination',type=Path,default=ROOT/'tests/testdata')
    parser.add_argument('--check',action='store_true')
    args=parser.parse_args()
    generate(args.destination,args.check)

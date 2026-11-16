"""Textbook identity definitions for synthetic fixtures, independent of Go parsers."""
import datetime
import string

KINDS = ('us_ssn','us_itin','uk_nino','uk_nhs','in_aadhaar','in_pan','br_cpf','br_cnpj','cn_resident_id','kr_rrn','ca_sin')


def luhn_valid(value):
    products = [int(c)*(1 if index%2==0 else 2) for index,c in enumerate(value[::-1])]
    return sum(sum(map(int,str(product))) for product in products)%10 == 0


def verhoeff_product(left, right):
    # Represent D5 as a rotation and a reflection, with five rotations first.
    rotation = (left%5 + (-1 if left>=5 else 1)*(right%5))%5
    return rotation + 5*((left>=5) != (right>=5))


def verhoeff_valid(value):
    permutation = (1,5,7,6,2,8,3,0,9,4)
    state = 0
    for position,c in enumerate(reversed(value)):
        digit = int(c)
        for _ in range(position%8):
            digit = permutation[digit]
        state = verhoeff_product(state,digit)
    return state == 0


def mod11_digit(values, weights):
    remainder = sum(a*b for a,b in zip(values,weights))%11
    return 0 if remainder<2 else 11-remainder


def cpf_digits(body):
    # Equivalent ascending-weight definition in Receita Federal's e-Financeira manual.
    value = [int(c) for c in body]
    first = sum(d*(i+1) for i,d in enumerate(value))%11%10
    second = sum(d*i for i,d in enumerate(value+[first]))%11%10
    return str(first)+str(second)


def cnpj_digits(body):
    value = [ord(c)-48 for c in body]
    first = mod11_digit(value,(5,4,3,2,9,8,7,6,5,4,3,2))
    second = mod11_digit(value+[first],(6,5,4,3,2,9,8,7,6,5,4,3,2))
    return str(first)+str(second)


def nhs_digit(body):
    remainder = sum(int(c)*(10-i) for i,c in enumerate(body))%11
    return (11-remainder)%11


def china_digit(body):
    # ISO 7064 MOD 11-2 recurrence, instead of the parser's positional weights.
    residue = 0
    for c in body:
        residue = (residue+int(c))*2%11
    check = (12-residue)%11
    return 'X' if check==10 else str(check)


def rrn_digit(body):
    return str((11-sum(int(c)*(2+i%8) for i,c in enumerate(body))%11)%10)


def valid_date(value):
    try:
        datetime.date(int(value[:4]),int(value[4:6]),int(value[6:8]))
        return True
    except ValueError:
        return False


def valid(kind, value, modern_rrn=False):
    digits = value.isascii() and value.isdigit()
    if kind=='us_ssn':
        return digits and len(value)==9 and value[:3] not in ('000','666') and value[0]!='9' and value[3:5]!='00' and value[5:]!='0000'
    if kind=='us_itin':
        return digits and len(value)==9 and value[0]=='9' and (50<=int(value[3:5])<=65 or 70<=int(value[3:5])<=88 or 90<=int(value[3:5])<=92 or 94<=int(value[3:5])<=99)
    if kind=='uk_nino':
        return len(value)==9 and value[0] in 'ABCEGHJKLMNOPRSTWXYZ' and value[1] in 'ABCEGHJKLMNPRSTWXYZ' and value[:2] not in ('BG','GB','KN','NK','NT','TN','ZZ') and value[2:8].isascii() and value[2:8].isdigit() and value[8] in 'ABCD'
    if kind=='in_pan':
        return len(value)==10 and all(c in string.ascii_uppercase for c in value[:5]+value[9:]) and value[3] in 'PCHABGJLFT' and value[5:9].isascii() and value[5:9].isdigit() and value[5:9]!='0000'
    if kind=='br_cnpj':
        return len(value)==14 and all(c in string.digits+string.ascii_uppercase for c in value[:12]) and value[12:].isascii() and value[12:].isdigit() and len(set(value))>1 and cnpj_digits(value[:12])==value[12:]
    if kind=='cn_resident_id':
        return len(value)==18 and value[:17].isascii() and value[:17].isdigit() and value[-1] in '0123456789X' and value[:2] in ('11','12','13','14','15','21','22','23','31','32','33','34','35','36','37','41','42','43','44','45','46','50','51','52','53','54','61','62','63','64','65','71','81','82') and valid_date(value[6:14]) and value[14:17]!='000' and china_digit(value[:17])==value[-1]
    if not digits:
        return False
    if kind=='uk_nhs':
        return len(value)==10 and len(set(value))>1 and nhs_digit(value[:9])==int(value[9])
    if kind=='in_aadhaar':
        return len(value)==12 and value[0] in '23456789' and len(set(value))>1 and verhoeff_valid(value)
    if kind=='br_cpf':
        return len(value)==11 and len(set(value))>1 and cpf_digits(value[:9])==value[9:]
    if kind=='ca_sin':
        return len(value)==9 and value[0] not in '08' and len(set(value))>1 and luhn_valid(value)
    if kind=='kr_rrn':
        century = {'9':'18','0':'18','1':'19','2':'19','3':'20','4':'20'}
        return len(value)==13 and value[6] in century and valid_date(century[value[6]]+value[:6]) and (modern_rrn or rrn_digit(value[:12])==value[12])
    raise ValueError(kind)


def generate_value(kind, rng, index):
    decimal = lambda size: ''.join(rng.choice(string.digits) for _ in range(size))
    while True:
        if kind=='us_ssn': value=decimal(9)
        elif kind=='us_itin': value='9'+decimal(8)
        elif kind=='uk_nino': value=''.join(rng.choice(string.ascii_uppercase) for _ in range(2))+decimal(6)+rng.choice('ABCD')
        elif kind=='uk_nhs':
            body=decimal(9);check=nhs_digit(body)
            if check==10: continue
            value=body+str(check)
        elif kind=='in_aadhaar':
            body=rng.choice('23456789')+decimal(10)
            value=next(body+str(c) for c in range(10) if verhoeff_valid(body+str(c)))
        elif kind=='in_pan': value=''.join(rng.choice(string.ascii_uppercase) for _ in range(3))+rng.choice('PCHABGJLFT')+rng.choice(string.ascii_uppercase)+f'{rng.randrange(1,10000):04d}'+rng.choice(string.ascii_uppercase)
        elif kind=='br_cpf':
            body=decimal(9);value=body+cpf_digits(body)
        elif kind=='br_cnpj':
            alphabet=string.digits if index%2==0 else string.digits+string.ascii_uppercase
            body=''.join(rng.choice(alphabet) for _ in range(12));value=body+cnpj_digits(body)
        elif kind=='cn_resident_id':
            date=datetime.date(1920,1,1)+datetime.timedelta(days=rng.randrange(36000))
            body=rng.choice(('110101','310101','440106','510104'))+date.strftime('%Y%m%d')+f'{rng.randrange(1,1000):03d}'
            value=body+china_digit(body)
        elif kind=='kr_rrn':
            date=datetime.date(1920,1,1)+datetime.timedelta(days=rng.randrange(36000))
            sex=rng.choice('12' if date.year<2000 else '34')
            body=date.strftime('%y%m%d')+sex+decimal(5);value=body+rrn_digit(body)
        elif kind=='ca_sin':
            body=rng.choice('12345679')+decimal(7)
            value=next(body+str(c) for c in range(10) if luhn_valid(body+str(c)))
        else: raise ValueError(kind)
        if valid(kind,value):return value

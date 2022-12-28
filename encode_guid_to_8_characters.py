import binascii
import uuid
import zlib
import mmh3
import fnvhash
import base64
import hashlib

def crc_encode(string):
    return binascii.crc32(string.encode())
def adler_encode(string):
    return zlib.adler32(string.encode())
def murur_hash(string):
    return mmh3.hash(string.encode())
def lsfr_encode(string):
    data = string.encode()
    lfsr = 0b11010101
    output = ""
    for b in data:
        lfsr ^= b
        lfsr >>= 1
        output += chr(lfsr & 0xff)
    return output[:8]
def fnv_encode(string):
    data = string.encode()
    fnv_hash = fnvhash.fnv1a_32(data)
    return fnv_hash

max_value_for_32_bit = 4294967295

def uhash_hash(string: str):
    n =  2 ** 48
    prime = 2 ** 64 - 1
    data = int.from_bytes(string.encode(), 'big')
    a = int.from_bytes(hashlib.sha256(data.to_bytes((data.bit_length() + 7) // 8, 'big')).digest(), 'big') % prime
    b = int.from_bytes(hashlib.sha256(a.to_bytes((a.bit_length() + 7) // 8, 'big')).digest(), 'big') % prime
    hash_value = ((a * data + b) % prime) % n
    hash_bytes = hash_value.to_bytes((hash_value.bit_length() + 7) // 8, 'big')
    return base64.b64encode(hash_bytes).decode()

def try_get_collision(function, iterations, function_name, salt = None):
    checksum_set = set()
    guid_set = set()
    with_salt = ""
    if salt != None:
        with_salt = " with salt"
    for i in range(iterations):
        
        guid = str(uuid.uuid4())
        if guid in guid_set:
            continue
        guid_set.add(guid)
        
        if salt != None:
            guid = guid + salt

        result = function(guid)

        if result in checksum_set:
            print(len(guid_set))
            print(function_name + " result is not unique" + with_salt)
            break

        if(i == iterations-1):
            print("Success with " + function_name + with_salt)

        checksum_set.add(result)

iterations = 1000000
salt = "NxiF1HcAFTR6wyo2BuZN"
try_get_collision(crc_encode, iterations, "crc-32")
try_get_collision(crc_encode, iterations, "crc-32", salt)
try_get_collision(adler_encode, iterations, "adler-32")
try_get_collision(adler_encode, iterations, "adler-32", salt)
try_get_collision(murur_hash, iterations, "murmurhash 3")
try_get_collision(murur_hash, iterations, "murmurhash 3", salt)
try_get_collision(lsfr_encode, iterations, "lsfr encoding")
try_get_collision(lsfr_encode, iterations, "lsfr encoding", salt)
try_get_collision(fnv_encode, iterations, "FNV-1a")
try_get_collision(fnv_encode, iterations, "FNV-1a", salt)
try_get_collision(uhash_hash, iterations, "Universal hash function")
#possible using universal hash function, but not any of the others
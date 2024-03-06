import os
import math
import hashlib
import struct
import binascii
import ctypes
from typing import Tuple, List
from bitcointx.core.secp256k1 import get_secp256k1
from bitcointx.core.key import CKey, CPubKey
secp_obj = get_secp256k1()
secp_obj.lib.secp256k1_ec_pubkey_tweak_mul.restype = ctypes.c_int
secp_obj.lib.secp256k1_ec_pubkey_tweak_mul.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
groupN  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

infty = "INFTY"

def bintohex(b):
    """Convert bytes to a hex string"""
    return binascii.hexlify(b).decode('utf8')

def getG(compressed: bool = True) -> CPubKey:
    """Returns the public key binary
    representation of secp256k1 G;
    note that CPubKey is of type bytes.
    """
    priv = b"\x00"*31 + b"\x01"
    k = CKey(priv, compressed=compressed)
    G = k.pub
    return G

def getNUMS(index=0):
    """Taking secp256k1's G as a seed,
    either in compressed or uncompressed form,
    append "index" as a byte, and append a second byte "counter"
    try to create a new NUMS base point from the sha256 of that
    bytestring. Loop counter and alternate compressed/uncompressed
    until finding a valid curve point. The first such point is
    considered as "the" NUMS base point alternative for this index value.

    The search process is of course deterministic/repeatable, so
    it's fine to just store a list of all the correct values for
    each index, but for transparency left in code for initialization
    by any user.
    
    The NUMS generator generated is returned as a secp256k1.PublicKey.
    """

    assert index in range(256)
    nums_point = None
    for G in [getG(True), getG(False)]:
        seed = G + struct.pack(b'B', index)
        for counter in range(256):
            seed_c = seed + struct.pack(b'B', counter)
            hashed_seed = hashlib.sha256(seed_c).digest()
            #Every x-coord on the curve has two y-values, encoded
            #in compressed form with 02/03 parity byte. We just
            #choose the former.
            claimed_point = b"\x02" + hashed_seed
            try:
                nums_point = CPubKey(claimed_point)
                # CPubKey does not throw ValueError or otherwise
                # on invalid initialization data; it must be inspected:
                assert nums_point.is_fullyvalid()
                return nums_point
            except:
                continue
    assert False, "It seems inconceivable, doesn't it?"  # pragma: no cover

def read_privkey(priv: bytes) -> Tuple[bool, bytes]:
    if len(priv) == 33:
        if priv[-1:] == b'\x01':
            compressed = True
        else:
            raise Exception("Invalid private key")
    elif len(priv) == 32:
        compressed = False
    else:
        raise Exception("Invalid private key")
    return (compressed, priv[:32])

def privkey_to_pubkey(priv: bytes) -> CPubKey:
    '''Take 32/33 byte raw private key as input.
    If 32 bytes, return as uncompressed raw public key.
    If 33 bytes and the final byte is 01, return
    compresse public key. Else throws Exception.'''
    compressed, priv = read_privkey(priv)
    # CKey checks for validity of key value;
    # any invalidity throws ValueError.
    newpriv = CKey(priv, compressed=compressed)
    return newpriv.pub

def add_pubkeys(pubkeys: List[bytes]) -> CPubKey:
    '''Input a list of binary compressed pubkeys
    and return their sum as a binary compressed pubkey.'''
    pubkey_list = [CPubKey(x) for x in pubkeys]
    if not all([x.is_compressed() for x in pubkey_list]):
        raise ValueError("Only compressed pubkeys can be added.")
    if not all([x.is_fullyvalid() for x in pubkey_list]):
        raise ValueError("Invalid pubkey format.")
    return CPubKey.combine(*pubkey_list)

def multiply(s: bytes, pub: bytes, return_serialized: bool = True) -> bytes:
    '''Input binary compressed pubkey P(33 bytes)
    and scalar s(32 bytes), return s*P.
    The return value is a binary compressed public key,
    or a PublicKey object if return_serialized is False.
    Note that the called function does the type checking
    of the scalar s.
    ('raw' options passed in)
    '''
    try:
        CKey(s)
    except ValueError:
        raise ValueError("Invalid tweak for libsecp256k1 "
                         "multiply: {}".format(bintohex(s)))

    pub_obj = CPubKey(pub)
    if not pub_obj.is_fullyvalid():
        raise ValueError("Invalid pubkey for multiply: {}".format(
            bintohex(pub)))

    privkey_arg = ctypes.c_char_p(s)
    pubkey_buf = pub_obj._to_ctypes_char_array()
    ret = secp_obj.lib.secp256k1_ec_pubkey_tweak_mul(
        secp_obj.ctx.verify, pubkey_buf, privkey_arg)
    if ret != 1:
        assert ret == 0
        raise ValueError('Multiplication failed')
    if not return_serialized:
        return CPubKey._from_ctypes_char_array(pubkey_buf)
    return bytes(CPubKey._from_ctypes_char_array(pubkey_buf))

# probably overkill, but just to encapsulate arithmetic in the group;
# this class handles the modular arithmetic of x and +.
class Scalar(object):
    def __init__(self, x):
        self.x = x % groupN
    def to_bytes(self):
        return int.to_bytes(self.x, 32, byteorder="big")
    @classmethod
    def from_bytes(cls, b):
        return cls(int.from_bytes(b, byteorder="big"))
    @classmethod
    def pow(cls, base, exponent):
        return cls(pow(base, exponent, groupN))
    def __add__(self, other):
        if isinstance(other, int):
            y = other
        elif isinstance(other, Scalar):
            y = other.x
        return Scalar((self.x + y) % groupN)
    def __radd__(self, other):
        return self.__add__(other)
    def __sub__(self, other):
        if isinstance(other, int):
            temp = other
        elif isinstance(other, Scalar):
            temp = other.x
        return Scalar((self.x - temp) % groupN)
    def __rsub__(self, other):
        if isinstance(other, int):
            temp = other
        elif isinstance(other, Scalar):
            temp = other.x
        else:
            assert False
        return Scalar((temp - self.x) % groupN)
    def __mul__(self, other):
        if other == 1:
            return self
        if other == 0:
            return Scalar(0)
        return Scalar((self.x * other.x) % groupN)
    def __rmul__(self, other):
        return self.__mul__(other)
    def __str__(self):
        return str(self.x)
    def __repr__(self):
        return str(self.x)
    def __len__(self):
        return len(str(self.x))

def binmult(a, b):
    """ Given two binary strings,
    return their multiplication as a binary string.
    """
    # optimisation for pre-mult with bits:
    if a == 0:
        return b"\x00"*32
    if a == 1:
        return b
    aint = Scalar.from_bytes(a)
    bint = Scalar.from_bytes(b)
    return (aint * bint).to_bytes()

def pointadd(points):
    # NB this is not correct as it does not account for cancellation;
    # not sure how a return is serialized as point at infinity in that case.
    # (but it doesn't happen in the uses in this module).
    pointstoadd = [x for x in points if x != infty]
    if len(pointstoadd) == 1:
        return pointstoadd[0]
    if len(pointstoadd) == 0:
        return infty
    return add_pubkeys(pointstoadd)

def pointmult(multiplier, point):
    # given a scalar 'multiplier' as a binary string,
    # and a pubkey 'point', returns multiplier*point
    # as another pubkey object
    if multiplier == 0:
        return infty
    if multiplier == 1:
        return point
    if int.from_bytes(multiplier, byteorder="big") == 0:
        return infty
    return multiply(multiplier, point, return_serialized=False)

def delta(a, b):
    # kronecker delta
    return 1 if a==b else 0

def poly_mult_lin(coeffs, a, b):
    """ Given a set of polynomial coefficients,
    in *decreasing* order of exponent from len(coeffs)-1 to 0,
    return the equivalent set of coeffs after multiplication
    by ax+b. Note a, b and all the returned elements are type Scalar.
    """
    coeffs_new = [Scalar(0) for _ in range(len(coeffs)+1)]
    coeffs_new[0] = a * coeffs[0]
    for i in range(1, len(coeffs_new)-1):
        coeffs_new[i] = b*coeffs[i-1] + a* coeffs[i]
    coeffs_new[-1] = b*coeffs[-1]
    return coeffs_new

def gen_rand(l=32):
    return os.urandom(l)

def gen_privkey_set(n, m):
    return (CKey(gen_rand(m), True) for _ in range(n))

# reuse NUMS points code from PoDLE
H = getNUMS(255)
J = getNUMS(254)

# the actual secp generator
G = getG(True)

def get_matrix_NUMS(n, m):
    # note that get_NUMS is currently limited to i*j < 256
    pts = []
    for i in range(n):
        inner_pts = []
        for j in range(m):
            inner_pts.append(getNUMS(i*m + j))
        pts.append(inner_pts)
    return pts

def nary_decomp(x, n, m):
    """ Given an integer x, a base n and an exponent m,
    return a digit representation of x in that base, padded
    out with zeros up to n^m-1.
    """
    if n == 0:
        return [0] * m
    digits = []
    while x:
        digits.append(int(x % n))
        x //= n
    return digits + [0] * (m - len(digits))

def hash_transcript(s):
    return hashlib.sha256(s).digest()

def get_bits_from_ring(ring):
    return math.ceil(math.log(len(ring), 2))

def hexer(x):
    if isinstance(x, Scalar):
        return bintohex(x.to_bytes())
    else:
        return bintohex(x)

def get_rev_bytes(hexstr, outfmt="bytes"):
    x = bytearray.fromhex(hexstr)
    x.reverse()
    y = bytes(x)
    if outfmt == "hex":
        return hexer(y)
    return y

def encode_le_4byte_num(num):
    return int(num).to_bytes(4, byteorder="little")

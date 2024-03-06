#!/usr/bin/env python

'''
Background:

https://github.com/AdamISZ/aut-ct/blob/master/aut-ct.pdf

This module is for auditing the Pedersen-DLEQ proof code
written in src/peddleq.rs in the aut-ct repo, by creating fixed
test cases.

Use a single command line argument `create` to re-create
the test cases.

Other argument values are for debugging and auditing
the detailed conversions.

'''

import sys
import json
from utils import *
from ctypes import *
from strobe import Strobe128
from hashlib import sha256
from binascii import unhexlify
from bitcointx.core.key import CPubKey

"""
Example output from STROBE debug for reference to the
structure of the challenge construction:

Initialize STROBE-128(4d65726c696e2076312e30)	# b"Merlin v1.0"
meta-AD : 646f6d2d736570 || LE32(13)	# b"dom-sep"
     AD : 7065642d646c65712d74657374	# b"ped-dleq-test"
meta-AD : 646f6d2d736570 || LE32(12)	# b"dom-sep"
     AD : 706564646c657170726f6f66	# b"peddleqproof"
meta-AD : 6e || LE32(8)	# b"n"
     AD : 0100000000000000	# b""
meta-AD : 31 || LE32(33)	# b"1"
     AD : 5a933d8d57ad60da8ba4bde44792f454c91a5c6e2a896c8deb07eacf65e7f88880
meta-AD : 32 || LE32(33)	# b"2"
     AD : b5b548526817477904e021c7bd79277e1151b7e826376053a48146a399e1177680
meta-AD : 33 || LE32(33)	# b"3"
     AD : 1a0e70108c8449dde28accbfb4bb66dadc17ab3d7f3a4da8fa3be41d16c15e8580
meta-AD : 34 || LE32(33)	# b"4"
     AD : 5a8ee8d48df141a8106c62bde53eef0954beec790b94a46ddd61b8540dbbd6bb80
meta-AD : 65 || LE32(64)	# b"e"
     PRF: adcc8fdeb0f57cb2a4ff98668fae2ce64fd851ea0174d257f0cb396efe192c9520bbe25c2e661b0432359176f6281241c9740818ccbc51daeeb53fadae103f28
"""
    
def append_message_to_strobe(strob, label, msg):
    strob.meta_ad(label, False)
    # process the `msg` field if a curve point, needs
    # to be in format used by ark:
    if isinstance(msg, CPubKey):
        newmsg = convert_to_ark_compressed(msg)
        assert len(newmsg) == 33
    else:
        newmsg = msg
    strob.meta_ad(encode_le_4byte_num(len(newmsg)), True)
    strob.ad(newmsg, False)

def pc(pt, randomness, Ha=None):
    """ Pedersen commitment to a point, without
    the value opening (so really, this is just a blinding
    operation).
    """
    if Ha is None:
        Ha = H
    pts = [pt]
    pts.append(pointmult(randomness, Ha))
    return pointadd(pts)

def key_image(privkey, Ja=None):
    if Ja is None:
        Ja = J
    return pointmult(privkey, Ja)

def get_setup_message(privkey, randomness=None, Ha=None, Ja=None):
    pt = pointmult(privkey, G)
    if randomness is None:
        randomness = gen_rand()
    if Ha is None:
        Ha = H
    if Ja is None:
        Ja = J
    pec = pc(pt, randomness, Ha)
    ki = key_image(privkey, Ja)
    return (pec, ki, randomness)

# These two functions allow sanity checks of the rather
# fiddly conversion between ark-ec's representation of
# compressed point (sign of y is the MSB of a last byte)
# with that used in old DER (*parity*, not sign, of
# y, is 2 or 3 as first byte).
def test_convert_unconvert():
    for _ in range(20):
        priv = os.urandom(32)
        test_convert_unconvert_inner(priv)

def test_convert_unconvert_inner(priv):
    pub = privkey_to_pubkey(priv+b"\x01")
    print("pub: ", hexer(pub))
    pub2 = convert_to_ark_compressed(pub)
    pub2x = pub2[:-1]
    pub2x2 = get_rev_bytes(hexer(pub2x))
    pub22 = pub2x2 + pub2[-1:]
    pub3 = convert_from_ark_compressed(pub22)
    print("pub2: ", hexer(pub2))
    print("pub3: ", hexer(pub3))
    assert bytes(pub3) == bytes(pub)

def convert_to_ark_compressed(pt):
    # points in ark are represented as compressed as:
    # 32 bytes + "00" for negative y
    # 32 bytes + "80" for positive y
    finalbyte = y_is_positive(pt)
    assert len(pt) == 33
    xonly = pt[1:]
    return get_rev_bytes(hexer(xonly)) + finalbyte

def convert_from_ark_compressed(ptbytes):
    # Arg must be: bytes, big endian x coord,
    # but ending with ark 1-byte sign flag.
    if bytes([ptbytes[-1]]) == b"\x00":
        pos = True
    elif bytes([ptbytes[-1]]) == b"\x80":
        pos = False
    else:
        assert False, "wrong format of ark compressed"
    # We choose one parity at random, and then check:
    pt1 = CPubKey(b"\x02" + ptbytes[:-1])
    # Note: _to_ctypes_char_array returns 64 byte string,
    # with x then y coord but LITTLE ENDIAN
    # Note: directly accessing serializedpt1.value fails
    # because strings are interpreted as null terminated
    # in ctypes, meaning we get incorrect truncated values.
    serializedpt1 = pt1._to_ctypes_char_array()
    address = cast(serializedpt1,c_void_p).value
    xandy = (c_char * 64).from_address(address).raw
    x = xandy[:32]
    y = xandy[32:]
    inty = int.from_bytes(y, byteorder="little")
    currentlypos = inty <= -inty % groupN
    if currentlypos == pos:
        tocheck = inty
    else:
        tocheck = -inty % groupN
    if tocheck % 2 == 1:
        return b"\x03" + get_rev_bytes(hexer(x))
    else:
        assert tocheck % 2 == 0
        return b"\x02" + get_rev_bytes(hexer(x))
    
def y_is_positive(pt):
    """ This parsing is needed to replicate
    the compression format used in ark_ec short weierstrass.
    
    Given a curve point object, inspect its y value.
    Note we have ignored infty.
    check whether y or -y is larger and return as
    "00" or "80"
    """
    serializedpt = pt._to_ctypes_char_array()
    # see note in `convert_from_ark_compressed`:
    address = cast(serializedpt, c_void_p).value
    xandy = (c_char * 64).from_address(address).raw
    y = xandy[32:]
    inty = int.from_bytes(y, byteorder="little")
    if inty <= groupN // 2:
        return b"\x00"
    return b"\x80"

def challenge_bytes(R1, R2, C, C2):
    """ This replicates exactly how the transcript,
    PRF challenge bytes are created in Merlin's implementation
    of STROBE, and using the labels applied in aut-ct codebase
    currently:
    """
    strob = Strobe128.new(b"Merlin v1.0")
    # TODO: dumb labels!
    append_message_to_strobe(strob, b"dom-sep", b"ped-dleq-test")
    append_message_to_strobe(strob, b"dom-sep", b"peddleqproof")
    append_message_to_strobe(strob, b"n", b"\x01" + b"\x00"*7)
    for i, pt in enumerate([R1, R2, C, C2]):
        append_message_to_strobe(strob, str(i+1).encode(), pt)
    strob.meta_ad(b"e", False)
    strob.meta_ad(encode_le_4byte_num(64), True)
    return strob.prf(64, False)
    
def get_challenge(R1, R2, pc, ki):
    """ Currently assuming first hashing will
    be successful which should be overwhelmingly likely.
    """
    cb = challenge_bytes(
        R1, R2, pc, ki)
    print("Got this from challenge_bytes: ", hexer(cb))
    cbsha = sha256(cb + bytes([0])).digest()
    print("Got this from sha256 hash with 0 counter: ", hexer(cbsha))
    return Scalar.from_bytes(cbsha)

def get_proof_message(privkey, randomness, pc, ki,
                      s=None, t=None, Ha=None, Ja=None):
    if Ha is None:
        Ha = H
    if Ja is None:
        Ja = J
    if s is None:
        s = gen_rand()
    if t is None:
        t = gen_rand()
    R1 = pointadd([pointmult(s, G), pointmult(t, Ha)])
    R2 = pointmult(s, Ja)
    x = get_challenge(R1, R2, pc, ki)
    sigma1 = Scalar.from_bytes(s) + x * Scalar.from_bytes(privkey)
    sigma2 = Scalar.from_bytes(t) + x * Scalar.from_bytes(randomness)
    return (R1, R2, sigma1.to_bytes(), sigma2.to_bytes())

def verify_proof_message(R1, R2, sigma1, sigma2, pc, ki, Ha=None, Ja=None):
    if Ha is None:
        Ha = H
    if Ja is None:
        Ja = J    
    x = get_challenge(R1, R2, pc, ki)
    assert pointadd([pointmult(sigma1, G),
                     pointmult(sigma2, Ha)]) == pointadd(
                    [R1, pointmult(x.to_bytes(), pc)])
    assert pointmult(sigma1, Ja) == pointadd(
        [R2, pointmult(x.to_bytes(), ki)])

def get_pt_from_ark_hex(hexstr):
    pthex_without_signbyte = hexstr[:-2]
    newpt_bytes_rev = get_rev_bytes(pthex_without_signbyte)
    revpt = newpt_bytes_rev + unhexlify(hexstr[-2:])
    return convert_from_ark_compressed(revpt)

def create_test_cases():
    # 4 "random" inputs to algo,
    # have them be fixed values spanning a byte:
    x_start, r_start, s_start, t_start = (64*x + 1 for x in range(4))
    # generator J is fixed in our Rust codebase; for H, we can stick
    # with the default created by the Curve Trees repo:    
    Hconverted = get_pt_from_ark_hex("87163d621f520cca22c42466af3b046475db26a1177166ba51eac76fc31dc35680")
    Jconverted = get_pt_from_ark_hex("b59adaae3dfb856a2869b29b0fa4b2ac31d27926e8b49150185e0224c9451c7980")
    # build 10 test cases:
    cases = []
    for i in range(10):
        priv, r, s, t = (bytes([q + i])*32 for q in (x_start, r_start, s_start, t_start))
        pc, ki, r = get_setup_message(priv, randomness=r,
                                      Ha=Hconverted, Ja=Jconverted)
        R1, R2, sigma1, sigma2 = get_proof_message(priv, r, pc, ki,
                            s, t, CPubKey(Hconverted), CPubKey(Jconverted))
        print("R1 is: ", hexer(convert_to_ark_compressed(R1)))
        print("R2 is: ", hexer(convert_to_ark_compressed(R2)))
        verify_proof_message(R1, R2, sigma1, sigma2, pc, ki, Ha=Hconverted, Ja=Jconverted)
        # output all elements to json;
        # we use formats convenient for the Rust codebase, which are:
        # ark-compressed for points and
        # little endian for 32 byte scalars
        casedict = {"case" : str(i),
                    "priv": hexer(priv),
                    "r": get_rev_bytes(hexer(r), "hex"),
                    "s": get_rev_bytes(hexer(s), "hex"),
                    "t": hexer(get_rev_bytes(hexer(t))),
                    "pc": hexer(convert_to_ark_compressed(pc)),
                    "ki": hexer(convert_to_ark_compressed(ki)),
                    "R1": hexer(convert_to_ark_compressed(R1)),
                    "R2": hexer(convert_to_ark_compressed(R2)),
                    "sigma1": get_rev_bytes(hexer(sigma1), "hex"),
                    "sigma2": get_rev_bytes(hexer(sigma2), "hex"),
                    "e": hexer(get_challenge(R1, R2, pc, ki).to_bytes())}
        cases.append(casedict)
    with open("testcases.json", "wb") as f:
        f.write(json.dumps(cases, indent=4).encode())
        

if __name__ == "__main__":
    """ Use argument `create` to re-create the test cases.
    Other argument values are for debugging and auditing
    the detailed conversions.
    """

    if sys.argv[1] == "create":
        create_test_cases()
        exit(0)



    if sys.argv[1] == "test":
        test_convert_unconvert()
        exit(0)

    # arguments for re-constructing a specific test case:
    # args: (prog) 1: x, 2: r, 3: s, 4: t, 5: H, 6: J
    if len(sys.argv[1]) == 1 and int(sys.argv[1]) == 0:
        privkey = gen_rand()
    elif len(sys.argv[1]) == 1:
        privkey = bytes([int(sys.argv[1])])*32
    else:
        privkey = get_rev_bytes(sys.argv[1])
    if len(sys.argv[2]) == 1 and int(sys.argv[2]) == 0:
        r = gen_rand()
    elif len(sys.argv[2]) == 1:
        r = bytes([int(sys.argv[2])])*32
    else:
        r = get_rev_bytes(sys.argv[2])
    if len(sys.argv[3]) == 1 and int(sys.argv[3]) == 0:
        s = gen_rand()
    elif len(sys.argv[3]) == 1:
        s = bytes([int(sys.argv[3])])*32
    else:
        s = get_rev_bytes(sys.argv[3])
    if len(sys.argv[4]) == 1 and int(sys.argv[4]) == 0:
        t = gen_rand()
    elif len(sys.argv[4]) == 1:
        t = bytes([int(sys.argv[4])])*32
    else:
        t = get_rev_bytes(sys.argv[4])
    # now input the generators H, J
    if len(sys.argv[5]) == 1:
        newH = H
    else:
        newHconverted = get_pt_from_ark_hex(sys.argv[5])
    if len(sys.argv[6]) == 1:
        newJ = J
    else:
        newJconverted = get_pt_from_ark_hex(sys.argv[6])
    print("Got new H: ", newHconverted)
    print("Got new J: ", newJconverted)
    print("Here is the starting privkey: ", hexer(privkey))
    pc, ki, r = get_setup_message(privkey, randomness=r,
                                  Ha=newHconverted, Ja=newJconverted)
    print("Setup created pc: ", hexer(pc))
    print("setup created ki: ", hexer(ki))
    print("Pc converted is: ", hexer(convert_to_ark_compressed(pc)))
    print("Ki converted is: ", hexer(convert_to_ark_compressed(ki)))
    R1, R2, sigma1, sigma2 = get_proof_message(privkey, r, pc, ki,
        s, t, CPubKey(newHconverted), CPubKey(newJconverted))
    print("R1 is: ", hexer(convert_to_ark_compressed(R1)))
    print("R2 is: ", hexer(convert_to_ark_compressed(R2)))
    verify_proof_message(R1, R2, sigma1, sigma2, pc, ki, Ha=newHconverted, Ja=newJconverted)


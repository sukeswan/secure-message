from ECDSA import hash,ECDSA,ECDSA_check,gen_Public_Key,nPoint,calculate_y
from Simon import ctr_simon
import copy
import sympy
import random
import requests

random.seed(234)

# macros
p = (2**521)-1
q = 6864797660130609714981900799081393217269435300143305409394463459185543183397655394245057746333217197532963996371363321113864768612440380340372808892707005449
# generator point on EC
P = (0xc6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66,0x11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650)

# for P-521 curve 
curve_a = -3
curve_b = 0x051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00
filename = "encoded.txt"

alice_next_stored = None

def writeAWS(filename): ## bucket taken down, enter your AWS bucket here
    data = {"key": filename}
    files = {"file": open(filename, "rb")}
    r = requests.post("INSERT AMAZON S3 BUCKER URL HERE", data=data, files=files)
    return r.status_code

def readAWS(filename): ## bucket taken down, enter your AWS bucket here
    url = "INSERT AMAZON S3 BUCKER URL HERE" + filename
    r = requests.get(url)
    return r.text

def xPoint(x,P):
    newPoint = nPoint(-3,p,P[0],P[1],x)
    return newPoint

def gen_keys():
    private_key = random.getrandbits(256)
    public_key = gen_Public_Key(P,private_key,p)
    return private_key,public_key

def signpad(dec_val,sign):
    input = bin(dec_val)[2:].zfill(521)
    if sign == 0:
        input = hex(int(input,2))[2:].zfill(132)
    else:
        input = "1" + input
        input.zfill(528)
        input = hex(int(input,2))[2:].zfill(132)

    return input

def un_signpad(dec_val):
    input = bin(dec_val)[2:].zfill(528)
    padding = int(input[0:6],2)
    sign = int(input[6],2)
    value = int(input[7:],2)

    return sign,value

def compress(point):
    x,y = point[0], point[1]
    bin_y = bin(y)[2:].zfill(528)

    if bin_y[0] == "1":
        sign = 1
    else:
        sign = 0
    
    compressed = signpad(x,sign)
    return compressed

def expand(padded_x):

    sign,x = un_signpad(padded_x)
    y = calculate_y(curve_a,curve_b,p,x)

    if sign == 0:
        return (x,y)
    else:
        return(x, (-1*y) % p)

def send_message(n,text,k,a,X,A_next):

    Ax = compress(A_next) 

    a_text = str(Ax) + text
    # hash string message for using sha3-512
    hashed_message = int(hash(a_text),16)
    print("Message in hex:       {}".format(text.encode("utf-8").hex()))
    print("A'x is                {}".format(Ax))
    print("Hashed A'x + message: {}".format(hex(hashed_message)))

    # sign message with ECDSA and check
    signature = ECDSA(n,p,q,P,a,hashed_message)

    # convert decimal signature to hex value
    signature = (hex(signature[0])[2:],hex(signature[1])[2:])
    # pad hex signature until its 66 bytes (or 132 hex digits)
    signature = ((signature[0]).zfill(132), (signature[1]).zfill(132))
    print("Padded Signature:     {}".format(signature))

    Xx = compress(X)
    
    #sig0 sig1
    final_input = str(signature[1]) + str(signature[0]) + str(Ax) + text.encode("utf-8").hex()
    print("R + S + A'x + message {}".format(final_input))

    encrypted = ctr_simon(final_input,k)
    print("The encrypted input:  {}".format(encrypted))

    print("The x-coor for X      {}".format(Xx))
    awsInput = Xx + encrypted
    print("Input to AWS          {}".format(awsInput)) 

    return awsInput

def get_message(n,input,b):
    global alice_next_stored
    A = alice_next_stored
    X = int(input[:132],16)

    print("A {}".format(hex(A)))
    print("X {}".format(hex(X)))

    A = expand(A)
    X = expand(X)

    print("Computed X y-coor:    {}".format(hex(X[1])))
    print("Computed A y-coor:    {}".format(hex(A[1])))

    bX = xPoint(b,X)
    k = hex(bX[0])[-64:]

    input = input[132:]
    input = ctr_simon(input,k)

    print("The decrypted input:  {}".format(input))
    r = input[:132]          # r is first 66 bytes
    s = input[132:264]       # s is next 66 bytes
    Ax_next = input[264:396] # A'x is next 66 bytes
    message = input[396:]    # message is after r and s

    print("R is:                 {}".format(r))
    print("S is:                 {}\n".format(s))
    print("Current A is:         ({}, {})".format(hex(A[0]),hex(A[1])))
    print("A'x sign + pad is:    {}\n".format(Ax_next))
    print("Message is:           {}".format(message))
    
    # convert hex message to ascii so can be hashed using sha3-512 
    hashed_message = int(hash(str(Ax_next) + bytearray.fromhex(message).decode()),16)
    print("Hashed A'x + message: {}".format(hex(hashed_message)))

    signature = (int(s,16),int(r,16))

    sign_check = ECDSA_check(signature,p,q,P,A,hashed_message)
    print("ECDSA check:          {}\n".format(sign_check))

    # set the next key pulled by Bob
    Ax_next = int(Ax_next,16)
    alice_next_stored = Ax_next
    return

def main(message, alice_private, alice_public):
    global alice_next_stored
    n = random.getrandbits(521) # ephemeral

    # privates keys = 256 bits public keys = points 
    bob_private   , bob_public   = gen_keys()
    transit_x     , transit_X    = gen_keys()

    alice_pri_next, alice_pub_next = gen_keys()  # the next keys that alice will use

    if alice_next_stored == None: # initialize A for bob
        alice_next_stored = int(compress(alice_public),16)

    print("Ephemeral Key: {}\n".format(hex(n)))

    print("________________ Alice's Keys _________________")
    print("Private: {}".format(hex(alice_private)))
    print("Public:  ({}, {})\n".format(hex(alice_public[0]),hex(alice_public[1])))

    print("_____________ Alice's Next Keys _______________")
    print("Private: {}".format(hex(alice_pri_next)))
    print("Public:  ({}, {})\n".format(hex(alice_pub_next[0]),hex(alice_pub_next[1])))

    print("________________ Bob's Keys _________________")
    print("Private: {}".format(hex(bob_private)))
    print("Public:  ({}, {})\n".format(hex(bob_public[0]),hex(bob_public[1])))

    print("________________ Transit (x,X) Keys _________________")
    print("Private: {}".format(transit_x))
    print("Public:  ({}, {})\n".format(hex(transit_X[0]),hex(transit_X[1])))

    # same values k but both calculated as sanity check
    
    xB = xPoint(transit_x,bob_public)  # k
    bX = xPoint(bob_private,transit_X) # k

    # key is bottom 64 bytes of x coordinate of k
    simon_key = hex(xB[0])[-64:]
    print("____________________ SANITY CHECKS ______________________")
    print("Does xB equal bX? {}".format(xB==bX))
    print("The simon key is: {}\n".format(simon_key))

    print("________________ SENDING MESSAGE TO AWS _________________\n")

    final_input = send_message(n,message,simon_key,alice_private,transit_X,alice_pub_next)
    f = open(filename, "w")
    f.write(final_input)
    f.close()
    code = writeAWS(filename)
    print("HTTP Status from AWS: {}\n".format(code))

    print("________________ GETTING MESSAGE FROM AWS _________________\n")

    text = readAWS(filename)
    print("Text pulled from AWS: {}".format(text))
    get_message(n,text,bob_private)
    return alice_pri_next, alice_pub_next

# initialize keys for main function
alice_private , alice_public = gen_keys()

# main returns keys for next time
print("_______________________ MESSAGE 1 INFO ________________________\n")
alice_pri_next, alice_pub_next = main("It's working!!!", alice_private,alice_public)

# use returned keys for next call 
print("_______________________ MESSAGE 2 INFO ________________________\n")
alice_pri_next, alice_pub_next = main("Hopefully this works again", alice_pri_next,alice_pub_next)

print("_______________________ MESSAGE 3 INFO ________________________\n")
alice_pri_next, alice_pub_next = main("No harm in triple checking this stuff", alice_pri_next,alice_pub_next)
from sha3_512 import textToHex, SHA3_512, bytesToHex
import copy
import sympy

def calculate_y(a,b,p,x):
    y2 = (pow(x,3) + a*x + b) % p
    y = pow(y2, (p + 1) // 4, p) 
    return y


def nPoint(a,p,x,y,d):

    d = bin(d)[3:]
        
    P = (x,y)
    T = (x,y)

    for bit in d:
        T = double_add(T,T,p,a)
        if bit == "1":
            T = double_add(T,P,p,a) 
    return T

def double_add(p_a,p_b,p,a):
    
    (x1,y1) = copy.deepcopy(p_a)
    (x2,y2) = copy.deepcopy(p_b)

    if p_a == p_b:
        s = ((3 * pow(x1,2) + a) * (pow(2 * y1, -1, p))) % p
    else:
        if x2==x1:
            return (float('inf'),float('inf'))
        s = ((y2 - y1) * pow((x2 - x1),-1,p)) % p
    
    if(x1 == float('inf')):
        return (x2,y2)
    if(x2 == float('inf')):
        return (x1,y1)
    
    x3 = (pow(s,2) - x1 - x2) % p
    y3 = (s * (x1 - x3) - y1) % p
    return (x3,y3)

def hash(text):
    input = textToHex(text)
    ans = SHA3_512(input)
    final_ans = bytesToHex(ans)
    return final_ans

def gen_Public_Key(generator,private,modulus):
    public_key = nPoint(-3,modulus,int(generator[0]),int(generator[1]),private)
    return public_key

def ECDSA(n,p,q,P,x,message):

    R = nPoint(-3,p,int(P[0]),int(P[1]),n)

    # Generate ECDSA Signature
    xr_q = (x * R[0]) % q
    n_inv = pow(n,-1,q)
    s = ((message + xr_q) * n_inv) % q
    signature = (s,R[0])
    return signature

def ECDSA_check(signature,p,q,P,X,message):
    (s,r) = signature
    # Signature Verification
    w = pow(s,-1,q)
    u1 = (w * message) % q
    u2 = (w * r) % q
    V = double_add(nPoint(-3,p,int(P[0]),int(P[1]),u1), nPoint(-3,p,int(X[0]),int(X[1]),u2),p,-3)
    sign_check = ((V[0]%q)==(r%q))
    return sign_check
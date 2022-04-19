import copy
AND = "AND"

z4 = [1,1,0,1,0,0,0,1,1,1,1,0,0,1,1,0,1,0,1,1,0,1,1,0,0,0,1,0,0,0,0,0,0,1,0,1,1,1,0,0,0,0,1,1,0,0,1,0,1,0,0,1,0,0,1,1,1,0,1,1,1,1]

# convert hex value to binary list 
def hex_to_binary(input,size):
    binary_input = bin(int(input,16))[2:].zfill(size)
    binary_list = list(map(int,str(binary_input)))
    return binary_list

# convert binary list to hex
def binary_to_hex(input):
    decimal_input = int("".join(str(i) for i in input),2)
    hex_value = hex(decimal_input)[2:]
    return hex_value

# shift left multiple times
def shift_left(input, times):
    result = copy.deepcopy(input)
    for i in range(times):
        newTail = result.pop(0)
        result.append(newTail)
    return result

#shift right function for genrating keys
def shift_right(input,times):
    result = copy.deepcopy(input)
    for i in range(times):
        newHead = result.pop()
        result.insert(0,newHead)
    return result

# split binary list into left and right
def split(input):
    half = len(input)//2
    left = input[:half]
    right = input[half:]
    return left,right

# combine left and right binary lists
def combine(left,right):
    return left + right

# return list of xor-ed bits in input lists
def bit_xor(one,two):
    result = []
    for i in range(len(one)):
        result.append(one[i] ^ two[i])
    return result

# return list of and-ed bits in input lists
def bit_and(one,two):
    result = []
    for i in range(len(one)):
        result.append(one[i] & two[i])
    return result

# invert the bits in k for key expansion 
def invert(input):
    result = copy.deepcopy(input)
    for i in range(len(result)):
        if result[i]==1:
            result[i]=0
        elif result[i]==0:
            result[i]=1
    return result 

# rounds for Simon
def round(left,right,key):
    left_shift_1 = shift_left(left,1)
    left_shift_2 = shift_left(left,2)
    left_shift_8 = shift_left(left,8)

    fx_res = bit_and(left_shift_1,left_shift_8)

    xor_1 = bit_xor(right,fx_res)
    xor_2 = bit_xor(xor_1,left_shift_2)
    xor_3 = bit_xor(xor_2,key)
    
    result_left = xor_3
    result_right  = left
    return result_left,result_right

def simon(binary_plain_text,sub_keys):
    left,right = split(binary_plain_text)
    for i in range(72):
        left,right = round(left,right,sub_keys[i])
    return combine(left,right)

# decrypt by switching left and right in final rounds
def simon_d(binary_plain_text,sub_keys):
    right,left = split(binary_plain_text)
    for i in range(72):
        left,right = round(left,right,sub_keys[i])
    return combine(right,left)

#generate subkeys
def generate_keys(key):
    high_order,low_order = split(key)
    k3,k2 = split(high_order)
    k1,k0 = split(low_order)

    sub_keys = [k0,k1,k2,k3]

    for i in range(4,72):
        temp = shift_right(sub_keys[i-1],3)
        temp = bit_xor(temp,sub_keys[i-3])
        temp = bit_xor(temp,shift_right(temp,1))
        
        invert_kim = invert(sub_keys[i-4])
        temp = bit_xor(invert_kim,temp)
        
        z_bit = z4[((i-4) % 62)]            # xor 3 (11) with the two last bits in the key
        temp[-1] = temp[-1] ^ z_bit ^ 1
        temp[-2] = temp[-2] ^ 1
        sub_keys.append(temp)
    
    return sub_keys

def encrypt(text,key):

    binary_key = hex_to_binary(key,256)
    sub_keys = generate_keys(binary_key)
    # Encryption of Test Vector
    binary_plain_text = hex_to_binary(text,128)
    binary_cipher_text = simon(binary_plain_text,sub_keys)
    final_encrypt = binary_to_hex(binary_cipher_text)
    return final_encrypt

def decrypt(text,key):
    binary_key = hex_to_binary(key,256)
    sub_keys = generate_keys(binary_key)
    # Decryption of Test Vector
    sub_keys.reverse()
    binary_cipher_text = hex_to_binary(text,128)
    binary_plain_text = simon_d(binary_cipher_text,sub_keys)
    final_decrypt = binary_to_hex(binary_plain_text)
    return final_decrypt

def block_list(text):
    # if there is only a single block of data return single element list
    if len(text) <= 32:
        text = text.zfill(32)
        blocks = [text]
        return blocks
    
    # figure out how much to pad by 
    size = len(text)
    extra = size % 32
    padding = (32 - extra) % 32
    # pad the text with zeros 
    padded_text = text.zfill(size + padding)

    # split padded text into 128 bits or 32 block hext values
    n = 32
    blocks = [padded_text[i:i+n] for i in range(0, len(padded_text), n)]

    blocks[0] = blocks[0][padding:]
    return blocks

def gen_key_streams(key,length,first_length):
    keys = []
    for i in range(1,length+1):
        k = encrypt(hex(i),key)
        keys.append(k)

    # remove the extra keystream for the MSB block
    keys[0] = keys[0][-1*first_length:]
    return keys

def ctr_simon(ciphertext,key):
    blocks = block_list(ciphertext)
    #print("Blocks are {}".format(blocks))
    cipher = ""
    block_lens = []
    key_stream = gen_key_streams(key,len(blocks),len(blocks[0]))   
    for i in range(len(blocks)):
        new_block = int(key_stream[i],16) ^ int(blocks[i],16)
        if i==0:
            new_block = (str(hex(new_block)[2:]))
        else:
            new_block = (str(hex(new_block)[2:]).zfill(32))
        block_lens.append(len(new_block))
        cipher = cipher + new_block
    #print(block_lens)
    return cipher.zfill(len(ciphertext))



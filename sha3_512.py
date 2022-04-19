BLOCK_SIZE = 576
BUS_SIZE = 1600
HEIGHT = 5
WIDTH = 5
DEPTH = 64
ROUNDS = 24
BYTE_SIZE = 8

def textToHex(input): # convert text input into a list of hex bytes 
    result = [int(hex(ord(i)),16) for i in input]
    return result

def bytesToHex(input): # convert hashed hex bytes to a single 512 bit hex value
    result = ''.join('{:02x}'.format(x) for x in input)
    return result

def ROL64(a, n): #helper function for math functions
    return ((a >> (64-(n%64))) + (a << (n%64))) % (1 << 64)

def f_rounds(lanes): # 24 rounds of 5 math functions on 5 x 5 x 64 bit matrix
    R = 1
    for round in range(ROUNDS):

        # θ function
        C = [lanes[x][0] ^ lanes[x][1] ^ lanes[x][2] ^ lanes[x][3] ^ lanes[x][4] for x in range(5)]
        D = [C[(x+4)%5] ^ ROL64(C[(x+1)%5], 1) for x in range(5)]
        lanes = [[lanes[x][y]^D[x] for y in range(5)] for x in range(5)]

        # ρ and π functions
        (x, y) = (1, 0)
        current = lanes[x][y]
        for t in range(ROUNDS):
            (x, y) = (y, (2*x+3*y)%5)
            (current, lanes[x][y]) = (lanes[x][y], ROL64(current, (t+1)*(t+2)//2))

        # χ function
        for y in range(5):
            T = [lanes[x][y] for x in range(5)]
            for x in range(5):
                lanes[x][y] = T[x] ^((~T[(x+1)%5]) & T[(x+2)%5])

        # ι function
        for j in range(7):
            R = ((R << 1) ^ ((R >> 7)*0x71)) % 256
            if (R & 2):
                lanes[0][0] = lanes[0][0] ^ (1 << ((1<<j)-1))
    return lanes

def load64(b): # load 64 lanes into 5x5 matrix 
    return sum((b[i] << (BYTE_SIZE*i)) for i in range(BYTE_SIZE))

def store64(a): # store 64 lanes back into state
    return list((a >> (8*i)) % 256 for i in range(8))

def f_function(state):
    lanes = [[load64(state[BYTE_SIZE*(x+5*y):BYTE_SIZE*(x+5*y)+BYTE_SIZE]) for y in range(HEIGHT)] for x in range(WIDTH)] # load lanes into 5x5
    lanes = f_rounds(lanes) # run 24 rounds on the lanes
    state = bytearray(BUS_SIZE//BYTE_SIZE)  # make new state and populate with updated lanes
    for x in range(5):
        for y in range(5):
            state[BYTE_SIZE*(x+5*y):BYTE_SIZE*(x+5*y)+BYTE_SIZE] = store64(lanes[x][y])
    return state

# Keccack is main function which takes input blocks, pads, and then "squeezes out hash"
def SHA3_512(inputBytes):
    
    outputBytes = bytearray()
    state = bytearray([0 for i in range(BUS_SIZE//BYTE_SIZE)]) # the state will be at most 1600 bits or 200 bytes
    rateInBytes = BLOCK_SIZE//BYTE_SIZE
    blockSize = 0

    inputOffset = 0
    # === Absorb all the input blocks
    while(inputOffset < len(inputBytes)):   # keep absorbing all bytes

        blockSize = min(len(inputBytes)-inputOffset, rateInBytes)

        for i in range(blockSize):                            # add all the bytes to the state byte array 
            state[i] = state[i] ^ inputBytes[i+inputOffset]   # new blocks will be xored with perviously computed blocks

        inputOffset = inputOffset + blockSize

        if (blockSize == rateInBytes):                        # if block fills up               
            state = f_function(state)                         # run f function and reset block 
            blockSize = 0

    # === Do the padding and switch to the squeezing phase
    state[blockSize] = state[blockSize] ^ 0x06               # Pad the final block and run the f function on it  
    state[rateInBytes-1] = state[rateInBytes-1] ^ 0x80
    state = f_function(state)

    # === Squeeze out all the output blocks === 
    blockSize = DEPTH
    outputBytes = outputBytes + state[0:blockSize]
    return outputBytes

# def main():

#     plainText = input("\nEnter a message to hash using SHA3-512: ")
#     hexInput = textToHex(plainText)
#     hashedBytes = SHA3_512(hexInput)
#     ans = bytesToHex(hashedBytes)
#     print("\nThe hashed message is {}\n".format(ans))

# if __name__ == "__main__":
#     main()

# inputBytes = [0x00,0x00,0x00,0x00]
# hashedBytes = SHA3_512(inputBytes)
# ans = bytesToHex(hashedBytes)
# print("\nThe hashed message is {}\n".format(ans))

    
# input = textToHex("hello")
# ans = SHA3_512(input)
# final_ans = bytesToHex(ans)
# check = "75d527c368f2efe848ecf6b073a36767800805e9eef2b1857d5f984f036eb6df891d75f72d9b154518c1cd58835286d1da9a38deba3de98b5a53e5ed78a84976"
# print(final_ans == check)
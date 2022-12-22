

SBOX = [
    [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76],
    [0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0],
    [0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15],
    [0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75],
    [0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84],
    [0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF],
    [0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8],
    [0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2],
    [0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73],
    [0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB],
    [0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79],
    [0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08],
    [0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A],
    [0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E],
    [0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF],
    [0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]
]
SBOX_INV = [
    [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb],
    [0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb],
    [0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e],
    [0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25],
    [0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92],
    [0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84],
    [0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06],
    [0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b],
    [0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73],
    [0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e],
    [0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b],
    [0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4],
    [0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f],
    [0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef],
    [0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61],
    [0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d]
]
RCON = [
    [0x01, 0x00, 0x00, 0x00],
    [0x02, 0x00, 0x00, 0x00],
    [0x04, 0x00, 0x00, 0x00],
    [0x08, 0x00, 0x00, 0x00],
    [0x10, 0x00, 0x00, 0x00],
    [0x20, 0x00, 0x00, 0x00],
    [0x40, 0x00, 0x00, 0x00],
    [0x80, 0x00, 0x00, 0x00],
    [0x1B, 0x00, 0x00, 0x00],
    [0x36, 0x00, 0x00, 0x00]
]

# STandard Matrix for mix column
MIX_COL = [
    [0x02, 0x03, 0x01, 0x01],
    [0x01, 0x02, 0x03, 0x01],
    [0x01, 0x01, 0x02, 0x03],
    [0x03, 0x01, 0x01, 0x02]
]
MIX_COL_INV = [
    [0x0E, 0x0B, 0x0D, 0x09],
    [0x09, 0x0E, 0x0B, 0x0D],
    [0x0D, 0x09, 0x0E, 0x0B],
    [0x0B, 0x0D, 0x09, 0x0E]
]
# A function g which rotates, substitutes and Xors with RCON value on a word
def g(word,round):
    result = []
    # rotating 1 pair left
    word = word[2:] + word[:2] 
    # Substitutinng values from Sbox and xor with rcon
    res = hex(SBOX[int(word[0],16)][int(word[1],16)] ^ RCON[round][0])
    if len(res) == 3:
        result.append('0x0')
        result.append("0x"+res[2])
    else:
        result.append('0x'+res[2])
        result.append("0x"+res[3])
    
    res = hex(SBOX[int(word[2],16)][int(word[3],16)] ^ RCON[round][1])
    if len(res) == 3:
        result.append('0x0')
        result.append("0x"+res[2])
    else:
        result.append('0x'+res[2])
        result.append("0x"+res[3])
    
    res = hex(SBOX[int(word[4],16)][int(word[5],16)] ^ RCON[round][2])
    if len(res) == 3:
        result.append('0x0')
        result.append("0x"+res[2])
    else:
        result.append('0x'+res[2])
        result.append("0x"+res[3])
    
    res = hex(SBOX[int(word[6],16)][int(word[7],16)] ^ RCON[round][3])
    if len(res) == 3:
        result.append('0x0')
        result.append("0x"+res[2])
    else:
        result.append('0x'+res[2])
        result.append("0x"+res[3])
    
    # print("Printing the result of G Function : ",result)
    return result

#  Function for key expansion
def KeyExpansion(word_list,round):
    new_words = []
    # Xor g(w3) with w0 = w4
    res = g(word_list[3],round)
    temp = []
    for i in range(8):
        temp.append(hex(int(res[i],16)^int(word_list[0][i],16)))
    new_words.append(temp)
    # Xor w4 with w1 = w5
    temp = []
    for i in range(8):
        temp.append(hex(int(new_words[0][i],16)^int(word_list[1][i],16)))
    new_words.append(temp)
    # Xor w5 with w2 = w6
    temp = []
    for i in range(8):
        temp.append(hex(int(new_words[1][i],16)^int(word_list[2][i],16)))
    new_words.append(temp)
    # Xor w6 with w3 = w7
    temp = []
    for i in range(8):
        temp.append(hex(int(new_words[2][i],16)^int(word_list[3][i],16)))
    new_words.append(temp)
    return new_words
# Covert the matrix to 4*4 from 4*8
def textto4(text):
#  Making the text matrix as 4*4
    text4 = [[0,0,0,0],
            [0,0,0,0],
            [0,0,0,0],
            [0,0,0,0]]
    for i in range(4):
        k = 0
        for j in range(0,8,2):
            text4[i][k] = "0x"+text[i][j][2]+text[i][j+1][2]
            k+=1
    return text4
# Convert the matrix to 4*8 from hex values in 4*4
def textto8_hex(text):
    text8 = [[0,0,0,0,0,0,0,0],
            [0,0,0,0,0,0,0,0],
            [0,0,0,0,0,0,0,0],
            [0,0,0,0,0,0,0,0]]
    # Converting the resulting matrix back to 4*8 and hex
    for i in range(4):
        k = 0
        for j in range(4):
            res = text[i][j]
            if len(res) == 3:
                x = '0x0'
                y = "0x"+res[2]
            else:
                x = '0x'+res[2]
                y = "0x"+res[3]
            text8[i][k] = x
            text8[i][k+1] = y
            k+=2
    return text8    
# Convert the matrix to 4*8 from integer values in 4*4
def textto8(text):
    text8 = [[0,0,0,0,0,0,0,0],
            [0,0,0,0,0,0,0,0],
            [0,0,0,0,0,0,0,0],
            [0,0,0,0,0,0,0,0]]
    # Converting the resulting matrix back to 4*8 and hex
    for i in range(4):
        k = 0
        for j in range(4):
            res = hex(text[i][j])
            if len(res) == 3:
                x = '0x0'
                y = "0x"+res[2]
            else:
                x = '0x'+res[2]
                y = "0x"+res[3]
            text8[i][k] = x
            text8[i][k+1] = y
            k+=2
    return text8
# Gallios Field Implementation
def GF(val1,val2):
    # Convert integer to a binary value
    bin_val1 = str(bin(val1))[2:].zfill(8)
    bin_val2 = str(bin(val2))[2:].zfill(8)
    # Irreducible_polinomial
    irp = int("00011011", 2)
    # Setting the values of fx and gx where gx is the smaller value
    if val1 < val2:
        gx = bin_val1
        fx = bin_val2
    else:
        gx = bin_val2
        fx = bin_val1
    # print(fx)
    # print(gx)
    values = []
    for bit in reversed(gx):
        if bit == "1":
            values.append(fx)
        carrybit = fx[0]
        fx = fx[1:]+"0"
        if carrybit == "1":
            fx = int(fx,2) ^ irp
            fx = str(bin(fx))[2:].zfill(8)
    result = 0
    for value in values:
        result ^= int(value,2)
    return result
# function to shift rows
def Shift_Rows(text):
    text4 = textto4(text)
    text4 = [list(x) for x in zip(*text4)]
    text8 = textto8_hex(text4)
    # rotating 1 pair left
    text8[1] = text8[1][2:] + text8[1][:2]
    # rotating 2 pair left
    text8[2] = text8[2][4:] + text8[2][:4]
    # rotating 3 pair left
    text8[3] = text8[3][6:] + text8[3][:6]
    res = textto4(text8)
    res = [list(x) for x in zip(*res)]

    return textto8_hex(res)
# function to shift rows in inverse
def Shift_Rows_inv(text):
    text4 = textto4(text)
    text4 = [list(x) for x in zip(*text4)]
    text8 = textto8_hex(text4)
    # rotating 1 pair right
    text8[1] = text8[1][6:] + text8[1][:6]
    # rotating 2 pair right
    text8[2] = text8[2][4:] + text8[2][:4]
    # rotating 3 pair right
    text8[3] = text8[3][2:] + text8[3][:2]
    res = textto4(text8)
    res = [list(x) for x in zip(*res)]

    return textto8_hex(res)

# Function to add roundkey
def Add_Round_Key(PT,KT):
    res = []
    for i in range(4):
        temp = []
        for j in range(8):
            temp.append(hex(int(PT[i][j],16)^int(KT[i][j],16)))
        res.append(temp)
    return res
# Function for sub bytes
def Sub_bytes(text):
    result = []
    for i in range(4):
        temp = []
        for j in range(0,8,2):
            res = hex(SBOX[int(text[i][j],16)][int(text[i][j+1],16)])
            if len(res) == 3:
                temp.append('0x0')
                temp.append("0x"+res[2])
            else:
                temp.append('0x'+res[2])
                temp.append("0x"+res[3])
        result.append(temp)
    return result  
# Function for sub bytes in inverse
def Sub_bytes_inv(text):
    result = []
    for i in range(4):
        temp = []
        for j in range(0,8,2):
            res = hex(SBOX_INV[int(text[i][j],16)][int(text[i][j+1],16)])
            if len(res) == 3:
                temp.append('0x0')
                temp.append("0x"+res[2])
            else:
                temp.append('0x'+res[2])
                temp.append("0x"+res[3])
        result.append(temp)
    return result  

# Function to implement mix column
def MixColumn(text):
    result = [[0,0,0,0],
              [0,0,0,0],
              [0,0,0,0],
              [0,0,0,0]]
    #  Making the text matrix as 4*4
    text4 = textto4(text)
    text4 = [list(x) for x in zip(*text4)]
    # print(text4)
    # Matrix Multiplication using Galois Field
    for i in range(4):
        for j in range(4):
            for k in range(4):
                result[i][j] ^= GF(MIX_COL[i][k],int(text4[k][j],16))
    result = [list(x) for x in zip(*result)]
    return textto8(result)

# Function to implement mix column in inverse
def MixColumn_Inv(text):
    result = [[0,0,0,0],
              [0,0,0,0],
              [0,0,0,0],
              [0,0,0,0]]
    #  Making the text matrix as 4*4
    text4 = textto4(text)
    text4 = [list(x) for x in zip(*text4)]
    # print(text4)
    # Matrix Multiplication using Galois Field
    for i in range(4):
        for j in range(4):
            for k in range(4):
                result[i][j] ^= GF(MIX_COL_INV[i][k],int(text4[k][j],16))
    result = [list(x) for x in zip(*result)]
    return textto8(result)


# *******************************************************************
# Main Function for Decryption
def AES_Decryption():
    # A list for storing words
    words = []

    # reading the plaintext from plaintext.pt file and storing it in a matrix
    f1 = open("encryptedData.enc","r")
    enc_string=f1.read()
    lis = []
    # Convert string to list
    lis[:0] = enc_string
    # Converting list into matrix
    enc_matrix = []
    for i in range(4):
        enc_matrix.append([hex(int(lis[i],16)) for i in range(i*8,i*8+8)])
    # reading the key from Key.key file and storing it in a matrix
    f2 = open("Key.key","r")
    key_string = f2.read() 
    # Convert string to list
    lis[:0] = key_string
    # Converting list into matrix
    key_matrix = []
    for i in range(4):
        key_matrix.append([hex(int(lis[i],16)) for i in range(i*8,i*8+8)])
        words.append([hex(int(lis[i],16)) for i in range(i*8,i*8+8)])
    print("===========================================================")
    print("====================Encrypted Matrix=======================")
    print(enc_matrix)
    print("===========================================================")
    print("=====================Key Matrix============================")
    print(key_matrix)
    print("===========================================================")
    
    # Expanding Keys for every round
    expanded_keys = []
    expanded_keys.append(words)
    for i in range(10):
        expanded_keys.append(KeyExpansion(expanded_keys[i],i))
    print(expanded_keys)

    # First Addition of plaintext and round key before round1
    text = Add_Round_Key(enc_matrix,expanded_keys[10])
    print(text)
    print("===========================================================")
    print("Starting Rounds")
    # Round 1-10
    print("===========================================================")
    for i in reversed(range(0,10)):
        print("Round : ", i)
        print("===========================================================")
        print("=================Shift Rows========================")
        text = Shift_Rows_inv(text)
        print(text)
        print("===================Sub Bytes======================")
        text = Sub_bytes_inv(text)
        print(text)
        print("======================Add Round Key=================")
        text = Add_Round_Key(text,expanded_keys[i])
        print(text)
        if i != 0: # no mix column for last round
            text = MixColumn_Inv(text)
        # text = MixColumn(text)
        print("====================Mix Column=====================")
        print(text)
        print("===========================================================")

    f = open("decryptedData.dec", "w")
    # Converting the matrix to a string
    res = ""
    for i in range(4):
        for j in range(8):
            res += text[i][j][2]
    f.write(res)
    f.close()
    return
    # Function which performs AES Encryption
def AES_Encryption():
    # A list for storing words
    words = []

    # reading the plaintext from plaintext.pt file and storing it in a matrix
    f1 = open("plaintext.pt","r")
    plain_string=f1.read()
    lis = []
    # Convert string to list
    lis[:0] = plain_string
    # Converting list into matrix
    plain_matrix = []
    for i in range(4):
        plain_matrix.append([hex(int(lis[i],16)) for i in range(i*8,i*8+8)])
    # reading the key from Key.key file and storing it in a matrix
    f2 = open("Key.key","r")
    key_string = f2.read() 
    # Convert string to list
    lis[:0] = key_string
    # Converting list into matrix
    key_matrix = []
    for i in range(4):
        key_matrix.append([hex(int(lis[i],16)) for i in range(i*8,i*8+8)])
        words.append([hex(int(lis[i],16)) for i in range(i*8,i*8+8)])
    print("===========================================================")
    print("====================Plaintext Matrix=======================")
    print(plain_matrix)
    print("===========================================================")
    print("=====================Key Matrix============================")
    print(key_matrix)
    print("===========================================================")
    
    # Expanding Keys for every round
    expanded_keys = []
    expanded_keys.append(words)
    for i in range(10):
        expanded_keys.append(KeyExpansion(expanded_keys[i],i))
    print(expanded_keys)

    # First Addition of plaintext and round key before round1
    text = Add_Round_Key(plain_matrix,words)
    print("===========================================================")
    print("Starting Rounds")
    # Round 1-10
    print("===========================================================")
    for i in range(1,11):
        print("Round : ", i)
        print("===========================================================")
        text = Sub_bytes(text)
        print("===================Sub Bytes======================")
        print(text)
        text = Shift_Rows(text)
        print("=================Shift Rows========================")
        print(text)
        if i != 10: # no mix column for round 10
            text = MixColumn(text)
        # text = MixColumn(text)
        print("====================Mix Column=====================")
        print(text)
        text = Add_Round_Key(text,expanded_keys[i])
        print("======================Add Round Key=================")
        print(text)
        print("===========================================================")

    f = open("encryptedData.enc", "w")
    # Converting the matrix to a string
    res = ""
    for i in range(4):
        for j in range(8):
            res += text[i][j][2]
    f.write(res)
    f.close()
    return

#  Function call for encryption of data
AES_Encryption()
AES_Decryption()
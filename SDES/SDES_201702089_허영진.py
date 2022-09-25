#!/usr/bin/env python
# coding: utf-8

# In[1]:


# Simplified DES (Data Encryption Standard) 
# S-DES Algorithm Template Code for CNU Information Security 2022

# This code requires "bitarray" package.
# Install with: pip install bitarray

from ctypes import ArgumentError
import re
from bitarray import bitarray, util as ba_util

# Initial Permutation (IP)
IP = [ 1, 5, 2, 0, 3, 7, 4, 6 ] #평문 -> 재배치

# Inverse of Initial Permutation (or Final Permutation)
IP_1 = [ 3, 0, 2, 4, 6, 1, 7, 5]

# Expansion (4bits -> 8bits)
EP = [ 3, 0, 1, 2, 1, 2, 3, 0 ]

# SBox (S0)
S0 = [
    [ 1, 0, 3, 2 ],
    [ 3, 2, 1, 0 ],
    [ 0, 2, 1, 3 ],
    [ 3, 1, 3, 2 ]
]

# SBox (S1)
S1 = [
    [ 0, 1, 2, 3 ],
    [ 2, 0, 1, 3 ],
    [ 3, 0, 1, 0 ],
    [ 2, 1, 0, 3 ]
]

# Permutation (P4)
P4 = [ 1, 3, 2, 0 ]

# Permutation (P10)
P10 = [ 2, 4, 1, 6, 3, 9, 0, 8, 7, 5 ]

# Permutation (P8)
P8 = [ 5, 2, 6, 3, 7, 4, 9, 8 ]

#### DES Start

MODE_ENCRYPT = 1
MODE_DECRYPT = 2

'''
schedule_keys: generate round keys for round function
returns array of round keys.
keep in mind that total rounds of S-DES is 2.
'''
def schedule_keys(key: bitarray) -> list[bitarray]:#라운드 키 생성
    round_keys = []
    permuted_key = bitarray()

    for i in P10: #[2,4,1,6,3,9,0,8,7,5]
        permuted_key.append(key[i]) #P10에 따라 key 섞음

    permuted_key_left = permuted_key[0:5] #선택된 키 반으로 자르기 [2,4,1,6,3]
    permuted_key_right = permuted_key[5:10] #[9,0,8,7,5]

    for i in range(1, 3): #1,2
        # shift for each round
        # round 1: shift 1, round 2: shift 2
        # shifting will be accumulated for each rounds
        permuted_key_left = permuted_key_left[i:] + permuted_key_left[0:i] #shift to left
        permuted_key_right = permuted_key_right[i:] + permuted_key_right[0:i]

        # merge and permutate with P8
        merge_permutation = permuted_key_left + permuted_key_right #Shift 후 합치기
        round_key = bitarray()

        for j in P8:#[5, 2, 6, 3, 7, 4, 9, 8]
            round_key.append(merge_permutation[j]) #round_key에 합친 결과 넣기

        round_keys.append(round_key)

    return round_keys

'''
round: round function
returns the output of round function
'''

#라운드 함수: 입력을 반으로 쪼개 번갈아가면서 투입
#라운드마다 키가 변함
def round(text: bitarray, round_key: bitarray) -> bitarray: #매개변수로 입력값과 라운드키 필요
    # implement round function
    expanded = bitarray() #선언
    for i in EP: #[3, 0, 1, 2, 1, 2, 3, 0]
        expanded.append(text[i])
    expanded ^= round_key #expanded에 round_key와 XOR 한 결과 저장

    # S0 
    s0_row = expanded[0:4]
    s0_sel_row = (s0_row[0] << 1) + s0_row[3] 
    s0_sel_col = (s0_row[1] << 1) + s0_row[2]
    s0_result = ba_util.int2ba(S0[s0_sel_row][s0_sel_col], length=2)

    # S1
    s1_row = expanded[4:8]
    s1_sel_row = (s1_row[0] << 1) + s1_row[3]
    s1_sel_col = (s1_row[1] << 1) + s1_row[2]
    s1_result = ba_util.int2ba(S1[s1_sel_row][s1_sel_col], length=2)

    pre_perm4 = s0_result + s1_result #합치기
    
    result = bitarray()#결과를 bitarray로 선언
    for i in P4:
        result.append(pre_perm4[i])#집어넣기

    return result #결과물은 4비트

'''
sdes: encrypts/decrypts plaintext or ciphertext.
mode determines that this function do encryption or decryption.
     MODE_ENCRYPT or MODE_DECRYPT available.
'''
def sdes(text: bitarray, key: bitarray, mode) -> bitarray:
    result = bitarray()
    
    # Place your own implementation of S-DES Here
    
    # IP [ 1, 5, 2, 0, 3, 7, 4, 6 ]를 이용해 재배치
    term_res = bitarray()
    for i in IP:
        term_res.append(text[i])
    
    # IP결과 둘로 쪼갬
    term_left = term_res[0:4]
    term_right = term_res[4:8]
    
    
    #First
    #term_right를 round함수에 집어넣음
    if mode == 1:
        term_left ^= round(term_right, schedule_keys(key)[0]) #round 함수 결과물과 left XOR
    else:
        term_left ^= round(term_right, schedule_keys(key)[1])
    

    #SW
    term = term_left + term_right
    
    #Second
    term_left = term[4:8] #Switch left and right
    term_right = term[0:4]
    
    if mode == 1:
        term_left ^= round(term_right, schedule_keys(key)[1]) # 4bit, 8bit
    else:
        term_left ^= round(term_right, schedule_keys(key)[0])

    finish_second = bitarray()
    finish_second = term_left + term_right
    
    #IP_1
    for i in IP_1:
        result.append(finish_second[i])
    
    return result


#### DES Sample Program Start
plaintext = input("[*] Input Plaintext in Binary (8bits): ")
key = input("[*] Input Key in Binary (10bits): ")

# Plaintext must be 8 bits and Key must be 10 bits.
if len(plaintext) != 8 or len(key) != 10: #입력 bit가 다를 경우 에러 발생
    raise ArgumentError("Input Length Error!!!")

if re.search("[^01]", plaintext) or re.search("[^01]", key):
    raise ArgumentError("Inputs must be in binary!!!")

bits_plaintext = bitarray(plaintext)#입력받은 값들 bitarray로 저장
bits_key = bitarray(key)

print(f"Plaintext: {bits_plaintext}")
print(f"Key: {bits_key}")

result_encrypt = sdes(bits_plaintext, bits_key, MODE_ENCRYPT)

print(f"Encrypted: {result_encrypt}")

result_decrypt = sdes(result_encrypt, bits_key, MODE_DECRYPT)

print(f"Decrypted: {result_decrypt}, Expected: {bits_plaintext}")

if result_decrypt != bits_plaintext:
    print(f"S-DES FAILED...")
else:
    print(f"S-DES SUCCESS!!!")


# In[ ]:





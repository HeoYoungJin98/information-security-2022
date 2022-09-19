#!/usr/bin/env python
# coding: utf-8

# In[31]:


# Enigma Template Code for CNU Information Security 2022
# Resources from https://www.cryptomuseum.com/crypto/enigma

# This Enigma code implements Enigma I, which is utilized by 
# Wehrmacht and Luftwaffe, Nazi Germany. 
# This version of Enigma does not contain wheel settings, skipped for
# adjusting difficulty of the assignment.

from copy import deepcopy
from ctypes import ArgumentError

# Enigma Components
ETW = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

WHEELS = {
    "I" : {
        "wire": "EKMFLGDQVZNTOWYHXUSPAIBRCJ",
        "turn": 16 #홈이 파인 알파벳의 위치
    },
    "II": {
        "wire": "AJDKSIRUXBLHWTMCQGZNPYFVOE",
        "turn": 4
    },
    "III": {
        "wire": "BDFHJLCPRTXVZNYEIWGAKMUSQO",
        "turn": 21
    }
}

UKW = {
    "A": "EJMZALYXVBWFCRQUONTSPIKHGD",
    "B": "YRUHQSLDPXNGOKMIEBFZCWVJAT",
    "C": "FVPJIAOYEDRZXWGCTKUQSBNMHL"
}# Reflector

# Enigma Settings
SETTINGS = {
    "UKW": None,
    "WHEELS": [],
    "WHEEL_POS": [],
    "ETW": ETW,
    "PLUGBOARD": []
}

def apply_settings(ukw, wheel, wheel_pos, plugboard):
    if not ukw in UKW: #Reflector
        raise ArgumentError(f"UKW {ukw} does not exist!") #잘못된 입력 알림
    SETTINGS["UKW"] = UKW[ukw] #SETTINGS의 UKW를 입력한 값으로 설정

    wheels = wheel.split(' ')
    for wh in wheels: #Selected Wheel
        if not wh in WHEELS:
            raise ArgumentError(f"WHEEL {wh} does not exist!")
        SETTINGS["WHEELS"].append(WHEELS[wh]) #SETTINGS의 WHEELS에 입력

    wheel_poses = wheel_pos.split(' ') #Wheel 첫 시작 위치
    for wp in wheel_poses:
        if not wp in ETW:
            raise ArgumentError(f"WHEEL position must be in A-Z!")
        SETTINGS["WHEEL_POS"].append(ord(wp) - ord('A')) #시작 위치의 숫자화
    
    plugboard_setup = plugboard.split(' ') #플러그
    for ps in plugboard_setup:
        if not len(ps) == 2 or not ps.isupper():
            raise ArgumentError(f"Each plugboard setting must be sized in 2 and caplitalized; {ps} is invalid")
        SETTINGS["PLUGBOARD"].append(ps)

# Enigma Logics Start

# Plugboard
def pass_plugboard(input): #input 값은 변경할 값 ex) HELLO
    for plug in SETTINGS["PLUGBOARD"]: #설정된 plugboard 내의 문자 ex) HD
        if str.startswith(plug, input): #H일경우
            return plug[1] #D 리턴
        elif str.endswith(plug, input): #D일경우
            return plug[0] #H 리턴

    return input #변환된 문자열 리턴

# ETW
def pass_etw(input):
    return SETTINGS["ETW"][ord(input) - ord('A')]

# Wheels
def pass_wheels(input, reverse = False): #input is one letter
    # Implement Wheel Logics
    # Keep in mind that reflected signals pass wheels in reverse order
    loc = SETTINGS["ETW"].find(input) #find input index in ETW
    first = second = third = None
    if reverse == False: #before reflect
        first = SETTINGS["WHEEL_POS"][0] #first wheel position
        second = SETTINGS["WHEEL_POS"][1] #second wheel position
        third = SETTINGS["WHEEL_POS"][2] #third wheel position
    elif reverse == True: #reflected
        first = SETTINGS["WHEEL_POS"][2]
        second = SETTINGS["WHEEL_POS"][1]
        third = SETTINGS["WHEEL_POS"][0]  
        
    loc = (loc+first)%26 #wheel position만큼 돌아간 wheel에서 input에 매칭된 index번호
    first_change = SETTINGS["WHEELS"][0]["wire"][loc] #해당 번호의 character로 변경
    loc = (loc+second)%26
    second_change = SETTINGS["WHEELS"][1]["wire"][loc]
    third = SETTINGS["WHEEL_POS"][2] #third wheel position
    loc = (loc+third)%26
    third_change = SETTINGS["WHEELS"][2]["wire"][loc]
    input = third_change
    return input

# UKW
def pass_ukw(input):
    return SETTINGS["UKW"][ord(input) - ord('A')]

# Wheel Rotation
def rotate_wheels(): #Position에 저장된 순서에 따라 각 Wheel의 trun이 몇 번째에 있는지 확인하고, 해당 위치에 도달했을 때 다음 것 회전
    # Implement Wheel Rotation Logics
    first_index = SETTINGS["WHEELS"][0]["turn"] #셋팅된 각 WHEEL들의 홈 위치
    secon_index = SETTINGS["WHEELS"][1]["turn"]
    third_index = SETTINGS["WHEELS"][2]["turn"]
    
    #첫 번째 휠이 홈에 닿았고, 두 번째는 닿지 않았을 때 두 번째 휠만 회전
    if first_index == SETTINGS["WHEEL_POS"][0] and second_index != SETTINGS["WHEEL_POS"][1]:
        SETTINGS["WHEEL_POS"][1] = SETTINGS["WHEEL_POS"][1]+1
    elif first_index == SETTINGS["WHEEL_POS"][0] and second_index == SETTINGS["WHEEL_POS"][1]:
        SETTINGS["WHEEL_POS"][1] = SETTINGS["WHEEL_POS"][1]+1 #두 번째 휠 회전
        SETTINGS["WHEEL_POS"][2] = SETTINGS["WHEEL_POS"][2]+1 #세 번째 휠 회전
    
    #첫 번째 휠 1회 회전
    SETTINGS["WHEEL_POS"][0] = SETTINGS["WHEEL_POS"][0]+1
    
    pass

# Enigma Exec Start
plaintext = input("Plaintext to Encode: ")
ukw_select = input("Set Reflector (A, B, C): ")
wheel_select = input("Set Wheel Sequence L->R (I, II, III): ")
wheel_pos_select = input("Set Wheel Position L->R (A~Z): ") #휠의 시작 위치
plugboard_setup = input("Plugboard Setup: ")

apply_settings(ukw_select, wheel_select, wheel_pos_select, plugboard_setup)

for ch in plaintext:
    rotate_wheels()

    encoded_ch = ch

    encoded_ch = pass_plugboard(encoded_ch) #plug 지나감
    encoded_ch = pass_etw(encoded_ch) #ETW 지나감
    encoded_ch = pass_wheels(encoded_ch) #Wheel 지나감. 3번 바뀜
    encoded_ch = pass_ukw(encoded_ch) #Reflector 지나감. 1번 바뀜
    encoded_ch = pass_wheels(encoded_ch, reverse = True) #Wheel 지나감
    encoded_ch = pass_plugboard(encoded_ch) #plug 지나감

    print(encoded_ch, end='')


# In[ ]:





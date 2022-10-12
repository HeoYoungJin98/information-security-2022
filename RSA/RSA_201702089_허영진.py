#!/usr/bin/env python
# coding: utf-8

# In[2]:


pip install BigNumber mpmath


# In[31]:


# BigNumber, mpmath package required
# run this before execute: pip install BigNumber mpmath

import random
from BigNumber import BigNumber


#make prime number list in range [x,y]
# https://www.delftstack.com/howto/python/python-generate-prime-number/
def primesInRange(x, y):
    prime_list = []
    for n in range(x, y):
        isPrime = True

        for num in range(2, n):
            if n % num == 0:
                isPrime = False

        if isPrime:
            prime_list.append(n)
            
    return prime_list

def make_keys(p: BigNumber, q: BigNumber):
    # place your own implementation of make_keys
    # use e = 65537 as if FIPS standard
    n = p * q;
    temp = (p-1) * (q-1);
    e = 0;
    d = 1;
    i = 0;
    
    # e < (p-1) * (q-1)
    if temp > 65537:
        e = 65537;
    else:
        e = 3;

    while(1):
        if (e * d) % temp == 1:
            break
        else:
            d = d + 1;
            
    return [e, d, n]

def rsa_encrypt(plain: BigNumber, e: BigNumber, n: BigNumber):
    # place your own implementation of rsa_encrypt
    
    # c = m^e mod n
    result = (plain ** e) % n;
    
    return result

def rsa_decrypt(cipher: BigNumber, d: BigNumber, n: BigNumber):
    # place your own implementation of rsa_decrypt
    
    # m = c ^ d mod N
    result = (cipher ** d) % n;
    
    return result

primes = primesInRange(100, 1000) #return prime number list in range [100,1000]

P = primes[random.randrange(0, len(primes))] #over 0 under len, random prime number
Q = primes[random.randrange(0, len(primes))]

while P == Q:
    P = primes[random.randrange(0, len(primes))]
    Q = primes[random.randrange(0, len(primes))]

M = random.randrange(2, 20) # 2~20 random number
e, d, N = make_keys(P, Q)
C = rsa_encrypt(M, e, N)
M2 = rsa_decrypt(C, d, N)

print(f"P = {P}, Q = {Q}, N = {N}, M = {M}, e = {e}, d = {d}, C = {C}, M2 = {M2}")

if M == M2:
    print("RSA Success!!")
else:
    print("RSA Failed...")


# In[ ]:





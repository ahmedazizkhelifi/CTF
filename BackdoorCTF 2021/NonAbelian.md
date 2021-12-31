# BackdoorCTF 2021 – NonAbelian

# Table of contents

<!--ts-->

- [BackdoorCTF 2021 – NonAbelian](#backdoorctf-2021--nonabelian)
- [Table of contents](#table-of-contents)
  - [Challenge details](#challenge-details)
    - [Details](#details)
    - [Description](#description)
  - [TL;DR](#tldr)
  - [Given](#given)
    - [Explanation:](#explanation)
  - [Solution](#solution)
    - [Step 1: Get the string from the bits list](#step-1-get-the-string-from-the-bits-list)
    - [Step 2: Write a function to decrypt the flag](#step-2-write-a-function-to-decrypt-the-flag)
    - [Step 3: Load the encrypted flag](#step-3-load-the-encrypted-flag)
    - [Step 4: Decrypt the flag](#step-4-decrypt-the-flag)
  - [References](#references)

<!--te-->

## Challenge details

### Details

- Category: crypto - misc
- Points: 500

### Description

Non-abelian group based cryptography has become a latest trend in research (I wonder why?!), and I just had to try my hands on it.

## TL;DR

- You'll need [**SageMath**](https://www.sagemath.org) to solve this challenge.
- You can use the online tool [**CoCalc**](https://cocalc.com), which allows you to use the SageMath kernel in a Jupyter notebook.
- This challenge is essentially **algebra**, I will explain the vocabulary used as we go along, and we will need these two simple rules to keep in mind:
  1. **det(M<sup>-1</sup>) = [det(M)]<sup>-1</sup>**
  2. **det(AB) = det(A) x det(B)**

![img-meme](./assets/meme.png)

## Given

1. `chall.sage`:

   ```python
   import numpy as np

    FLAG = b"flag{r3aL_FLA9_r3DaCT3d}"

    def bytes_to_bits(_bytes):
        str_bits = ''.join([bin(int(_byte))[2:].zfill(8) for _byte in _bytes])
        int_bits = [int(bit) for bit in str_bits]
        return int_bits

    def get_random_non_singular_matrix(N):
        A = random_matrix(ZZ, N)
        while A.det() == 0:
            A = random_matrix(ZZ, N)
        return A

    def matrix_encrypt(pt):
        P = random_matrix(ZZ, 32, algorithm='unimodular')
        Pinv = matrix(ZZ, P.inverse())

        bits = bytes_to_bits(pt)
        ct = []
        for bit in bits:
            G = get_random_non_singular_matrix(32)
            H = get_random_non_singular_matrix(32)
            if bit:
                H = Pinv * G * P
            ct.append((H, G))
        return ct

    enc = matrix_encrypt(FLAG)
    np.save('out.npy', enc)
   ```

2. `out.npy`:  
   The encrypter flag.

### Explanation:

1. function `bytes_to_bits`:  
    This function takes bytes as argument, and returns a list which contains its binary equivalent.

   ```python
   >>> bytes_to_bits(FLAG)
   [0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1]
   ```

2. function `get_random_non_singular_matrix`:  
   As its name indicates, this function generates a **singular matrix** of _dimension N_. _A matrix is singular if its determinant is 0[<sup> [1]</sup>](#references)_.

3. function `matrix_encrypt`:  
   This is the function you need to understand to reverse it and decipher the flag.

   - We generate `P` a **unimodular matrix**. _A unimodular matrix M is a square integer matrix having determinant +1 or −1. [<sup> [2]</sup>](#references)_, and `Pinv` which is its inverse matrix.
   - Then we generate the list of the binary equivalent of the argument (which is the flag).
   - Then we loop on this list, if the element is 0 then we add to the return list a tuple of two non-singular matrices otherwise, we add a tuple which contains the matrix `Pinv * G * P` and any singular matrix.

4. `np.save`:  
   This method turns our list into a numpy array and saves it in a bynary file `out.npy`.

## Solution

To decrypt the flag, we have to check if the determinants of the given tuple are equal or not. Indeed, the matrix P, and its inverse, are unimodular, so their determinant is ±1. While the determinant of G is arbitrary. So the determinant of `H = Pinv * G * P` is equal to the determinant of `G`.

### Step 1: Get the string from the bits list

Write a function to return a string from the bit list.

```python
def int_bits_to_str(int_bits):
    """
    return ascii string from the list of bits.
    """
    # This inner function helps us to divide the list of bits sub-lists (because each byte is written on 8bits 😉 ).
    def splitAt(w,n):
        for i in range(0,len(w),n):
            yield w[i:i+n]

    # We turn the list into a string
    str_bits = "".join([str(bit) for bit in int_bits])
    # We generate a list that contains every single 8bits
    _bytes = " ".join(splitAt(str_bits,8)).split()

    ascii_string = ""
    for _byte in _bytes:
        ascii_string += chr(int(_byte, 2))
    return ascii_string
```

```python
>>> int_bits = bytes_to_bits(FLAG)
>>> int_bits_to_str(int_bits)
'flag{r3aL_FLA9_r3DaCT3d}'
```

### Step 2: Write a function to decrypt the flag

Now we have to code the solution we proposed.

```python
def decode(arr):
    # We turn the numpy array into a list
    arr = arr.tolist()
    L = []
    # Then we iterate over the list arr, generate the matrices H and G, and compute their determinant, finally we check our condition and fill the list.
    for _t in arr:
        det_H = matrix(ZZ,_t[0]).det()
        det_G = matrix(ZZ,_t[1]).det()
        if (det_H == det_G):
            L.append(1)
        else:
            L.append(0)
    return L
```

### Step 3: Load the encrypted flag

To load the encrypted flag, which is saved with the method `np.save`, we should call the `np.load`, but receives this error: `ValueError: Object arrays cannot be loaded when allow_pickle=False`. After a quick Google search, I found a solution[<sup> [3]</sup>](#references). We'll need to write a function:

```python
def loading(file_name):
    np_load_old = np.load
    np.load = lambda *a,**k: np_load_old(*a, allow_pickle=True, **k)
    flag_enc = np.load(f'{file_name}.npy')
    np.load = np_load_old
    return flag_enc
```

### Step 4: Decrypt the flag

> **Note**: Since Backdoor is an always-online CTF platform, and not a one time contest, I'll not load the real encoded flag[<sup> [4]</sup>](#references).

```python
>>> arr = loading('out1') # Load the flag into arr (numpy.array)
>>> L = decode(arr) # Get the list of bits
>>> int_bits_to_str(L) # Print the flag
'flag{tH17_15_N07_7h3_R43L_FL4g}'
```

## References

1. https://en.wikipedia.org/wiki/Unimodular_matrix
2. https://mathworld.wolfram.com/SingularMatrix.html
3. https://stackoverflow.com/questions/55890813/how-to-fix-object-arrays-cannot-be-loaded-when-allow-pickle-false-for-imdb-loa/56062555
4. https://backdoor.sdslabs.co/about#writeup-guide

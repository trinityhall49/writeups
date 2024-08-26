# TL;DR

This reverse engineering exercise is a challenge-response problem. The challenge is a sudoku puzzle that expects a solution with certain squares substituted. The python code is obfuscated by pickle bytecode that has python bytecode embedded in it. It abuses the `REDUCE` pickle bytecode to call pythonic functions.  I solved this challenge by researching how pickle works under the hood and instrumenting the pickle.py library file manually.

# First Impressions

This is the start of the challenge:

```
Magnum-Opus
----------------------
I've always felt obfuscated pickles was a fantastic way to run code...

Author: Legoclones

❖ Note
Challenge uses the most up-to-date version of python:3.11.9 in Docker.

```
Right ahead I installed python3.11 and tried running the challenge:
```
$ python3.11 magnum_opus.py
Woah woah woah, are you trying to reverse me?
```

Interesting, so there is some anti-reversing mechanism in the code, so I proceeded to look at the python script.

# Pythons and Pickles

The python script consist of one very long pickle bytestring. I wrote the bytestring into a file and started looking up ways to analyze it. Working as a python developer a few years ago, I know that pickle is a common serialization framework, but nothing more in-depth. During my research, I learned that the pickle framework is in fact a virtual machine. The pickle binary is supposedly bytecodes to the VM. The virtual machine is stack-based with no jumps. This case is more interesting because we actually ended up executing code somehow. It has to at least run `print("Woah woah woah, are you trying to reverse me?
")`. So how would a VM execute python code? 

Some more research revealed that there is a `REDUCE` opcode that would call pythonic functions (Side note: this is also one of the ways that pickles can be exploited to run arbitrary code). This is an interesting find! What if I can intercept this opcode to figure out all the function calls!

So that's exactly what I did -- I looked at the local pickle.py file installed along with python.11 and looked for the function that executes the reduce opcode. It looks like this:

```
$ sudo vim /usr/lib/python3.11/pickle.py 
    ... 
    def load_reduce(self):
        stack = self.stack
        args = stack.pop()
        func = stack[-1]
        stack[-1] = func(*args)
    dispatch[REDUCE[0]] = load_reduce
    ...

```
OK, so I should print out `func` and `args`, and call it a day, right? If only it's so easy! I could not see anything getting print out -- it didn't crash, it didn't halt, it didn't do anything! But why? I searched through the file, and landed on this spot:

```
$ sudo vim /usr/lib/python3.11/pickle.py
...
# Use the faster _pickle if possible
try:
   from _pickle import (
         PickleError,
        PicklingError,
        UnpicklingError,
        Pickler,
        Unpickler,
        dump,
        dumps,
        load,
        loads
    )
except ImportError:
    Pickler, Unpickler = _Pickler, _Unpickler
    dump, dumps, load, loads = _dump, _dumps, _load, _loads
...
```
OK... what probably happened was that, there are some other "compiled" version of pickle that is optimized, and python tries to use these versions first before falling back on the `pickle.py` script. So I removed the import line, and then the script started running and crashing. 

```
$ python3.11 magnum-opus.py
  <built-in function chr> (116,)
  <built-in function getattr> ('', 'join')
  <built-in method join of str object at 0xa6f200> (['i', 'n', 'f'],)
  <class 'float'> ('inf',)
  ...
  <built-in method join of str object at 0xa6f200> ([],)
  <built-in method join of str object at 0xa751b0> (['', '', 'import', '', ''],)
  <built-in function getattr> ('_', 'join')
  <built-in function getattr> ('', 'join')
  <built-in method join of str object at 0xa6f200> ([],)
  <built-in function getattr> ('', 'join')
  <built-in method join of str object at 0xa6f200> (['e', 'x', 'i', 't'],)
  <built-in method join of str object at 0xa751b0> (['', 'exit'],)
  ...
  <class 'code'> (0, 0, 0, 3, 4, 3, b'\x97\x00\t\x00d\x01d\x00l\x00}\x00d\x01d\x02l\x01m\x02}\x01m\x03}\x02\x01\x00d\x00S\x00#\x00\x01\x00t\t\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00d\x03\xa6\x01\x00\x00\xab\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00t\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00d\x04\xa6\x01\x00\x00\xab\x01\x00\x00\x00\x00\x00\x00\x00\x00\xa0\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00d\x05\xa6\x01\x00\x00\xab\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00Y\x00d\x00S\x00x\x03Y\x00w\x01', (None, 0, ('long_to_bytes', 'bytes_to_long'), 'Woah woah woah, are you trying to reverse me?', 'os', 1), ('sudokum', 'Crypto.Util.number', 'long_to_bytes', 'bytes_to_long', 'print', '__import__', '_exit'), ('', '', ''), '', '', '', 1, b'\x80\x00\xf0\x02\x05\x05"\xd8\x08\x16\x88\x0e\x88\x0e\x88\x0e\xd8\x08C\xd0\x08C\xd0\x08C\xd0\x08C\xd0\x08C\xd0\x08C\xd0\x08C\xd0\x08C\xd0\x08C\xd0\x08C\xf8\xf0\x02\x02\x05"\xdd\x08\r\xd0\x0e=\xd1\x08>\xd4\x08>\xd0\x08>\xdd\x08\x12\x904\xd1\x08\x18\xd4\x08\x18\xd7\x08\x1e\xd2\x08\x1e\x98q\xd1\x08!\xd4\x08!\xd0\x08!\xd0\x08!\xd0\x08!\xd0\x08!\xf8\xf8\xf8', b'\x82\x0c\x10\x00\x903A\x06\x03', (), ())
  File "/usr/lib/python3.11/pickle.py", line 1786, in _loads
    encoding=encoding, errors=errors).load()
                                      ^^^^^^
  File "/usr/lib/python3.11/pickle.py", line 1213, in load
    dispatch[key[0]](self)
  File "/usr/lib/python3.11/pickle.py", line 1601, in load_reduce
    stack[-1] = func(*args)
                ^^^^^^^^^^^
ValueError: code: co_nlocals != len(co_varnames)
```
The first part shows that python functions are being called stealthily! The `REDUCE` opcode is used to call python functions, and the most common one calle is the `join()` function, which is used to string together single characters to form more pythonic functions and keywords , such as `import` and `exit()` But why did it crash at the end? What are `co_nlocals` and `co_varnames`? Turns out, they're variables of `CodeObject`, a python type that lets us executes python bytecode directly. But why did it crash? Honestly, I am not sure, I ended up trying to force `co_nlocals` to be `len(co_varnames)` using the following hack:
```
$ sudo vim /usr/lib/python3.11/pickle.py 
    ... 
    def load_reduce(self):
        stack = self.stack
        args = stack.pop()
        func = stack[-1]
        print(func, args)
        if (len(args) == 18 and args[3] == 0):
            args2 = ()
            for i in range(18):
                if (i == 3):
                    args2 += (args[5],)
                else:
                    args2 += (args[i],) 
            args = args2
        print(func, args)
        stack[-1] = func(*args)
    dispatch[REDUCE[0]] = load_reduce
    ...
```
After that, I started playing around with the last function before it crashed.

```
$ python3.11
>>> from types import CodeObject
>>> import dis 
>>> c = CodeObject (0, 0, 0, 3, 4, 3, b'\x97\x00\t\x00d\x01d\x00l\x00}\x00d\x01d\x02l\x01m\x02}\x01m\x03}\x02\x01\x00d\x00S\x00#\x00\x01\x00t\t\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00d\x03\xa6\x01\x00\x00\xab\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00t\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00d\x04\xa6\x01\x00\x00\xab\x01\x00\x00\x00\x00\x00\x00\x00\x00\xa0\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00d\x05\xa6\x01\x00\x00\xab\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00Y\x00d\x00S\x00x\x03Y\x00w\x01', (None, 0, ('long_to_bytes', 'bytes_to_long'), 'Woah woah woah, are you trying to reverse me?', 'os', 1), ('sudokum', 'Crypto.Util.number', 'long_to_bytes', 'bytes_to_long', 'print', '__import__', '_exit'), ('', '', ''), '', '', '', 1, b'\x80\x00\xf0\x02\x05\x05"\xd8\x08\x16\x88\x0e\x88\x0e\x88\x0e\xd8\x08C\xd0\x08C\xd0\x08C\xd0\x08C\xd0\x08C\xd0\x08C\xd0\x08C\xd0\x08C\xd0\x08C\xd0\x08C\xf8\xf0\x02\x02\x05"\xdd\x08\r\xd0\x0e=\xd1\x08>\xd4\x08>\xd0\x08>\xdd\x08\x12\x904\xd1\x08\x18\xd4\x08\x18\xd7\x08\x1e\xd2\x08\x1e\x98q\xd1\x08!\xd4\x08!\xd0\x08!\xd0\x08!\xd0\x08!\xd0\x08!\xf8\xf8\xf8', b'\x82\x0c\x10\x00\x903A\x06\x03', (), ())
>>> dis.disasssemble(c)
  1           0 RESUME                   0

  2           2 NOP

  3           4 LOAD_CONST               1 (0)
              6 LOAD_CONST               0 (None)
              8 IMPORT_NAME              0 (sudokum)
             10 STORE_FAST               0

  4          12 LOAD_CONST               1 (0)
             14 LOAD_CONST               2 (('long_to_bytes', 'bytes_to_long'))
             16 IMPORT_NAME              1 (Crypto.Util.number)
             18 IMPORT_FROM              2 (long_to_bytes)
             20 STORE_FAST               1
             22 IMPORT_FROM              3 (bytes_to_long)
             24 STORE_FAST               2
             26 POP_TOP
             28 LOAD_CONST               0 (None)
             30 RETURN_VALUE
        >>   32 PUSH_EXC_INFO

  5          34 POP_TOP

  6          36 LOAD_GLOBAL              9 (NULL + print)
             48 LOAD_CONST               3 ('Woah woah woah, are you trying to reverse me?')
             50 PRECALL                  1
             54 CALL                     1
             64 POP_TOP

  7          66 LOAD_GLOBAL             11 (NULL + __import__)
             78 LOAD_CONST               4 ('os')
             80 PRECALL                  1
             84 CALL                     1
             94 LOAD_METHOD              6 (_exit)
            116 LOAD_CONST               5 (1)
            118 PRECALL                  1
            122 CALL                     1
            132 POP_TOP
            134 POP_EXCEPT
            136 LOAD_CONST               0 (None)
            138 RETURN_VALUE
        >>  140 COPY                     3
            142 POP_EXCEPT
            144 RERAISE                  1
ExceptionTable:
  4 to 26 -> 32 [0]
  32 to 132 -> 140 [1] lasti

```

Looks like it was trying to import a library callled `sudokum` and `Crypto.Util.numbers`, and if that fails, it would print out `Woah woah woah, are you trying to reverse me?`. I don't have either libaries, so I went ahead and installed them. Afterwards, I saw this print out that prompted me to enter "hello": 

```
$ python3.11 magnum_opus.py 
EwGeFuH+LVQbrUfDCDkcWldxYGst0hkLFAKkzm2iBMJmiA==
> hello
bad
```
# Sudokus and Sudokums

This already seems like a classic challenge-response mechanism: I'm given a challenge -- a string that looks like base64, in this case -- and expects me to compute a response base on the string. The next step should be unlocked if I send the correct string. 



# Flag
```
python3.11 solve.py 
[+] Starting local process './magnum_opus.py': pid 120477
0 input: b'm2xkaFLiC8fAmHLYjEto75dl4DxosvO+Ryx+1Aaw4x4='
response:  b'CMDhpPHG+tDNDM0C4LtU8IaSEwX/vOHciMQrnCnggBZl8A=='
1 input: b'> RW/4iAv94uy7xmMVCcVr6xLyBPGw2K1G1QLf63Qy1rfE'
response:  b'FTNcFHIPVWdUlTIkmysxUX2AIWnnwDZg9v+PnjODw2DIhA=='
2 input: b'> BeqCDkbIiGeQKnSQ22In57ANT4IHjOObd+NoNEVPnOTFKA=='
response:  b'Bg0N75wRKGLqcs6sM9KhBAgHo95CNfLiZABRSJiHgIP/7g=='
3 input: b'> BsBsC7GZup+6VzOr3JJFC0QHRmmr7gYjjmXNSVHb+f243A=='
response:  b'ChdnM3a1n3GJj3A06L6tKJhSy/0YWFMfD6gZxyCPkDwb5A=='
4 input: b'> AcHbvdcwwwaliLo0YPOlToGPDpiGtmZpxvHItn27KjW1HA=='
response:  b'DfkZhRl9t8rmwFrqC+X7rfDJp+Vuxru2HsbJhc+D4ThFnQ=='
5 input: b'> FEV58UX9qKXXXHz8GmbR0sSyuuQLoO8cW8IY/B6Xf7AfOQ=='
response:  b'Df9mbrqDzIaa3w2bQoL82UQa+idKOs9pEKRGvsuuGPSSsQ=='
6 input: b'> AbUTlOjN0zb+dxyRSI7D4yGZS6SZPUAV5u5oRRMrNIF2iA=='
response:  b'Dfy40TbL2LG5vzqPDhK64Xn4UjvkVAH0pFxUwS6cUIdQxw=='
7 input: b'> CiYxG6NsSrJJ6HnC8zndoextpaMEmvw1CBqxtFm0BXKOuA=='
response:  b'Df7M8tDAQcnf1rfvzBzvrnxihst0Afqmd3D3mBF2xN+enA=='
8 input: b'> DoiEg9cN2rPgIvgVb6JgjXfI41IXIpOYhzlAyYc+O+oMIA=='
response:  b'Df8kYhLvIsOdY4Bk9iEFX5SPeZjxVkYixzYlh7zBZS/VGg=='
9 input: b'> O1aXo74+Dz1PwnJAlHsWNGc2kKcr1j0UUZNKuG1a8jCl'
response:  b'Df75E6kSp/r9EHP3eaGFlyxRH35Romwolnn4vODbXfxVDw=='
[*] Switching to interactive mode
> Good job! Here is your flag:
SEKAI{when_you_implement_the_same_VM_3_times_there's_bound_to_be_discrepancies}
```

# Pitfalls 

Even though most reverse engineering writeups are straightforward, the act of reverse engineering itself is not. It is quite convoluted and hackers can easily get trapped in red herrings for hours. So I felt it is necessary to call out some dead ends I ran into, and how I got myself out of it.

1. The biggest pitfall I fell into was trying to implement a pickle virtual machine by hand. I used pickle tool to try to disassemble every single pickle bytecode, but pickletools was crashing at different locations. I spent maybe 5, 6 hours on this effort. And then I realize there are so many bytecodes to emulate, and I could very easily make some logical mistakes and emulate it wrong! 

2. This is the first time i've seen a pickle bytestring with the `buffers` argument. Since I was building the small pickle interpreter, I spent a few hours trying to figure out how `buffers` work, going into the PEP documentation of pickle protocol 5.0. I stopped digging deep once I realize I can just hook the existing pickle code in my library. 

1. I spent a lot of time figuring out `sudokum` was a small python library. I originally thought we need to reverse engineer w

2. I spent some time implementing an actual pickle parser myself. After a few hours, I realize that this exercise is moot and I should just go for the 



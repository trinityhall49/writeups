# TL;DR

This reverse engineering exercise is a challenge-response problem. The challenge is a sudoku puzzle that expects a solution with certain squares substituted. The python code is obfuscated by pickle bytecode that has python bytecode embedded in it. It abuses the `REDUCE` pickle bytecode to call pythonic functions.  I solved this challenge by researching how pickle works under the hood and instrumenting the pickle.py library file manually. I installed the appropriate libaries to get the python script to run locally, and used pwntools to automate the solution. 

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
  [PICKLE HOOK] <built-in function chr> (116,)
  [PICKLE HOOK] <built-in function getattr> ('', 'join')
  [PICKLE HOOK] <built-in method join of str object at 0xa6f200> (['i', 'n', 'f'],)
  [PICKLE HOOK] <class 'float'> ('inf',)
  ...
  [PICKLE HOOK] <built-in method join of str object at 0xa6f200> ([],)
  [PICKLE HOOK] <built-in method join of str object at 0xa751b0> (['', '', 'import', '', ''],)
  [PICKLE HOOK] <built-in function getattr> ('_', 'join')
  [PICKLE HOOK] <built-in function getattr> ('', 'join')
  [PICKLE HOOK] <built-in method join of str object at 0xa6f200> ([],)
  [PICKLE HOOK] <built-in function getattr> ('', 'join')
  [PICKLE HOOK] <built-in method join of str object at 0xa6f200> (['e', 'x', 'i', 't'],)
  [PICKLE HOOK] <built-in method join of str object at 0xa751b0> (['', 'exit'],)
  ...
  [PICKLE HOOK] <class 'code'> (0, 0, 0, 3, 4, 3, b'\x97\x00\t\x00d\x01d\x00l\x00}\x00d\x01d\x02l\x01m\x02}\x01m\x03}\x02\x01\x00d\x00S\x00#\x00\x01\x00t\t\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00d\x03\xa6\x01\x00\x00\xab\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00t\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00d\x04\xa6\x01\x00\x00\xab\x01\x00\x00\x00\x00\x00\x00\x00\x00\xa0\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00d\x05\xa6\x01\x00\x00\xab\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00Y\x00d\x00S\x00x\x03Y\x00w\x01', (None, 0, ('long_to_bytes', 'bytes_to_long'), 'Woah woah woah, are you trying to reverse me?', 'os', 1), ('sudokum', 'Crypto.Util.number', 'long_to_bytes', 'bytes_to_long', 'print', '__import__', '_exit'), ('', '', ''), '', '', '', 1, b'\x80\x00\xf0\x02\x05\x05"\xd8\x08\x16\x88\x0e\x88\x0e\x88\x0e\xd8\x08C\xd0\x08C\xd0\x08C\xd0\x08C\xd0\x08C\xd0\x08C\xd0\x08C\xd0\x08C\xd0\x08C\xd0\x08C\xf8\xf0\x02\x02\x05"\xdd\x08\r\xd0\x0e=\xd1\x08>\xd4\x08>\xd0\x08>\xdd\x08\x12\x904\xd1\x08\x18\xd4\x08\x18\xd7\x08\x1e\xd2\x08\x1e\x98q\xd1\x08!\xd4\x08!\xd0\x08!\xd0\x08!\xd0\x08!\xd0\x08!\xf8\xf8\xf8', b'\x82\x0c\x10\x00\x903A\x06\x03', (), ())
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
        print("[PICKLE HOOK]", func, args)
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

Looks like it was trying to import a library callled `sudokum` and `Crypto.Util.numbers`, and if that fails, it would print out `Woah woah woah, are you trying to reverse me?`. I don't have either libraries, so I went ahead and installed them. Afterwards, I saw this print out that prompted me to enter "hello": 

```
$ python3.11 magnum_opus.py 
EwGeFuH+LVQbrUfDCDkcWldxYGst0hkLFAKkzm2iBMJmiA==
> hello
bad
```
# Sudokus and Sudokums

This seems like a classic challenge-response problem: I'm given a challenge -- a string that looks like base64, in this case -- and itexpects me to compute a response base on that string.

To understand why I got the `bad` print out, I looked at the code object right before I was prompted to enter a response
```
[PICKLE HOOK] <class 'code'> (0, 0, 0, 6, 9, 3, b'\x97\x00d\x01d\x02l\x00m\x01}\x00\x01\x00d\x01d\x03l\x02m\x03}\x01\x01\x00\t\x00t\t\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00d\x04\xa6\x01\x00\x00\xab\x01\x00\x00\x00\x00\x00\x00\x00\x00}\x02t\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00|\x00\x02\x00|\x01|\x02\xa6\x01\x00\x00\xab\x01\x00\x00\x00\x00\x00\x00\x00\x00\xa6\x01\x00\x00\xab\x01\x00\x00\x00\x00\x00\x00\x00\x00\xa6\x01\x00\x00\xab\x01\x00\x00\x00\x00\x00\x00\x00\x00\xa0\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00d\x05\xa6\x01\x00\x00\xab\x01\x00\x00\x00\x00\x00\x00\x00\x00}\x02g\x00a\x07t\x11\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00d\x01d\x05d\x06\xa6\x03\x00\x00\xab\x03\x00\x00\x00\x00\x00\x00\x00\x00D\x00][}\x03g\x00}\x04t\x11\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00d\x06\xa6\x01\x00\x00\xab\x01\x00\x00\x00\x00\x00\x00\x00\x00D\x00]-}\x05|\x04\xa0\t\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00t\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00|\x02|\x03|\x05z\x00\x00\x00\x19\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa6\x01\x00\x00\xab\x01\x00\x00\x00\x00\x00\x00\x00\x00\xa6\x01\x00\x00\xab\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x8c.t\x0e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa0\t\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00|\x04\xa6\x01\x00\x00\xab\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x8c\\d\x00S\x00#\x00\x01\x00t\x17\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00d\x07\xa6\x01\x00\x00\xab\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00t\x19\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00d\x08\xa6\x01\x00\x00\xab\x01\x00\x00\x00\x00\x00\x00\x00\x00\xa0\r\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00d\t\xa6\x01\x00\x00\xab\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00Y\x00d\x00S\x00x\x03Y\x00w\x01', (None, 0, ('bytes_to_long',), ('b64decode',), '> ', 81, 9, 'bad', 'os', 1), ('Crypto.Util.number', 'bytes_to_long', 'base64', 'b64decode', 'input', 'str', 'zfill', 'add', 'range', 'append', 'int', 'print', '__import__', '_exit'), ('bytes_to_long', 'b64decode', '', '', '', ''), '', '', '', 1, b'\x80\x00\xe0\x040\xd0\x040\xd0\x040\xd0\x040\xd0\x040\xd0\x040\xd8\x04 \xd0\x04 \xd0\x04 \xd0\x04 \xd0\x04 \xd0\x04 \xf0\x02\x0c\x05"\xdd\x0f\x14\x90T\x89{\x8c{\x88\x04\xdd\x0f\x12\x90=\x90=\xa0\x19\xa0\x19\xa84\xa1\x1f\xa4\x1f\xd1\x131\xd4\x131\xd1\x0f2\xd4\x0f2\x88\x04\xd8\x0e\x10\x88\x03\xdd\x11\x16\x90q\x98"\x98a\x91\x1f\x94\x1f\xf0\x00\x05\t\x1d\xf0\x00\x05\t\x1d\x88A\xd8\x13\x15\x88D\xdd\x15\x1a\x981\x91X\x94X\xf0\x00\x01\r,\xf0\x00\x01\r,\x90\x01\xd8\x10\x14\x97\x0b\x92\x0b\x9dC\xa0\x04\xa0Q\xa0q\xa1S\xa4\t\x99N\x9cN\xd1\x10+\xd4\x10+\xd0\x10+\xd0\x10+\xe5\x0c\x0f\x8fJ\x8aJ\x90t\xd1\x0c\x1c\xd4\x0c\x1c\xd0\x0c\x1c\xd0\x0c\x1c\xf0\x0b\x05\t\x1d\xf0\x00\x05\t\x1d\xf8\xf0\x0c\x02\x05"\xdd\x08\r\x88e\x89\x0c\x8c\x0c\x88\x0c\xdd\x08\x12\x904\xd1\x08\x18\xd4\x08\x18\xd7\x08\x1e\xd2\x08\x1e\x98q\xd1\x08!\xd4\x08!\xd0\x08!\xd0\x08!\xd0\x08!\xd0\x08!\xf8\xf8\xf8', b'\x8eB2C\x02\x00\xc3\x023C8\x03', (), ())

```

This translates to the following bytecode:
```
  1           0 RESUME                   0

  3           2 LOAD_CONST               1 (0)
              4 LOAD_CONST               2 (('bytes_to_long',))
              6 IMPORT_NAME              0 (Crypto.Util.number)
              8 IMPORT_FROM              1 (bytes_to_long)
             10 STORE_FAST               0 (bytes_to_long)
             12 POP_TOP

  4          14 LOAD_CONST               1 (0)
             16 LOAD_CONST               3 (('b64decode',))
             18 IMPORT_NAME              2 (base64)
             20 IMPORT_FROM              3 (b64decode)
             22 STORE_FAST               1 (b64decode)
             24 POP_TOP

  5          26 NOP

  6          28 LOAD_GLOBAL              9 (NULL + input)
             40 LOAD_CONST               4 ('> ')
             42 PRECALL                  1
             46 CALL                     1
             56 STORE_FAST               2

  7          58 LOAD_GLOBAL             11 (NULL + str)
             70 PUSH_NULL
             72 LOAD_FAST                0 (bytes_to_long)
             74 PUSH_NULL
             76 LOAD_FAST                1 (b64decode)
             78 LOAD_FAST                2
             80 PRECALL                  1
             84 CALL                     1
             94 PRECALL                  1
             98 CALL                     1
            108 PRECALL                  1
            112 CALL                     1
            122 LOAD_METHOD              6 (zfill)
            144 LOAD_CONST               5 (81)
            146 PRECALL                  1
            150 CALL                     1
            160 STORE_FAST               2
            162 BUILD_LIST               0
            164 STORE_GLOBAL             7 (add)

 10         166 LOAD_GLOBAL             17 (NULL + range)
            178 LOAD_CONST               1 (0)
            180 LOAD_CONST               5 (81)
            182 LOAD_CONST               6 (9)
            184 PRECALL                  3
            188 CALL                     3
            198 GET_ITER
        >>  200 FOR_ITER                91 (to 384)
            202 STORE_FAST               3

 12         204 BUILD_LIST               0
            206 STORE_FAST               4
            208 LOAD_GLOBAL             17 (NULL + range)
            220 LOAD_CONST               6 (9)
            222 PRECALL                  1
            226 CALL                     1
            236 GET_ITER
        >>  238 FOR_ITER                45 (to 330)
            240 STORE_FAST               5
            242 LOAD_FAST                4
            244 LOAD_METHOD              9 (append)
            266 LOAD_GLOBAL             21 (NULL + int)
            278 LOAD_FAST                2
            280 LOAD_FAST                3
            282 LOAD_FAST                5
            284 BINARY_OP                0 (+)
            288 BINARY_SUBSCR
            298 PRECALL                  1
            302 CALL                     1
            312 PRECALL                  1
            316 CALL                     1
            326 POP_TOP
            328 JUMP_BACKWARD           46 (to 238)
        >>  330 LOAD_GLOBAL             14 (add)
            342 LOAD_METHOD              9 (append)
            364 LOAD_FAST                4
            366 PRECALL                  1
            370 CALL                     1
            380 POP_TOP
            382 JUMP_BACKWARD           92 (to 200)

 17     >>  384 LOAD_CONST               0 (None)
            386 RETURN_VALUE
        >>  388 PUSH_EXC_INFO
            390 POP_TOP
            392 LOAD_GLOBAL             23 (NULL + print)
            404 LOAD_CONST               7 ('bad')
            406 PRECALL                  1
            410 CALL                     1
            420 POP_TOP
            422 LOAD_GLOBAL             25 (NULL + __import__)
            434 LOAD_CONST               8 ('os')
            436 PRECALL                  1
            440 CALL                     1
            450 LOAD_METHOD             13 (_exit)
            472 LOAD_CONST               9 (1)
            474 PRECALL                  1
            478 CALL                     1
            488 POP_TOP
            490 POP_EXCEPT
            492 LOAD_CONST               0 (None)
            494 RETURN_VALUE
        >>  496 COPY                     3
            498 POP_EXCEPT
            500 RERAISE                  1
ExceptionTable:
  28 to 382 -> 388 [0]
  388 to 488 -> 496 [1] lasti
```
Basic blocks 6 and 7 tells us that it expects an input that is then base64-decoded. So I have to input a base64 string. Let's turn `hello` into its base64 form: 

```
$ python3.11 magnum-opus.py 
FnQ8apO3E4PaRTzBjw6jWxvBC9Bq+hn0DDl+GVdkxHYU
> aGVsbG8=
no
```
It turned from a `bad` to a `no`, that's good progress! Let's look some interesting functions that are called after I entered my response:

```
[PICKLE HOOK] <built-in function getattr> (['print("no");__import__("os")._exit(1)', ''], '__getitem__')
...
[PICKLE HOOK] <built-in function eq> ([[0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 4, 4, 8], [3, 7, 8, 2, 0, 3, 2, 4, 7]], [[9, 9, 2, 6, 3, 5, 8, 4, 1], [3, 1, 5, 8, 4, 8, 6, 9, 4], [4, 1, 6, 7, 9, 1, 4, 3, 2], [5, 3, 9, 8, 7, 4, 2, 5, 6], [2, 4, 1, 5, 6, 3, 7, 8, 7], [5, 6, 8, 9, 2, 7, 3, 1, 4], [6, 2, 3, 4, 8, 9, 1, 7, 5], [8, 9, 7, 1, 5, 9, 4, 6, 3], [1, 5, 4, 3, 7, 6, 5, 2, 8]])
...
no
```
So it looks like two 2D arrays are compared against each other, and the challenge-response fails if they are not equal. At this point I am not sure how these two arrays are created, so I went back to the last code object to see how my base64 input is manipulated internally. 

I reversed the logic in basic block 7, 10 and 12, and this is approximately what was happening:
```
my_input = input('>')
b64_str = base64.b64decode("my_input")
byte_str = Crypto.Util.numbers.bytes_to_long(b64_str)
arr2d = []
for i in range(0, 81, 9):
    arr = []
    for j in range(9):
        arr.append(int(byte_str[i]))
    arr2d.append(arr)
```
Indeed, if you plug in `my_input` to be `aGVsbG8=`, it would yield the first 2d array that we saw before. 

What about the second 2D array. If you look around when the challenge is printed out, you will see the following function calls:
```
[PICKLE HOOK] <class 'code'> (0, 0, 0, 5, 6, 3, b'\x97\x00d\x01d\x00l\x00}\x00\t\x00|\x00\xa0\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00d\x03\xac\x04\xa6\x01\x00\x00\xab\x01\x00\x00\x00\x00\x00\x00\x00\x00a\x02g\x00}\x01t\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00d\x05\xa6\x01\x00\x00\xab\x01\x00\x00\x00\x00\x00\x00\x00\x00D\x00]5}\x02|\x01\xa0\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00|\x00\xa0\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00t\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa6\x01\x00\x00\xab\x01\x00\x00\x00\x00\x00\x00\x00\x00d\x06\x19\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa6\x01\x00\x00\xab\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x8c6g\x00}\x03|\x01D\x00]!}\x04|\x03\xa0\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00|\x04|\x01d\x01\x19\x00\x00\x00\x00\x00\x00\x00\x00\x00k\x02\x00\x00\x00\x00\xa6\x01\x00\x00\xab\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x8c"t\r\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00|\x03\xa6\x01\x00\x00\xab\x01\x00\x00\x00\x00\x00\x00\x00\x00r\n|\x01d\x01\x19\x00\x00\x00\x00\x00\x00\x00\x00\x00a\x07d\x00S\x00\x8c\x9d', (None, 0, True, 0.56, ('mask_rate',), 10, 1), ('sudokum', 'generate', 'dirg', 'range', 'append', 'solve', 'all', 'plus'), ('sudokum', '', '', '', ''), '', '', '', 3, b"\x80\x00\xf0\x06\x00\x05\x13\x80N\x80N\x80N\xf0\x02\x0c\x05\x12\xd8\x0f\x16\xd7\x0f\x1f\xd2\x0f\x1f\xa8$\xd0\x0f\x1f\xd1\x0f/\xd4\x0f/\x88\x04\xe0\x11\x13\x88\x06\xdd\x11\x16\x90r\x91\x19\x94\x19\xf0\x00\x01\t2\xf0\x00\x01\t2\x88A\xd8\x0c\x12\x8fM\x8aM\x98'\x9f-\x9a-\xad\x04\xd1\x1a-\xd4\x1a-\xa8a\xd4\x1a0\xd1\x0c1\xd4\x0c1\xd0\x0c1\xd0\x0c1\xe0\x0e\x10\x88\x03\xd8\x11\x17\xf0\x00\x01\t%\xf0\x00\x01\t%\x88A\xd8\x0c\x0f\x8fJ\x8aJ\x90q\x98&\xa0\x11\x9c)\x92|\xd1\x0c$\xd4\x0c$\xd0\x0c$\xd0\x0c$\xdd\x0b\x0e\x88s\x898\x8c8\xf0\x00\x02\t\x12\xd8\x19\x1f\xa0\x01\x9c\x19\x88J\xd8\x0c\x11\x88E\xf0\x19\x0c\x05\x12", b'', (), ())
...
[PICKLE HOOK] <built-in function eval> (b"int(''.join([''.join(list(map(str,x)))for(x)in dirg]))",)
[PICKLE HOOK] <function long_to_bytes at 0x7da8dc98e020> (2600001000048007000701530700014200001563789068920304023009005000050463000000020,)
[PICKLE HOOK] <function b64encode at 0x7da8dc98e660> (b'\x16t<j\x93\xb7\x13\x83\xdaE<\xc1\x8f\x0e\xa3[\x1b\xc1\x0b\xd0j\xfa\x19\xf4\x0c9~\x19Wd\xc4v\x14',)
[PICKLE HOOK] <built-in function getattr> ('', 'join')
[PICKLE HOOK] <built-in method join of str object at 0xa6f200> (['d', 'e', 'c', 'o', 'd', 'e'],)
[PICKLE HOOK] <built-in function getattr> (b'FnQ8apO3E4PaRTzBjw6jWxvBC9Bq+hn0DDl+GVdkxHYU', 'decode')
[PICKLE HOOK] <built-in method decode of bytes object at 0x7da8dc9f3be0> ()
[PICKLE HOOK] <built-in function print> ('FnQ8apO3E4PaRTzBjw6jWxvBC9Bq+hn0DDl+GVdkxHYU',)
```
A variable called `dirg` is used to create a large number, which gets converted to a byte string, and then base64-encoded. This is exactly the opposite of the previous process! And looking at the code object that is referncing `dirg`, there are other calls like `sudokum`, `solve`, `append`, maybe this is a sudoku puzzle, and the response is just to solve the sudoku! So I went to work again, and wrote a script that solves the sudoku and encodes the solution in the way the challenge wants:

```
$ python3.11 magnum-opus.py
Ejg/cT9QcNaEibAgiFWivbO4nxyGCdtfbBxRhiSsGDQ2kg==
> Eoe1B5TaczCn26J1mERxMKXMHNEDoUD8odWWxJZMPwuOSA==
no
```
Still? What else could be wrong? I re-enabled the instrumentation and looked around the equality operator again: 

```
[PICKLE HOOK] <built-in function getattr> ('', 'join')
[PICKLE HOOK] <built-in method join of str object at 0xa6f200> (['a', 'd', 'd'],)
[PICKLE HOOK] <built-in function eval> ('add',)
[PICKLE HOOK] <built-in function getattr> ('', 'join')
[PICKLE HOOK] <built-in method join of str object at 0xa6f200> (['p', 'l', 'u', 's'],)
[PICKLE HOOK] <built-in function eval> ('plus',)
[PICKLE HOOK] <built-in function eq> ([[5, 4, 9, 2, 8, 3, 7, 6, 1], [2, 7, 3, 4, 6, 1, 5, 9, 8], [1, 8, 6, 7, 5, 9, 2, 3, 4], [7, 6, 1, 8, 9, 4, 3, 2, 5], [4, 5, 2, 1, 3, 7, 6, 8, 9], [9, 3, 8, 6, 2, 5, 1, 4, 7], [8, 9, 5, 3, 7, 6, 4, 1, 2], [6, 2, 4, 5, 1, 8, 9, 7, 3], [3, 1, 7, 9, 4, 2, 8, 5, 6]], [[6, 4, 9, 2, 8, 3, 7, 6, 1], [2, 7, 3, 1, 6, 1, 5, 9, 8], [1, 8, 6, 7, 5, 9, 5, 3, 4], [7, 4, 1, 8, 9, 4, 3, 2, 5], [4, 5, 2, 1, 3, 7, 6, 8, 9], [9, 3, 8, 6, 2, 5, 1, 4, 7], [8, 9, 8, 3, 7, 6, 4, 1, 2], [6, 2, 6, 5, 1, 8, 9, 7, 3], [3, 1, 7, 9, 4, 2, 8, 1, 8]])
<built-in method __getitem__ of list object at 0x7286fd9058c0> (False,)
no
```
My answer is almost correct, but doesn't the expected response look at bit strange? If you look at the first list of the second 2D array:
```
[6, 4, 9, 2, 8, 3, 7, 6, 1]
```
This is not the solution to a sudoku. A sudoku expects all elements in a row to be unique, but this obviously has a duplicate! What else is there? 

# A time-based RNG

Looking at the function call right above the equality operator, there is a `eval()` function call on `plus` variable. I actually saw this `plus` variable referenced elsewhere in the code, so I took the trace and grepped for all the lines that references `plus`:

```
$ cat pickle_trace | grep plus
...
<built-in function add> ('plus[', '6')
<built-in function add> ('plus[6', '][')
<built-in function add> ('plus[6][', '2')
<built-in function add> ('plus[6][2', '] = ')
<built-in function add> ('plus[6][2] = ', '7')
<built-in function add> ('plus[6][2] = 7', ' + 1')
<built-in function exec> ('plus[6][2] = 7 + 1',)
<built-in function add> ('plus[', '2')
<built-in function add> ('plus[2', '][')
<built-in function add> ('plus[2][', '6')
<built-in function add> ('plus[2][6', '] = ')
<built-in function add> ('plus[2][6] = ', '4')
<built-in function add> ('plus[2][6] = 4', ' + 1')
<built-in function exec> ('plus[2][6] = 4 + 1',)
<built-in function add> ('plus[', '5')
<built-in function add> ('plus[5', '][')
<built-in function add> ('plus[5][', '7')
<built-in function add> ('plus[5][7', '] = ')
<built-in function add> ('plus[5][7] = ', '3')
<built-in function add> ('plus[5][7] = 3', ' + 1')
<built-in function exec> ('plus[5][7] = 3 + 1',)
<built-in function add> ('plus[', '7')
<built-in function add> ('plus[7', '][')
<built-in function add> ('plus[7][', '2')
<built-in function add> ('plus[7][2', '] = ')
<built-in function add> ('plus[7][2] = ', '5')
<built-in function add> ('plus[7][2] = 5', ' + 1')
<built-in function exec> ('plus[7][2] = 5 + 1',)
<built-in function eval> ('plus',)
```
Isn't this interesting? It looks like there is a third 9x9 matrix called `plus`. It has the potential to alter the sudoku's solution. Narrowing down only the interesting ones:

```
$ cat pickle_trace | grep plus | grep exec
<built-in function exec> ('plus[6][2] = 2 + 1',)
<built-in function exec> ('plus[8][7] = 4 + 1',)
<built-in function exec> ('plus[3][1] = 3 + 1',)
<built-in function exec> ('plus[0][0] = 5 + 1',)
<built-in function exec> ('plus[8][7] = 0 + 1',)
<built-in function exec> ('plus[1][3] = 0 + 1',)
<built-in function exec> ('plus[8][8] = 7 + 1',)
<built-in function exec> ('plus[6][2] = 7 + 1',)
<built-in function exec> ('plus[2][6] = 4 + 1',)
<built-in function exec> ('plus[5][7] = 3 + 1',)
<built-in function exec> ('plus[7][2] = 5 + 1',)
```

If you match the indices of plus to that of the expected solution, you will see that the indexed squares are substituted with values in this plus matrix. Next question is, how are the indices and values chosen? If we look at how the first set of indices are created: 

```
<built-in function getattr> (<CDLL '/lib/x86_64-linux-gnu/libc.so.6', handle 728701593080 at 0x72870070d010>, 'srand')
...
<built-in function time> ()
<class 'int'> (1724528623.368277,)
<_FuncPtr object at 0x728700818a10> (1724528623,)
...
<built-in method join of str object at 0xa6f200> (['r', 'a', 'n', 'd'],)
<built-in function getattr> (<CDLL '/lib/x86_64-linux-gnu/libc.so.6', handle 728701593080 at 0x72870070d010>, 'rand')
...
<_FuncPtr object at 0x72870081b520> ()
<built-in function mod> (2085967131, 9)
<class 'str'> (6,)
<built-in function add> ('plus[6', '][')
...
<_FuncPtr object at 0x72870081b520> ()
<built-in function mod> (987274433, 9)
<class 'str'> (2,)
<built-in function add> ('plus[6][', '2')
...
<built-in function add> ('plus[6][2', '] = ')
...
<_FuncPtr object at 0x72870081b520> ()
<built-in function mod> (982788104, 9)
<class 'str'> (2,)
<built-in function add> ('plus[6][2] = ', '2')

```

From the print outs, it looks like the indices and the values are generated with `rand()`, which is seeded with the current time. After I updated my script to take this substitution matrix into account, I got the initial correct answer. 

The script gave me another challenge after the first correct answer, and the response is the same: a sudoku solution modified by a substitution matrix. I got to the final flag locally, but of course, when ran against the challenge server, I have to run it 5-10 times because the seed to `rand()` is time-based. 

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

3. I spent half an hour to figure out `sudokum` was an existing python library. I originally thought we need to reverse engineer what sudokum is from the bytecode. But luckily I did some more research and found the link to the sudokum python package. 
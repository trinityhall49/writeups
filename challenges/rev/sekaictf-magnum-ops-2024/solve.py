import Crypto.Util.number
import base64
from sudoku import Sudoku
import time
from ctypes import CDLL
from pwn import *

def input_to_sudoku(my_input):
    a = base64.b64decode(my_input)
    b = str(Crypto.Util.number.bytes_to_long(a)).zfill(81)
    c = []
    for i in range(0, 81, 9):
        d = []
        for j in range(9):
            d.append(int(b[i+j]))
        c.append(d)
    return c

def sudoku_to_input(my_board, seed, iteration):
    final_str = ""
    libc = CDLL("libc.so.6")
    libc.srand(seed)
    count = 11;
    for i in range(count):
        x = libc.rand() % 9
        y = libc.rand() % 9
        plus = (libc.rand() % 9) + 1
        my_board[x][y] = plus
    for i in range(9):
        for j in range(9):
            final_str += str(my_board[i][j])
    assert(len(final_str) == 81)
    final_int = int(final_str)
    # print(final_int)
    return base64.b64encode(Crypto.Util.number.long_to_bytes(final_int))


sh = process('./magnum_opus.py')
# sh = remote('magnum-opus.chals.sekai.team', 1337, ssl=True)

i = 0 
while (i < 10):
    a = sh.recvline()
    if b"no" in a:
        print("Wrong answer")
        break
    print("{} input: {}".format(i, a.strip()))
    board_str = a.strip()
    seed=int(time.time())
    board = input_to_sudoku(board_str)
    puzzle = Sudoku(3,3,board=board)
    solution = puzzle.solve()
    res = sudoku_to_input(solution.board, seed, i)
    print("response: ", res)
    sh.sendline(res)
    i += 1;
sh.interactive()

from z3 import * 
from string import ascii_letters, digits

li_flag = [BitVec(f'a{i}', 8) for i in range(36)]
s = Solver()

alp = ascii_letters + digits + '_!'

format_flag = 'ISITDTU{'
for i in range(len(format_flag)):
    s.add(li_flag[i] == ord(format_flag[i]))
s.add(li_flag[35] == ord('}'))

for i in range(len(format_flag), len(li_flag)-1):
    s.add(Or([li_flag[i] == ord(c) for c in alp]))


s.add(li_flag[32] * li_flag[27] * li_flag[25] - li_flag[29] + li_flag[1] * li_flag[8] == 538738,
li_flag[7] - li_flag[6] + li_flag[4] * li_flag[20] * li_flag[10] - li_flag[11] == 665370,
li_flag[16] * li_flag[31] - li_flag[31] - li_flag[30] * li_flag[22] + li_flag[14] == -2945,
li_flag[3] - li_flag[9] - li_flag[4] + li_flag[33] - li_flag[18] - li_flag[11] == -191,
li_flag[1] - li_flag[8] + li_flag[30] + li_flag[25] * li_flag[29] + li_flag[18] == 4853,
li_flag[5] + li_flag[13] - li_flag[23] * li_flag[2] * li_flag[14] * li_flag[7] == -86153321,
li_flag[13] + li_flag[9] * li_flag[12] * li_flag[5] + li_flag[10] * li_flag[27] == 873682,
li_flag[21] * li_flag[18] * li_flag[9] - li_flag[6] + li_flag[22] + li_flag[3] == 451644,
li_flag[23] * li_flag[32] + li_flag[21] + li_flag[24] + li_flag[34] - li_flag[4] == 9350,
li_flag[24] + li_flag[17] + li_flag[35] - li_flag[19] - li_flag[26] - li_flag[6] == 27,
li_flag[15] - li_flag[3] + li_flag[19] * li_flag[23] + li_flag[14] + li_flag[13] == 11247,
li_flag[2] - li_flag[15] + li_flag[17] + li_flag[12] * li_flag[7] - li_flag[21] == 13297,
li_flag[8] + li_flag[35] + li_flag[28] - li_flag[0] - li_flag[20] + li_flag[26] == 266,
li_flag[12] * li_flag[28] - li_flag[1] + li_flag[0] + li_flag[2] + li_flag[17] == 10422,
li_flag[5] * li_flag[19] - li_flag[34] - li_flag[11] + li_flag[22] + li_flag[15] == 9883,
li_flag[16] + li_flag[33] * li_flag[10] - li_flag[16] * li_flag[20] - li_flag[0] == -5604,
li_flag[8]* 2 == 194, li_flag[34] == li_flag[33],
li_flag[17] == 99, li_flag[18] == 97, li_flag[19] == 116)

# print(s.check())
while s.check() == sat:
    moduls = s.model()
    tmp = ''
    for i in li_flag:
        tmp += chr(moduls[i].as_long())
    print(tmp)
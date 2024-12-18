#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/reg.h>

// anti-disasm
#define JZJMP __asm__ volatile(".byte 0x74,0x01,0xe9\n");

#define R(v, n) (((v) >> (n)) | ((v) << (32 - (n))))
#define X(u, v) t = s[u], s[u] = s[v], s[v] = t
#define F(n) for (i = 0; i < n; i++)
typedef unsigned int W;

uint8_t enc[] = {203, 237, 14, 34, 9, 130, 4, 34, 193, 117, 130, 51, 52, 114, 64, 240, 169, 174, 4, 61, 30, 194, 3, 135, 47, 121, 216, 103, 7, 72, 246, 163, 139, 29, 184, 142, 135, 201, 16, 176, 246, 161, 46, 100, 163, 21, 189, 63};

void xtea(void *mk, void *p)
{
    unsigned int t, r = 65, s = 0, *k = mk, *x = p;
    while (--r)
        t = x[1],
        x[1] = *x += ((((t << 4) ^ (t >> 5)) + t) ^
                      (s + k[((r & 1) ? s += 0x9E3779B9,
                              s >> 11 : s) &
                             3])),
        *x = t;
}

void xoodoo(void *p)
{
    W e[4], a, b, c, t, r, i, *s = p;
    W x[12] = {
        0x058, 0x038, 0x3c0, 0x0d0,
        0x120, 0x014, 0x060, 0x02c,
        0x380, 0x0f0, 0x1a0, 0x012};

    for (r = 0; r < 12; r++)
    {
        F(4)
        e[i] = R(s[i] ^ s[i + 4] ^ s[i + 8], 18),
        e[i] ^= R(e[i], 9);
        F(12)
        s[i] ^= e[(i - 1) & 3];
        X(7, 4);
        X(7, 5);
        X(7, 6);
        s[0] ^= x[r];
        F(4)
        a = s[i],
        b = s[i + 4],
        c = R(s[i + 8], 21),
        s[i + 8] = R((b & ~a) ^ c, 24),
        s[i + 4] = R((a & ~c) ^ b, 31),
        s[i] ^= c & ~b;
        X(8, 10);
        X(9, 11);
    }
}

bool check(uint8_t *flag)
{
    bool tmp = false;
    uint8_t *buf;
    register int key asm("r13");
    W li_key[48];
    W list[12];
    W i, j = 0;

    F(48)
    {
        asm("mov (0), %r10\n");
        li_key[i] = key;
    }

    xtea(li_key, flag);

    F(12)
    list[i] = (flag[i * 4] << 24) | (flag[i * 4 + 1] << 16) | (flag[i * 4 + 2] << 8) | flag[i * 4 + 3];

    xoodoo(list);

    F(12)
    flag[j++] = (list[i] >> 24) & 0xff,
    flag[j++] = (list[i] >> 16) & 0xff,
    flag[j++] = (list[i] >> 8) & 0xff,
    flag[j++] = list[i] & 0xff;

    F(48)
    if (flag[i] == enc[i])
    {
        tmp = true;
    }
    else
    {
        tmp = false;
    }
    return tmp;
}

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        printf("%s <flag>\n", argv[0]);
        exit(1);
    }
    sleep(2);

    pid_t pid;
    struct user_regs_struct regs;
    int status;
    long orig_RAX;
    int len = 0;
    uint8_t key;

    pid = fork();
    if (pid == 0)
    {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        if (check(argv[1]))
            printf("Yeahh 2 much :(( \n");
        else
            printf("Nope :))\n");
        exit(0);
    }
    else
    {
        ptrace(PTRACE_ATTACH, pid, NULL, NULL);
        while (1)
        {
            waitpid(pid, &status, 0);
            if (WIFEXITED(status))
                break;

            if (WIFCONTINUED(status))
                continue;

            if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSEGV)
            {
                JZJMP;
                len += 1;
                key = R(((len ^ 0xab) << 2), 5) & 0xff;

                ptrace(PTRACE_GETREGS, pid, NULL, &regs);

                JZJMP;
                regs.r13 = key;
                regs.rip += 8;

                ptrace(PTRACE_SETREGS, pid, NULL, &regs);
            }
            ptrace(PTRACE_CONT, pid, NULL, NULL);
        }
    }
    return 0;
}
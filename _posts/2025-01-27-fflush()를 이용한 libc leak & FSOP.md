---
layout: post
title: "fflush()를 이용한 libc leak & FSOP"
author: "hazziin"
tags: [Pwn]
---

드림핵의 [validator-revenge](https://dreamhack.io/wargame/challenges/101)를 풀며 배운 걸 정리해 보려고 한다.(처음 푼 7단계 문제... ㅋㅋ)
풀다가 배운 것이 많아서 간단히 라업 정리 + 깨달은 것을 정리하고자 한다.
개인 노션에 중요한 것만 정리해 두는 느낌으로다가...

---

<img src="{{ '/assets/250127/img01.png' | relative_url }}">
보호기법은 full relro만 걸려 있다. → GOT overwrite는 불가

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  char s[128]; // [rsp+0h] [rbp-80h] BYREF
 
  initalize();
  memset(s, 0, sizeof(s));
  read(0, s, 0x400uLL);
  validate(s, 128LL);
  fflush(stdout);
  return 0LL;
}
__int64 __fastcall validate(__int64 a1, __int64 a2)
{
  unsigned int i; // [rsp+1Ch] [rbp-4h]
  int j; // [rsp+1Ch] [rbp-4h]
 
  for ( i = 0; i <= 9; ++i )
  {
    if ( *(_BYTE *)((int)i + a1) != aDreamhack[i] )
      exit(0);
  }
  for ( j = 11; j < (unsigned __int64)(a2 - 10); ++j )
  {
    if ( *(unsigned __int8 *)(j + a1) != *(char *)(j + 1LL + a1) + 1 )
      exit(0);
  }
  return 0LL;
}
```
코드는 굉장히 단순하다. 이전 문제와 달리 NX가 켜져 있어서 셸코드를 넣을 수는 없다.
오버플로가 발생하는 것은 여전하니 rop로 공격해야 할 것 같은데... rop 페이로드를 짜기 위해서는 libc base를 leak해야 한다.
그런데 마땅한 출력 함수가 없다... libc base를 어떻게 leak할까? → `fflush()`를 이용하자!

# fflush()를 이용한 libc leak

`fflush()`를 이용해 libc leak이 가능하다는 사실... 왜 이게 가능한지 libc 함수를 분석해 보자.

```c
int
_IO_fflush (_IO_FILE *fp)
{
  if (fp == NULL)
    return _IO_flush_all ();
  else
    {
      int result;
      CHECK_FILE (fp, EOF);
      _IO_acquire_lock (fp);
      result = _IO_SYNC (fp) ? EOF : 0;
      _IO_release_lock (fp);
      return result;
    }
}
```
`fflush()`는 내부적으로 `_IO_SYNC()`를 호출한다. 그리고 `_IO_SYNC()`는 vtable에서 `_IO_new_file_sync()`를 실행시킨다.
(libioP.h 내부의 `#define _IO_SYNC(FP) JUMP0 (__sync, FP)`)

```c
int
_IO_new_file_sync (_IO_FILE *fp)
{
  _IO_ssize_t delta;
  int retval = 0;
 
  /*    char* ptr = cur_ptr(); */
  if (fp->_IO_write_ptr > fp->_IO_write_base)
    if (_IO_do_flush(fp)) return EOF;
  delta = fp->_IO_read_ptr - fp->_IO_read_end;
  if (delta != 0)
    {
#ifdef TODO
      if (_IO_in_backup (fp))
	delta -= eGptr () - Gbase ();
#endif
      _IO_off64_t new_pos = _IO_SYSSEEK (fp, delta, 1);
      if (new_pos != (_IO_off64_t) EOF)
	fp->_IO_read_end = fp->_IO_read_ptr;
      else if (errno == ESPIPE)
	; /* Ignore error from unseekable devices. */
      else
	retval = EOF;
    }
  if (retval != EOF)
    fp->_offset = _IO_pos_BAD;
  /* FIXME: Cleanup - can this be shared? */
  /*    setg(base(), ptr, ptr); */
  return retval;
}

#define _IO_do_flush(_f) \
  ((_f)->_mode <= 0							      \
   ? _IO_do_write(_f, (_f)->_IO_write_base,				      \
		  (_f)->_IO_write_ptr-(_f)->_IO_write_base)		      \
   : _IO_wdo_write(_f, (_f)->_wide_data->_IO_write_base,		      \
		   ((_f)->_wide_data->_IO_write_ptr			      \
		    - (_f)->_wide_data->_IO_write_base)))
		    
int
_IO_new_do_write (_IO_FILE *fp, const char *data, _IO_size_t to_do)
{
  return (to_do == 0
	  || (_IO_size_t) new_do_write (fp, data, to_do) == to_do) ? 0 : EOF;
}
libc_hidden_ver (_IO_new_do_write, _IO_do_write)

```
`_IO_new_file_sync()`는 내부에서 `_IO_do_flush(fp)`를 호출하게 되는데, 이는 매크로로 정의되어 있어 `_IO_do_write()`를 수행하게 된다. 
이때, `_IO_do_write()`는 `libc_hidden_ver (_IO_new_do_write, _IO_do_write)`에 의해 실제로는 
`_IO_new_do_write()`의 `new_do_write()`를 실행한다.

```c
static size_t
new_do_write (FILE *fp, const char *data, size_t to_do)
{
  size_t count;
  if (fp->_flags & _IO_IS_APPENDING)
    /* On a system without a proper O_APPEND implementation,
       you would need to sys_seek(0, SEEK_END) here, but is
       not needed nor desirable for Unix- or Posix-like systems.
       Instead, just indicate that offset (before and after) is
       unpredictable. */
    fp->_offset = _IO_pos_BAD;
  else if (fp->_IO_read_end != fp->_IO_write_base)
    {
      off64_t new_pos
	= _IO_SYSSEEK (fp, fp->_IO_write_base - fp->_IO_read_end, 1);
      if (new_pos == _IO_pos_BAD)
	return 0;
      fp->_offset = new_pos;
    }
  count = _IO_SYSWRITE (fp, data, to_do);
  if (fp->_cur_column && count)
    fp->_cur_column = _IO_adjust_column (fp->_cur_column - 1, data, count) + 1;
  _IO_setg (fp, fp->_IO_buf_base, fp->_IO_buf_base, fp->_IO_buf_base);
  fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_buf_base;
  fp->_IO_write_end = (fp->_mode <= 0
		       && (fp->_flags & (_IO_LINE_BUF | _IO_UNBUFFERED))
		       ? fp->_IO_buf_base : fp->_IO_buf_end);
  return count;
}
```
이번엔 `new_do_write()` 내부의 `count`쪽을 보자.
이곳에서 `_IO_SYSWRITE (fp, data, to_do)`를 수행하는데, 이 부분에서 vtable의 `_IO_new_file_write()`를 호출하게 된다.
(libioP.h 내부의 `#define _IO_SYSWRITE(FP, DATA, LEN) JUMP2 (__write, FP, DATA, LEN)`)

```c
_IO_ssize_t
_IO_new_file_write (_IO_FILE *f, const void *data, _IO_ssize_t n)
{
  _IO_ssize_t to_do = n;
  while (to_do > 0)
    {
      _IO_ssize_t count = (__builtin_expect (f->_flags2
               & _IO_FLAGS2_NOTCANCEL, 0)
         ? write_not_cancel (f->_fileno, data, to_do)
         : write (f->_fileno, data, to_do));
      if (count < 0)
  {
    f->_flags |= _IO_ERR_SEEN;
    break;
  }
      to_do -= count;
      data = (void *) ((char *) data + count);
    }
  n -= to_do;
  if (f->_offset >= 0)
    f->_offset += n;
  return n;
}
```
`_IO_new_file_write()`를 살펴보면 내부에서 `write` 시스템콜을 호출하는 것을 볼 수 있다. 결론적으로, 인자에는 각각 아래의 값이 들어간다. 

- `_fileno`: 파일 디스크립터
- `data`: `_IO_write_base`
- `to_do`: `_IO_write_ptr` - `_IO_write_base`

이를 정리해 전달되는 인자를 파일 구조체로 표현하면 아래와 같다.
```c
write (f->_fileno, _IO_write_base, _IO_write_ptr - _IO_write_base)
```

따라서 프로그램 종료 전 `fflush(stdout)`을 수행하고 있으니, `stdout` 구조체를 조작하면 libc base를 leak할 수 있겠다.

# FSOP payload

대충 아래와 같이 페이로드를 작성했다. 

<img src="{{ '/assets/250127/img04.png' | relative_url }}" width="500">
*stdout 덮어써서 FSOP 수행 중 . . .*

그런데 파일 구조체를 덮어쓰는 과정에서 `fflush()+43`에서 자꾸 세그폴트가 발생했는데, 알고보니 `_lock` 부분에 쓰기 가능한 주소를 넣어줘야 하더라. 처음에 0으로 덮어썼더니 터졌다...
그래서 그냥 bss영역을 넣어 줬다가, 이후에도 저기에서 뭔가 자꾸 터지길래 아예 `_lock`까지는 안 덮도록 바꿔 줬다.

# Trivia
요 문제의 경우엔 bss로 stack pivoting까지 해 줬다.
그런데 이 과정에서 rsp, rbp가 꼬이며 인자가 다 제대로 들어갔는데도 세그폴트가 뜨는 것이다 ㅠㅠ!!

<img src="{{ '/assets/250127/img05.png' | relative_url }}" width="700">
<img src="{{ '/assets/250127/img06.png' | relative_url }}" width="600">
*... 😇*

이 디스코드 질문도 사실 여기에서 출발한 거였다.
rsp, rbp가 꼬일 거라는 생각을 전혀 하지 않고 '인자가 제대로 들어가는데 왜 call이 안 되지?' 하고 있었던 것 kk
결론적으로 `_IO_do_write()`가 호출되며 rsp가 낮아지는데, 이 과정에서 writable한 영역인 bss영역을 벗어나 버려서 그런 거였다.

이를 어떻게 해결할지 조금 고민하다가... 가젯 중에 `add rsp`나 `mov rbp, rsp`가 있는지 찾아봤다.

<img src="{{ '/assets/250127/img07.png' | relative_url }}" width="600">
*발견!*

그래서 rbp를 아래로 끌어내리기 위해 rsp 값을 계속 더해 주고, rbp를 rsp 위치로 이동시켜서 bss 영역의 윗부분을 참조하지 못하도록 만들어 줬다.
그런데 쓰면서 깨달은 건데... 어차피 rsp 주소만 높일 거면 계속 ret을 반복하도록 해도 되지 않았을까? 굳이 add rsp를 해줄 필요까진 없었을 것 같다.

+) ROP 시 `system()`을 쓰면 잘 터지기도 하고, `do_system()`에서 또 bss를 벗어나며 세그폴트가 뜬다. 그래서 `execve()` 애용 중 ㅎㅎ

---
<br>

<br>

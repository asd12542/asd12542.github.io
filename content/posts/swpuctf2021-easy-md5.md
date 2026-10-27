---
title: SWPUCTF 2021 新生赛 easy_md5
date: 2026-03-03T10:19:09+08:00
slug: swpuctf2021-easy-md5
description: MD5 弱类型比较绕过——数组漏洞与 0e 开头科学计数法两种解法
cover: /img/posts/swpuctf2021-easy-md5/01.png
categories: [CTF]
tags: [SWPUCTF, Web, PHP, MD5, 弱类型比较]
toc: true
comment: false
not_cover: true
---

题目链接：https://www.nssctf.cn/problem/386

需要使用到的工具是 HackBar：

![HackBar 工具](/img/posts/swpuctf2021-easy-md5/01.png)

## 源代码

```php
<?php
highlight_file(__FILE__);
include 'flag2.php';
if (isset($_GET['name']) && isset($_POST['password'])){
    $name = $_GET['name'];
    $password = $_POST['password'];
    if ($name != $password && md5($name) == md5($password)){
        echo $flag;
    }
    else {
        echo "wrong!";
    }
}
else {
    echo 'wrong!';
}
?>
```

## a. 代码审计

1. 代码通过 `$_GET['name']` 和 `$_POST['password']` 分别为 name 和 password 赋初值。
2. `if ($name != $password && md5($name) == md5($password))` 的意思是当变量 name 和变量 password 的值**不相等**，且两者 MD5 哈希值**弱相等**（`==`）时输出 flag，否则输出 wrong。

## b. 具体解法

由以上我们可以得知：当且仅当 name 和 password 的值不相等，且两者进行 MD5 加密之后的值弱相等，则能得到我们要的 flag。

### (1) 利用数组漏洞绕过

> **tip**：PHP `md5()` 函数接收 string 字符串类型，如果传入 array 数组类型的值，函数无法计算 MD5 值，但是不会报错，这样两者的函数返回值都为 NULL（弱相等为真），且初值不同，输出 flag。

```text
GET:  ?name[]=1
POST: password[]=2
```

![数组绕过得到 flag](/img/posts/swpuctf2021-easy-md5/02.png)

flag 为：

```text
NSSCTF{b5d3504c-80c5-4ba5-b9fe-07f278b1d949}
```

### (2) 利用 PHP `==` 弱类型比较漏洞

> **tip**：PHP 弱类型比较之前会进行字符串转化，而 MD5 之后以 `0e` 开头的会被解读为科学计数法（e 为指数），这样两者的值都为 0，输出 flag。

![0e 科学计数法绕过](/img/posts/swpuctf2021-easy-md5/03.png)

以下是常见 MD5 加密之后以 `0e` 开头的值（详情参照大佬的博客「常见的 MD5 碰撞：md5 值为 0e 开头」）：

| 字符串 | MD5 |
| --- | --- |
| QNKCDZO | 0e830400451993494058024219903391 |
| 240610708 | 0e462097431906509019562988736854 |
| s878926199a | 0e545993274517709034328855841020 |
| s155964671a | 0e342768416822451524974117254469 |
| s214587387a | 0e8482404488302881bc137137261715 |

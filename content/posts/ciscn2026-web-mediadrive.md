---
title: CISCN 2026 Web MediaDrive
date: 2026-05-08T18:08:01+08:00
slug: ciscn2026-web-mediadrive
description: 利用 iconv 的 UTF-7 转码特性 + preg_match 脏字符截断差异，绕过正则读取 /flag
cover: /img/posts/ciscn2026-web-mediadrive/01.png
categories: [CTF]
tags: [CISCN, Web, PHP, 反序列化, iconv]
toc: true
comment: false
---

## a. 漏洞概述

在 preview.php 这个文件中，通过特定文件名的拼接，利用函数 `iconv()` 的转码漏洞，实现文件读取，最终获得 flag。

## b. 代码审计

```php
$user = null;
if (isset($_COOKIE['user'])) {
    $user = @unserialize($_COOKIE['user']);
}
if (!$user instanceof User) {
    $user = new User("guest");
    setcookie("user", serialize($user), time() + 86400, "/");
}
```

将 user 这个对象序列化，存到 cookie 中，使用的时候再将它反序列化，赋值给变量 `$user`。

```php
$f = (string)($_GET['f'] ?? "");
if ($f === "") {
    http_response_code(400);
    echo "Missing parameter: f";
    exit;
}
$rawPath = $user->basePath . $f;
```

采用 GET 方式获取 `f` 的值，之后将它和 user 对象里面的 `basePath` 拼接，赋值给变量 `$rawPath`。其中 `basePath` 是 user 对象里面的一个属性，是我们构造特定文件名的利用点。

```php
if (preg_match('/flag|\/flag|\.\.|php:|data:|expect:/i', $rawPath)) {
    http_response_code(403);
    echo "Access denied";
    exit;
}
$convertedPath = @iconv($user->encoding, "UTF-8//IGNORE", $rawPath);
if ($convertedPath === false || $convertedPath === "") {
    http_response_code(500);
    echo "Conversion failed";
    exit;
}
$content = @file_get_contents($convertedPath);
```

将拼接好的变量 `$rawPath` 和特定字符串进行比较，之后利用函数 `iconv` 进行转码，之后再通过文件读取获得内容。以下是根据 PHP 手册对 iconv 函数的描述：

![iconv 函数说明](/img/posts/ciscn2026-web-mediadrive/01.png)

## c. payload 构建

既然代码最后是通过文件读取来获得内容，那我们就构建一个特殊的名称，在网页的根目录之下读取 flag 这个文件，也就是 `/flag`——这是我们期望得到的。但是 preview.php 添加了正则匹配校验（`preg_match` 函数），并不能直接读取 f 为 flag。

但是我们可以：

1. 修改 user 里面的 `basePath`，改为 `/`
2. 将原有编码格式修改为 `UTF-7`
3. 把预览界面的 f 赋值为 `f%c2lag`

这里详细说一下原理：当变量 `$rawPath` 被拼接成 `/f%c2lag` 的时候，通过正则校验的时候，虽然 `preg_match()` 函数只认 UTF-8 的编码，但是单独出现的 `%c2` 是脏字符，它之后的内容会被忽略，也就是存在一个**截断效果**，最终函数识别出来的内容就只有 `/f`，所以可以绕过正则校验。之后的编码转换 `iconv(UTF-7, "UTF-8//IGNORE", $rawPath)`，这种情况下编码转换时遇到无法识别的内容就自动忽略，然后转换后面的内容，最后得到 `/flag`，然后通过文件读取，获得 flag。

**Tip：关于脏字符截断**

| 场景 | 遇到 `%c2` 的行为 | 结果 |
| --- | --- | --- |
| `preg_match` 正则（UTF-8） | **截断，后面内容全部不读** | 输入 `/f%c2lag`，正则看到 `/f` |
| `iconv(UTF-7 → UTF-8)` | **只删掉脏字节，后面内容保留** | 输入 `/f%c2lag`，输出 `/flag` |

## d. Burp Suite 实操

修改 user 对象里面的 `$basePath` 和原编码体系。EXP（将结果替换到原 cookie 的位置）：

```php
<?php
class User {
    public string $name = "guest";
    public string $encoding = "UTF-7";
    public string $basePath = "/";
}
$a = new User();
echo urlencode(serialize($a));
```

之后打开 Burp Suite，进入预览界面，将 f 改为 `f%c2lag`，然后发包，得到 flag：

![Burp 发包得到 flag](/img/posts/ciscn2026-web-mediadrive/02.png)

```text
flag{6536db6a-f39e-42ab-8453-919a48b523c0}
```

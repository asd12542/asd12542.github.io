---
title: SWPUCTF 2021 新生赛 babyrce
date: 2026-03-05T19:13:30+08:00
slug: swpuctf2021-babyrce
description: Cookie 伪造进入 RCE 页面，$IFS 绕过空格过滤 + 通配符 * 绕过 flag 关键词
cover: /img/posts/swpuctf2021-babyrce/01.png
categories: [CTF]
tags: [SWPUCTF, Web, RCE, 命令执行]
toc: true
comment: false
not_cover: true
---

附题目链接：https://www.nssctf.cn/problem/425

![题目界面](/img/posts/swpuctf2021-babyrce/01.png)

## 源码

```php
<?php
error_reporting(0);
header("Content-Type:text/html;charset=utf-8");
highlight_file(__FILE__);
if($_COOKIE['admin'] == 1)
{
    include "../next.php";
}
else
    echo "小饼干最好吃啦！";
?>
```

## a. 代码审计

- `error_reporting(0)`：这是 PHP 的内置报错控制函数，无论代码哪里出现错误都不会显示。
- `$_COOKIE['admin'] == 1` 的意思是当 cookie 中 admin 的值为 1 的时候，执行包含一个 php 文件。

## b. 具体执行

根据前面的代码审计，给 cookie 的 admin 赋值为 1：

![给 cookie admin 赋值为 1](/img/posts/swpuctf2021-babyrce/02.png)

操作之后包含了一个名为 `rasalghul.php` 的文件，我们将它添加到端口之后获得以下源码：

![包含 rasalghul.php](/img/posts/swpuctf2021-babyrce/03.png)

```php
<?php
error_reporting(0);
highlight_file(__FILE__);
error_reporting(0);
if (isset($_GET['url'])) {
    $ip = $_GET['url'];
    if(preg_match("/ /", $ip)){
        die('nonono');
    }
    $a = shell_exec($ip);
    echo $a;
}
?>
```

通过 GET 传参的方式获取一个叫 `url` 的参数，随后将这个参数赋给变量 ip。`preg_match` 是 PHP 的内置函数，将变量 ip 和 `"/ /"` 里面的东西比较，如果说有相同就执行 die——这里的话是跟空格比较，也就是**过滤了空格**：

![过滤空格源码](/img/posts/swpuctf2021-babyrce/04.png)

我们试着执行 `ls` 命令，查看到有两个 php 文件。前面我们说过系统过滤了空格，那我们就使用 `${IFS}` 代替空格，执行结果如下：

![ls 命令执行结果](/img/posts/swpuctf2021-babyrce/05.png)

我们发现这个命令没有任何回显，但是也没有任何异常，就猜测系统是不是把 flag 这个关键词给过滤了，这时就要用到通配符 `*` 来代替 flag：

![通配符代替 flag 得到最终 flag](/img/posts/swpuctf2021-babyrce/06.png)

最终 flag 为：

```text
NSSCTF{561db995-d110-4f18-9f9c-06f73c49922b}
```

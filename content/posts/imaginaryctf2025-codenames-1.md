---
title: ImaginaryCTF 2025 codenames-1
date: 2026-06-02T21:40:00+08:00
lastmod: 2026-06-02T21:41:59+08:00
slug: imaginaryctf2025-codenames-1
description: os.path.join 路径穿越读取 /flag.txt，结合双用户局内信息共享拿到 flag
cover: /img/posts/imaginaryctf2025-codenames-1/01.png
categories: [CTF]
tags: [ImaginaryCTF, Web, Python, 路径穿越]
toc: true
comment: false
not_cover: true
---

题目提示：

> author: Eth007
>
> I hear that multilingual codenames is all the rage these days. Flag is in `/flag.txt`.

## a. 代码审计

### 1. 基于 /create_game 上半部分的

打开附件发现有两个附件，app.py 和 bot.py，点开第一个 app.py 前面并没有发现什么异样，直到我们定位到 `/create_game` 这个路径下，其中存在一个致命的漏洞 ---- `os.path.join()`，当参数中存在绝对地址也就是 `/` 会抛弃前面所有的路径。

举几个例子：

1. `os.path.join("words", "english.txt")`，这是正常拼接，结果为：`words/english.txt`
2. `os.path.join("words", "/flag.txt")`，由于出现 `/`，要抛弃前面所有路径，结果为：`/flag.txt`
3. `os.path.join("a/b/c/d", "/etc/passwd")`，结果为：`/etc/passwd`

```python
@app.route('/create_game', methods=['POST'])  # 这里是上半部分
def create_game():
    if 'username' not in session:
        return redirect(url_for('index'))
    # generate unique code
    while True:
        code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
        if code not in games:
            break
    # prepare game with selected language word list
    # determine language (default to first available)
    language = request.form.get('language', None)
    if not language or '.' in language:
        language = LANGUAGES[0] if LANGUAGES else None
    # load words for this language
    word_list = []
    if language:
        wl_path = os.path.join(WORDS_DIR, f"{language}.txt")
        try:
            with open(wl_path) as wf:
                word_list = [line.strip() for line in wf if line.strip()]
        except IOError as e:
            print(e)
            word_list = []
```

在得知了这个漏洞之后，继续审代码，发现在拼接之后，会尝试打开 `wl_path`，之后把值赋给 `word_list`。

### 2. 基于 /create_game 下半部分

接着看 `/create_game` 的后半部分，我们发现后半部分把 `word_list` 这个内容通过 `words = random.sample(word_list, 25)` 赋值给 `words`，这也就解释了为什么后续结果显示有 25 个 flag 结果。这里解释一下 `random.sample(列表, 数量)`，前者是列表，后者是数量，意思是选取列表中一定数量的内容赋值给 `words`。

之后将 `words` 存入 `game` 这个字典里面，把字典 game 那段的操作理解为 `game[board]=words`，赋完之后进行：

```python
games[code] = game
return redirect(url_for('game_view', code=code))
```

这一段的意思是把 game 这个字典全局接入 `game[code]`，然后重定向到 `game_view` 访问内容。

```python
    if not word_list:                # 这是 /create_game 的后半部分
        word_list = []
    # pick 25 random words
    words = random.sample(word_list, 25) if len(word_list) >= 25 else random.sample(word_list * 25, 25)
    start_team = random.choice(['red', 'blue'])
    counts = {
        'red': 9 if start_team == 'red' else 8,
        'blue': 9 if start_team == 'blue' else 8
    }
    # assign colors by index to support duplicate words
    indices = list(range(25))
    random.shuffle(indices)
    colors_list = [None] * 25
    # one assassin
    assassin_idx = indices.pop()
    colors_list[assassin_idx] = 'assassin'
    # team words
    for team in ['red', 'blue']:
        for _ in range(counts[team]):
            idx = indices.pop()
            colors_list[idx] = team
    # the rest are neutral
    for idx in indices:
        colors_list[idx] = 'neutral'
    # determine hard mode (double win points)
    hard_mode = bool(request.form.get('hard_mode'))
    # initialize game state
    game = {
        'players': [session['username']],
        'board': words,
        'colors': colors_list,
        'revealed': [False] * 25,
        'start_team': start_team,
        'team_color': start_team,
        'clue_giver': None,
        'clue': None,
        'guesses_remaining': 0,
        'score': 0,
        'hard_mode': hard_mode,
        'bots': []
    }
    games[code] = game
    return redirect(url_for('game_view', code=code))
```

### 3. 对于 /join_game 的分析

这段代码主要是关于其他用户如何通过邀请码 code 加入 game，其中 `game = games.get(code)`，将局部的 code 接入全局，再结合前面 `games[code] = game`，现在全局 game 和 `game[code]` 实际上是互通的，当后续其他用户通过邀请码加入就可以获取全局内容，这个通过以下代码也可以体现：

```python
if session['username'] in game['players']:
    return redirect(url_for('game_view', code=code))
```

```python
@app.route('/join_game', methods=['POST'])
def join_game():
    if 'username' not in session:
        return redirect(url_for('index'))
    code = request.form.get('code', '').strip().upper()
    game = games.get(code)
    if not game or len(game['players']) >= 2:
        flash('Invalid or full game code')
        return redirect(url_for('lobby'))
    if session['username'] in game['players']:
        return redirect(url_for('game_view', code=code))
    game['players'].append(session['username'])
    # assign the joiner as clue giver
    game['clue_giver'] = session['username']
    return redirect(url_for('game_view', code=code))
```

看到这里你可能还是有点懵，别担心继续往下看，下面我将介绍如何利用，并在后续梳理整个触发的链路。

## b. 具体利用思路

根据前面的代码审计，我们可以得知 join 这个函数，如果出现 `/` 会抛弃前面的路径，那我们能否将其中的参数 language 改为 `/flag`（这里路径穿越 `../../../../`，但是由于前面好像有验证，如果出现 `.` 就会默认选取第一种语言）。我们用 bp 修改 language 为 `/flag`，之后抛弃掉前面的路径，最后 `wl_path` 打开的内容也是 `/flag` 路径下的，并把该内容传给 `word_list`，然后通过 `random.sample(word_list, 25)`（这也就是为啥后续会出现 25 个 flag）传给 `words`，`words` 再把值存入字典 `game`，但是这里只通过一个用户无法访问到 flag 的内容。

我们还需要利用一个新用户，用它的邀请码加入 game，因为全局 game 和局部 `game[code]` 互通，相当于当另外的用户使用 code 就可以读取到所有全局内容，然后重定向到 `game_view` 得到 flag 的内容。

## c. 具体操作

首先 bp 在 `/create_game` 下抓包，修改 `language=/flag`，发包：

![Burp 抓包修改 language](/img/posts/imaginaryctf2025-codenames-1/01.png)

发包之后返回 code，利用 code，使用新的账户加入 game：

![返回邀请码](/img/posts/imaginaryctf2025-codenames-1/02.png)

利用新用户 admin 访问可以得到：

![admin 访问得到 flag](/img/posts/imaginaryctf2025-codenames-1/03.png)

最终 flag：`ictf{common_os_path_join_L_b19d35ca}`

## d. 触发链梳理

```
(/create_game)join() ——> wl_path ——> word_list ——> words ——> game[board]=words（这里这样写是便于理解）——>（新用户通过 code 访问）——> game_view
```

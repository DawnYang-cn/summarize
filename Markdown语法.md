# Markdown
>刚刚开始用github的时候各位都会发现每一个repo里面可以自动创建一个readme.md，这是什么东西呢？我一直以为他就是个readme.txt，用来写一点简单的描述，没什么特别的。随着不断地学习也看了一些其他人的github空间才发现我这种想法可以说对也可以说不对，说对是因为他的作用确实可以说是一个描述文件，说不对是因为他有自己一套语法，可以像html一样多彩，他就是Markdown。(html里面的很多语法都可以在Markdown中直接使用)

## 什么是Markdown?
简单说Markdown是一种标记语言，通过非常简单的语法就可以是我们的普通文本内容是一种可以使用普通文本拥有漂亮的排版。听起来有点像html，虽然没有像html那么强大的功能，但是用起来十分的方便。下面就介绍一些比较常见的Markdown语法，基本满足日常需求。

## Markdown语法
### 标题
Markdown支持两种标题语法：Setext和Atx
Setext格式是用下划线来表示两级标题，代码就是下面这样：
```
This is title
============
This is title
------------
```
效果：
>This is title
>=============
>This is title
>-------------
Atx格式是使用1-6个#来表达6级标题，代码是下面这样：
```
#title
###title
######title
#######title
```
效果：
># title
>### title ###
>###### title
>####### title

很明显，当我们输入7个#的时候没有用了。这里要注意在#和文字中间要留至少一个空格，你也可以选择用#来闭合前面的#，当然这么做仅仅是为了美观，没有别的作用。

### 引用
区块引用使用>来表示，引用还可以使用>>这种方式进行嵌套，代码像下面这样：
```
>Block
>>Block
>>>Block
>>>>Block
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>Block
```
效果：
>Block
>>Block
>>>Block
>>>>Block
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>Block

这个好像是没有限制嵌套的层数的，你也看到了，像上面那样的都还可以实现。

### 链接

链接也是我们非常常用的：
```
Click [github](http://github.com)
```

Click [github](http://github.com)

类似的，我们还可以添加图片
```
![](https://avatars3.githubusercontent.com/u/9919?v=3&s=200)
```
![](https://avatars3.githubusercontent.com/u/9919?v=3&s=200)


### 列表
列表又可以分成有序列表和无序列表。有序列表如下：

```
1.AAA
2.BBB
4.CCC
```
效果：

1.AAA

2.BBB

3.CCC

可以看到，即使我们上面输入的不是123，Markdown也会很智能的把序列修正。下面是无序列表：
```
*AAA
*BBB
*CCC
```
效果：

* AAA

* BBB

* CCC

这里需要说一下，\* + - 都可以使用


### 代码块
代码块用反引号表示，反引号就是键盘最左上角的那个东西，前面其实已经用过很多代码块了：

\```

JavaScript

\```

```
JavaScript
```

好，有这些基本已经够我用了，再深入一点还可以学习一下表格什么的。实在是不会了也可以直接写html进去哦！反正最后都会翻译成html😆😆


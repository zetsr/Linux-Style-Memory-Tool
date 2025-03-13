# Linux-Style-Memory-Tool

## process

*列出所有有效进程*

```
process -ls
```

*退出当前选中的进程*

```
process -d
```

*选择指定进程*

```
process -r <list_id> <process_name> <process_name.exe>
```

*使用特征码扫描当前选中的进程的内存地址*

```
process -AOBS <sig>
```

## address

*退出当前选中的内存地址*

```
address -d
```

*以float类型获取当前选中的内存地址的值*

```
address -get -float
```

*以int类型获取当前选中的内存地址的值*

```
address -get -int
```

*以float类型设置当前选中的内存地址的值*

```
address -set -float <value>
```

*以int类型设置当前选中的内存地址的值*

```
address -set -int <value>
```

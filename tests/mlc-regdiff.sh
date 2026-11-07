#!/bin/bash
# 把两轮（或任意多轮）的区域清单按区间长度归一化后对比。
# 之所以按长度而不是按地址：客户机窗口基址每轮都变，绝对地址不可比，
# 而各库的映射长度是固定的，长度集合的差异直接指出「哪一块没进来」。
set -u
for f in "$@"; do
    echo "=== $f ==="
    grep '转储\] 区域' "$f" | sed 's/.*区域 //; s/ ->.*//' | while IFS= read -r r; do
        inner="${r#*[}"; inner="${inner%)*}"
        s="${inner%%,*}"; e="${inner##*,}"
        ds=$(( 16#${s#0x} )); de=$(( 16#${e#0x} ))
        printf '%10d  0x%08x - 0x%08x\n' "$(( de - ds ))" "$ds" "$de"
    done | sort -n
    echo
done

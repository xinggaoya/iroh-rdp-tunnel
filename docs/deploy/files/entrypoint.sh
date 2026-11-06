#!/bin/sh
# rustp2p 的 node 是**交互式**的：stdin 一旦 EOF 就退出。
# 这里用一个永不结束的管道顶住 stdin，让它能长期当 bootstrap + 中继跑。
set -e

tail -f /dev/null | rustp2p-node "$@" &
NODE_PID=$!

term() {
    kill -TERM "$NODE_PID" 2>/dev/null || true
}
trap term TERM INT

wait "$NODE_PID"

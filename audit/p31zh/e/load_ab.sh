#!/bin/sh
# load.py со всплеском: d7a90cc (dbgold) и новый код (dbgnew) по очереди
S=/home/claude/scripts-p31d/audit-scripts-p31d
OUT=/home/claude/bench/load
mkdir -p $OUT
for v in ${VERS:-dbgold dbgnew dbgold dbgnew}; do
  i=$(ls $OUT | grep -c "^$v")
  LAB_NEW=/tmp/$v LAB_CERT_DIR=/tmp/lab PYTHONDONTWRITEBYTECODE=1 unshare -rn python3 -I $S/load.py new ${RATE:-200} ${DUR:-120} ${BURST:-300} > $OUT/$v.$i.json 2> $OUT/$v.$i.err
  d=$(ls -td /tmp/p31-new-* | head -1)
  echo "$v.$i checkfail=$(grep -c CHECKFAIL $d/log.txt) openfail=$(grep -c OPENFAIL $d/log.txt) descriptor=$(grep -c 'is used by transport' $d/log.txt)" >> $OUT/summary.txt
  cp $d/log.txt $OUT/$v.$i.log
done
echo done >> $OUT/summary.txt

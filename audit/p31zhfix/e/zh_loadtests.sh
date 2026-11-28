#!/bin/sh
# Ж: тесты DNS со сроками под нагрузкой на процессор: два «пожирателя» на двух процессорах, 6 прогонов подряд
cd /tmp/r
python3 -c 'while 1: pass' & H1=$!
python3 -c 'while 1: pass' & H2=$!
for i in 1 2 3 4 5 6; do
  python3 -m unittest tests.test_v125_p31 tests.test_v125_p31d tests.test_v125_p31e tests.test_v122 tests.test_v125 > /tmp/lt_$i.log 2>&1
  echo "RUN $i: $(grep -E '^(Ran|OK|FAILED)' /tmp/lt_$i.log | tr '\n' ' ') $(grep -E '^(FAIL|ERROR):' /tmp/lt_$i.log | tr '\n' ' ')"
done
kill $H1 $H2

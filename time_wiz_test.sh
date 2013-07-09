#!/bin/bash

# Date cible
NEW_DATE="2023-07-22"
# Date actuelle
CUR_DATE=$(date +%s)
# Epoch de la date cible
NEWEPOCH=$(date -d "$NEW_DATE" +%s)
# Calcul de la différence
OFFSET=$((CUR_DATE - NEWEPOCH))

#Tests
date
TIMEHOOK_MODE=static TIMEHOOK_EPOCH=000000001 LD_PRELOAD=$PWD/time_pre.so date
TIMEHOOK_MODE=static TIMEHOOK_EPOCH=$NEWEPOCH LD_PRELOAD=$PWD/time_pre.so date
TIMEHOOK_MODE=offset TIMEHOOK_EPOCH=\-$OFFSET LD_PRELOAD=$PWD/time_pre.so date
./time_trc             -mode static -epoch 000000001 -- date
./time_trc             -mode static -epoch $NEWEPOCH -- date
./time_trc             -mode offset -epoch \-$OFFSET -- date
pin   -t ./time_pin.so -mode static -epoch 000000001 -- date
pin   -t ./time_pin.so -mode static -epoch $NEWEPOCH -- date
pin   -t ./time_pin.so -mode offset -epoch \-$OFFSET -- date
drrun -c ./time_dyn.so -mode static -epoch 000000001 -- date
drrun -c ./time_dyn.so -mode static -epoch $NEWEPOCH -- date
drrun -c ./time_dyn.so -mode offset -epoch \-$OFFSET -- date
TIMEHOOK_MODE=static TIMEHOOK_EPOCH=000000001 LD_PRELOAD=$PWD/time_pre.so ./mini_date
pin   -t ./time_pin.so -mode static -epoch 000000001 -- ./mini_date
./time_trc             -mode static -epoch 000000001 -- ./mini_date
drrun -c ./time_dyn.so -mode static -epoch 000000001 -- ./mini_date
/bin/ls -l --time-style=full-iso /bin/ls
TIMEHOOK_MODE=static TIMEHOOK_EPOCH=000000001 TIMEHOOK_FILETS=1 TIMEHOOK_CLAMP=1 LD_PRELOAD=$PWD/time_pre.so /bin/ls -l --time-style=full-iso /bin/ls
TIMEHOOK_MODE=static TIMEHOOK_EPOCH=$NEWEPOCH TIMEHOOK_FILETS=1 TIMEHOOK_CLAMP=1 LD_PRELOAD=$PWD/time_pre.so /bin/ls -l --time-style=full-iso /bin/ls
TIMEHOOK_MODE=offset TIMEHOOK_EPOCH=\-$OFFSET TIMEHOOK_FILETS=1 TIMEHOOK_CLAMP=1 LD_PRELOAD=$PWD/time_pre.so /bin/ls -l --time-style=full-iso /bin/ls
./time_trc             -mode static -epoch 000000001 -filets 1 -clamp 1 -- /bin/ls -l --time-style=full-iso /bin/ls
./time_trc             -mode static -epoch $NEWEPOCH -filets 1 -clamp 1 -- /bin/ls -l --time-style=full-iso /bin/ls
./time_trc             -mode offset -epoch \-$OFFSET -filets 1 -clamp 1 -- /bin/ls -l --time-style=full-iso /bin/ls
pin   -t ./time_pin.so -mode static -epoch 000000001 -filets 1 -clamp 1 -- /bin/ls -l --time-style=full-iso /bin/ls
pin   -t ./time_pin.so -mode static -epoch $NEWEPOCH -filets 1 -clamp 1 -- /bin/ls -l --time-style=full-iso /bin/ls
pin   -t ./time_pin.so -mode offset -epoch \-$OFFSET -filets 1 -clamp 1 -- /bin/ls -l --time-style=full-iso /bin/ls
drrun -c ./time_dyn.so -mode static -epoch 000000001 -filets 1 -clamp 1 -- /bin/ls -l --time-style=full-iso /bin/ls
drrun -c ./time_dyn.so -mode static -epoch $NEWEPOCH -filets 1 -clamp 1 -- /bin/ls -l --time-style=full-iso /bin/ls
drrun -c ./time_dyn.so -mode offset -epoch \-$OFFSET -filets 1 -clamp 1 -- /bin/ls -l --time-style=full-iso /bin/ls
TIMEHOOK_MODE=static TIMEHOOK_EPOCH=000000001 TIMEHOOK_FILETS=1 TIMEHOOK_CLAMP=1 LD_PRELOAD=$PWD/time_pre.so ./mini_file
./time_trc             -mode static -epoch 000000001 -filets 1 -clamp 1 -- ./mini_file
pin   -t ./time_pin.so -mode static -epoch 000000001 -filets 1 -clamp 1 -- ./mini_file
drrun -c ./time_dyn.so -mode static -epoch 000000001 -filets 1 -clamp 1 -- ./mini_file

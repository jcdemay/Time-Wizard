set -x
gcc -O2 -static -s -o mini_date mini_date.c
gcc -O2 -static -s -o mini_file mini_file.c
gcc -shared -fPIC -O2 -Wall -Wextra -Wno-nonnull-compare -ldl -o time_pre.so time_pre.c
g++ -O2 -std=c++17 -Wall -Wextra time_trc.cpp -o time_trc
make -B -f time_pin.mk
g++ -m64 -std=c++11 -O2 -fPIC -shared -DLINUX -DX86_64 -I"/opt/dynamorio/current/include" -I"/opt/dynamorio/current/ext/include" -o time_dyn.so time_dyn.cpp -L"/opt/dynamorio/current/lib64/release" -L"/opt/dynamorio/current/ext/lib64/release" -Wl,-rpath,"/opt/dynamorio/current/lib64/release" -Wl,-rpath,"/opt/dynamorio/current/ext/lib64/release" -Wl,--start-group -ldrwrap -ldrmgr -ldrsyms -ldynamorio -Wl,--end-group
gcc -O2 -Wall -Wextra time_scp.c -o time_scp

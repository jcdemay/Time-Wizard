PIN_ROOT ?= /opt/pin/current
PIN_ARCH ?= intel64

PINRTDIR := $(PIN_ROOT)/$(PIN_ARCH)/pinrt
CXX      := $(PINRTDIR)/bin/pin-g++

TOOL   := time_pin.so
OBJ    := time_pin.o

CXXFLAGS := -std=c++17 -Wall -Wextra -Wno-unknown-pragmas \
            -fno-stack-protector -funwind-tables -fasynchronous-unwind-tables \
            -fno-rtti -fPIC -DTARGET_LINUX -faligned-new -O2 -fno-strict-aliasing

CXXFLAGS += -Wno-cast-function-type -Wno-unused-parameter

INCS := -isystem $(PINRTDIR)/include/adaptor \
        -I$(PIN_ROOT)/source/include/pin \
        -I$(PIN_ROOT)/source/include/pin/gen \
        -I$(PIN_ROOT)/extras/components/include \
        -I$(PIN_ROOT)/extras/xed-$(PIN_ARCH)/include/xed \
        -I$(PIN_ROOT)/source/tools/Utils

LDFLAGS := -shared -Wl,-Bsymbolic \
           -Wl,--version-script=$(PIN_ROOT)/source/include/pin/pintool.ver

LIBS := -L$(PIN_ROOT)/$(PIN_ARCH)/lib \
        -L$(PIN_ROOT)/extras/xed-$(PIN_ARCH)/lib \
        -lpin -lpinrt-adaptor-static -lxed -lpindwarf -ldwarf -lunwind-dynamic

all: $(TOOL)

$(OBJ): time_pin.cpp
	$(CXX) $(CXXFLAGS) $(INCS) -c -o $@ $<

$(TOOL): $(OBJ)
	$(CXX) $(LDFLAGS) -o $@ $^ $(LIBS)

clean:
	rm -f $(TOOL) $(OBJ)

CXX ?= g++
CXXFLAGS ?= -std=c++17 -Wall -Wextra -O2 -Iinclude
DEPFLAGS := -MMD -MP
TARGET := dnsrelay
SRC := $(wildcard src/*.cpp)
OBJ := $(SRC:.cpp=.o)
DEP := $(OBJ:.o=.d)

.PHONY: all clean run test-port

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^

src/%.o: src/%.cpp
	$(CXX) $(CXXFLAGS) $(DEPFLAGS) -c -o $@ $<

run: $(TARGET)
	sudo ./$(TARGET) -d 114.114.114.114 dnsrelay.txt

test-port: $(TARGET)
	./$(TARGET) -dd -p 1053 114.114.114.114 dnsrelay.txt

clean:
	rm -f $(TARGET) $(OBJ) $(DEP)

-include $(DEP)

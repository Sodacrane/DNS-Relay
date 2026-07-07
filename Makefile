CXX ?= g++
CXXFLAGS ?= -std=c++17 -Wall -Wextra -O2 -pthread -Iinclude
DEPFLAGS := -MMD -MP
TARGET := dnsrelay
BUILD_DIR := build
OBJ_DIR := $(BUILD_DIR)/obj
DEP_DIR := $(BUILD_DIR)/dep
SRC := $(wildcard src/*.cpp)
OBJ := $(patsubst src/%.cpp,$(OBJ_DIR)/%.o,$(SRC))
DEP := $(patsubst src/%.cpp,$(DEP_DIR)/%.d,$(SRC))

.PHONY: all clean run test-port

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^

$(OBJ_DIR)/%.o: src/%.cpp | $(OBJ_DIR) $(DEP_DIR)
	$(CXX) $(CXXFLAGS) $(DEPFLAGS) -MF $(DEP_DIR)/$*.d -c -o $@ $<

$(OBJ_DIR) $(DEP_DIR):
	mkdir -p $@

run: $(TARGET)
	sudo ./$(TARGET) -d 114.114.114.114 dnsrelay.txt

test-port: $(TARGET)
	./$(TARGET) -dd -p 1053 114.114.114.114 dnsrelay.txt

clean:
	rm -rf $(TARGET) $(BUILD_DIR)

-include $(DEP)

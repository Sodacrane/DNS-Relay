CXX ?= g++
CXXFLAGS ?= -std=c++17 -Wall -Wextra -O2 -pthread -Iinclude
DEPFLAGS := -MMD -MP
TARGET_NAME := dnsrelay
ROOT_TARGET := dnsrelay
BUILD_DIR := build
BIN_DIR := $(BUILD_DIR)/bin
OBJ_DIR := $(BUILD_DIR)/obj
DEP_DIR := $(BUILD_DIR)/dep
TARGET := $(BIN_DIR)/$(TARGET_NAME)
SRC := $(wildcard src/*.cpp)
OBJ := $(patsubst src/%.cpp,$(OBJ_DIR)/%.o,$(SRC))
DEP := $(patsubst src/%.cpp,$(DEP_DIR)/%.d,$(SRC))

.PHONY: all clean run test-port

all: $(TARGET) $(ROOT_TARGET)

$(TARGET): $(OBJ) | $(BIN_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $^

$(ROOT_TARGET): $(TARGET)
	cp $< $@

$(OBJ_DIR)/%.o: src/%.cpp | $(OBJ_DIR) $(DEP_DIR)
	$(CXX) $(CXXFLAGS) $(DEPFLAGS) -MF $(DEP_DIR)/$*.d -c -o $@ $<

$(BIN_DIR) $(OBJ_DIR) $(DEP_DIR):
	mkdir -p $@

run: $(TARGET)
	sudo ./$(TARGET) -d 114.114.114.114 dnsrelay.txt

test-port: $(TARGET)
	./$(TARGET) -dd -p 1053 114.114.114.114 dnsrelay.txt

clean:
	rm -rf $(BUILD_DIR) dnsrelay src/*.o src/*.d

-include $(DEP)

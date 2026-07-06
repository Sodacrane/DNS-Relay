CXX ?= g++
CXXFLAGS ?= -std=c++17 -Wall -Wextra -O2
TARGET := dnsrelay
SRC := dnsrelay.cpp

.PHONY: all clean run test-port

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $@ $<

run: $(TARGET)
	sudo ./$(TARGET) -d 114.114.114.114 dnsrelay.txt

test-port: $(TARGET)
	./$(TARGET) -dd -p 1053 114.114.114.114 dnsrelay.txt

clean:
	rm -f $(TARGET)

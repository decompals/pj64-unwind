CXX_SRCS := duktape.cpp unwind.cpp
CXX_OBJS := $(CXX_SRCS:.cpp=.o)
TARGET := unwind.dll

CXXFLAGS := -O2 -m32 -std=c++20
CPPFLAGS := -Ilib/ELFIO

$(TARGET): $(CXX_OBJS)
	clang++ -shared $(CXXFLAGS) $^ -o $@

%.o : %.cpp
	clang++ $(CXXFLAGS) $(CPPFLAGS) $< -c -o $@

clean:
	rm $(CXX_OBJS)
	rm $(TARGET)
	rm $(TARGET:.dll=.exp)
	rm $(TARGET:.dll=.lib)

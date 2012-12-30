CXXFLAGS := -Ilibwait/include/
LDFLAGS  := -Llibwait
LDLIBS   := -lwait -lrt
OBJECTS  := main.o jabber.o

jxclient: $(OBJECTS) libwait/libwait.a
	$(CXX) -o jxclient $(LDFLAGS) $(OBJECTS) $(LDLIBS)

libwait/libwait.a:
	$(MAKE) -C libwait

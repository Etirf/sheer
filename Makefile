CC      = cc

# MARCH is intentionally absent from the default build - the binary
# must run on any x86-64 Linux, not just the build machine.
# Pass MARCH=native if you want CPU-specific optimisation for yourself.
MARCH   ?=
MARCH_F := $(if $(MARCH),-march=$(MARCH))

CFLAGS  = -std=c11 -O3 $(MARCH_F) -mtune=generic -flto=auto \
          -Wall -Wextra -Wpedantic -Wstrict-prototypes -Wmissing-prototypes \
          -Wshadow -Wconversion -Wdouble-promotion -Wnull-dereference \
          -fstack-protector-strong \
          -D_POSIX_C_SOURCE=200809L -D_FORTIFY_SOURCE=2 \
          -pipe
LDFLAGS = -flto=auto

SRCS   := src/main.c src/token.c src/cmd.c src/out.c src/llm.c
OBJS   := $(SRCS:.c=.o)
DEPS   := $(OBJS:.o=.d)
TARGET := sheer

.PHONY: all debug clean install uninstall asm test bench

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

src/%.o: src/%.c
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

-include $(DEPS)

debug: CFLAGS  := -std=c11 -O0 -g3 \
                   -fsanitize=address,undefined -fno-omit-frame-pointer \
                   -Wall -Wextra -Wpedantic -Wstrict-prototypes \
                   -Wmissing-prototypes -Wshadow -Wconversion \
                   -D_POSIX_C_SOURCE=200809L
debug: LDFLAGS := -fsanitize=address,undefined
debug: clean $(TARGET)

# annotated assembly. -Wno-format-truncation: GCC complains that tok->s (512 bytes)
# might not fit into our small destination buffers. it's right, we truncate on purpose.
# the main build doesn't warn because LTO defers this analysis past the point GCC checks.
asm: src/cmd.c
	$(CC) $(filter-out -flto=auto,$(CFLAGS)) -Wno-format-truncation \
	      -S -fverbose-asm -o src/cmd.s $<
	@echo "written to src/cmd.s - $(shell wc -l < src/cmd.s) lines"

test: $(TARGET)
	@bash tests/run_tests.sh

bench: $(TARGET)
	@bash tests/bench.sh

clean:
	rm -f $(OBJS) $(DEPS) src/cmd.s $(TARGET)

uninstall:
	rm -f $(DESTDIR)/usr/local/bin/$(TARGET)
	rm -f $(DESTDIR)/usr/local/share/sheer/sheer.sh
	rmdir --ignore-fail-on-non-empty $(DESTDIR)/usr/local/share/sheer 2>/dev/null || true
	@REAL_HOME=$$(eval echo ~$${SUDO_USER:-$$USER}); \
	 for RC in "$$REAL_HOME/.bashrc" "$$REAL_HOME/.zshrc"; do \
	   if [ -f "$$RC" ] && grep -qF '# >>> sheer <<<' "$$RC" 2>/dev/null; then \
	     sed -i '/# >>> sheer <<</,/# <<< sheer >>>/d' "$$RC"; \
	     echo "  removed from $$RC"; \
	   fi; \
	 done
	@echo ""
	@echo "  uninstalled. restart your shell."
	@echo ""

install: $(TARGET)
	install -Dm755 $(TARGET) $(DESTDIR)/usr/local/bin/$(TARGET)
	install -Dm644 shell/sheer.sh $(DESTDIR)/usr/local/share/sheer/sheer.sh
	@# write the function inline - no sourcing, no parser surprises
	@REAL_HOME=$$(eval echo ~$${SUDO_USER:-$$USER}); \
	 for RC in "$$REAL_HOME/.bashrc" "$$REAL_HOME/.zshrc"; do \
	   if [ -f "$$RC" ] && ! grep -qF '# >>> sheer <<<' "$$RC" 2>/dev/null; then \
	     printf '\n# >>> sheer <<<\nfunction shrun { eval "$$(sheer run "$$@")"; }\n# <<< sheer >>>\n' >> "$$RC"; \
	     echo "  added to $$RC"; \
	   fi; \
	 done
	@echo ""
	@echo "  done. restart your shell or: source ~/.bashrc"
	@echo ""

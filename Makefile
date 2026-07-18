NVIM ?= nvim

.PHONY: test vectors
# Run headless with a scratch XDG_CONFIG_HOME so no contributor's personal
# Neovim config (init.lua, plugin managers) can leak into test output. plenary
# is still discovered by tests/minimal_init.lua via its absolute-path candidate.
test:
	mkdir -p $(CURDIR)/.test-xdg
	XDG_CONFIG_HOME=$(CURDIR)/.test-xdg \
	$(NVIM) --headless --noplugin -u tests/minimal_init.lua \
	  -c "PlenaryBustedDirectory tests/ { minimal_init = 'tests/minimal_init.lua' }"

# Regenerate golden conformance vectors from the Provenance monorepo (Task 9).
vectors:
	cd $(PROVENANCE_REPO) && node --experimental-strip-types tools/export-conformance-vectors.ts \
	  --out $(CURDIR)/tests/conformance/fixtures

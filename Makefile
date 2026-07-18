NVIM ?= nvim

.PHONY: test vectors
test:
	$(NVIM) --headless --noplugin -u tests/minimal_init.lua \
	  -c "PlenaryBustedDirectory tests/ { minimal_init = 'tests/minimal_init.lua' }"

# Regenerate golden conformance vectors from the Provenance monorepo (Task 9).
vectors:
	cd $(PROVENANCE_REPO) && node --experimental-strip-types tools/export-conformance-vectors.ts \
	  --out $(CURDIR)/tests/conformance/fixtures

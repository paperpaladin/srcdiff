# Planted divergences, checked for both detection and correct severity.
test:
	@python3 t/test_srcdiff.py

# Live audit against a real PyPI package. Needs network.
audit:
	@python3 srcdiff.py audit $(PKG) $(VER)

.PHONY: test audit

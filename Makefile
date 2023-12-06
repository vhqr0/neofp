.PHONY: compile
compile:
	hy2py -o build/hy2py neofp

.PHONY: build
build:
	poetry build

.PHONY: clean
clean:
	rm -rf build dist
	hy -c "(do (import pathlib [Path] shutil [rmtree]) \
(for [p (.rglob (Path \"neofp\") \"__pycache__\")] (rmtree p)))"

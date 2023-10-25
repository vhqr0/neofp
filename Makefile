.PHONY: compile
compile:
	hy2py -o neofp neofp

.PHONY: build
build: compile
	hy setup.hy -v bdist_wheel

.PHONY: clean
clean:
	rm -rf build dist neofp.egg-info
	hy -c "(do (import pathlib [Path] shutil [rmtree]) \
(for [p (.rglob (Path \"neofp\") \"*.py\")] (.unlink p)) \
(for [p (.rglob (Path \"neofp\") \"__pycache__\")] (rmtree p)))"

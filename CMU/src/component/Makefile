all:


.PHONY: clean all release
clean:
	bash build.sh clean
all:
	poetry run pip install pymonocypher==3.1.3.2
	bash build.sh all
release:
	poetry run pip install pymonocypher==3.1.3.2
	bash build.sh release
debug:
	poetry run pip install pymonocypher==3.1.3.2
	bash build.sh debug

install:
	test -d venv || virtualenv -p python3 venv
	. venv/bin/activate; pip install -Ur requirements.txt

sync:
	rsync -av --exclude-from=.gitignore . root@192.168.115.61:python-netflow-collector/

.PHONY: install sync

PYTHON_EXEC = /usr/bin/python3
VENV_PYTHON_EXEC = ./venv/bin/python3
VENV_PIP_EXEC = ./venv/bin/pip3

.DEFAULT_GOAL = help
.PHONY: install run

## —— DNS domain mail checker ——————————————————————————————————

install: ## Installs virtual python env, makes sure pip is up to date and finally, installs the required dependencies
	$(PYTHON_EXEC) -m venv venv
	$(VENV_PIP_EXEC) install --upgrade pip
	$(VENV_PIP_EXEC) install -r requirements.txt

run: ## Runs the script (Usage: make run domain=<domain-name>)
ifdef domain
	$(VENV_PYTHON_EXEC) main.py $(domain)
else
	@echo "Usage: make run domain=<domain-name>"
endif

help: ## Outputs this help screen
	@grep -E '(^[a-zA-Z0-9\./_-]+:.*?##.*$$)|(^##)' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}{printf "\033[32m%-30s\033[0m %s\n", $$1, $$2}' | sed -e 's/\[32m##/[33m/'

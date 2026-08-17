.PHONY: build clean install

PLUGIN_NAME = bifrost-anthropic-inference-hooks
OUTPUT_DIR  = build
OUTPUT      = $(OUTPUT_DIR)/$(PLUGIN_NAME).so

build:
	@mkdir -p $(OUTPUT_DIR)
	go build -buildmode=plugin -o $(OUTPUT) main.go
	@echo "built $(OUTPUT)"

install: build
	@mkdir -p ~/.bifrost/plugins
	@cp $(OUTPUT) ~/.bifrost/plugins/

clean:
	@rm -rf $(OUTPUT_DIR)
